// OptiCombatScanEngine.cs — implémentation IScanEngine adossée au cœur Rust optiCombat.
//
// FICHIER D'INTÉGRATION (à copier dans optiCombat/Services/OptiCombat/).
// Non inclus dans le projet par défaut pour ne pas imposer la DLL native au build.
// Compile contre .NET 8 ; nécessite opticombat.dll déployée à côté de l'exécutable.
//
// Mappe la sortie JSON du cœur Rust (opticombat_scan_json) vers les modèles
// existants ScanResult / ThreatInfo, et s'enregistre comme IScanEngine en
// remplacement (ou complément) de ClamAvScanEngineAdapter.
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using optiCombat.Models;

namespace optiCombat.Services.OptiCombat
{
    /// <summary>Liaison P/Invoke vers la bibliothèque native optiCombat (C ABI).</summary>
    internal static class OptiCombatNative
    {
        private const string Dll = "opticombat"; // opticombat.dll / libopticombat.so

        [DllImport(Dll, EntryPoint = "opticombat_scan_path", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ScanPath([MarshalAs(UnmanagedType.LPUTF8Str)] string path);

        [DllImport(Dll, EntryPoint = "opticombat_scan_json", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ScanJson([MarshalAs(UnmanagedType.LPUTF8Str)] string path);

        [DllImport(Dll, EntryPoint = "opticombat_string_free", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void StringFree(IntPtr s);

        [DllImport(Dll, EntryPoint = "opticombat_version", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr Version();

        internal static string? ScanJsonManaged(string path)
        {
            IntPtr ptr = ScanJson(path);
            if (ptr == IntPtr.Zero) return null;
            try { return Marshal.PtrToStringUTF8(ptr); }
            finally { StringFree(ptr); } // contrat de propriété mémoire
        }

        internal static string VersionManaged() => Marshal.PtrToStringUTF8(Version()) ?? "?";
    }

    /// <summary>
    /// Moteur de scan optiCombat adossé au cœur Rust optiCombat (ClamAV/clamd + YARA +
    /// heuristique + sandbox + ML + réputation), exposé via l'interface existante.
    /// </summary>
    public sealed class OptiCombatScanEngine : IScanEngine
    {
        // Le verdict natif : 0 propre, 1 suspect, 2 malveillant, -1 erreur.
        private const int OcMalicious = 2;
        private const int OcSuspicious = 1;

        public bool IsAvailable
        {
            get
            {
                if (!TryNativeProbe(out _, out var reason))
                {
                    if (!string.IsNullOrEmpty(reason))
                        AppLogger.Warn("OptiCombatScanEngine", $"Moteur natif indisponible : {reason}");
                    return false;
                }
                return true;
            }
        }

        public Task<string> GetVersionAsync()
        {
            if (TryNativeProbe(out var version, out _))
                return Task.FromResult($"optiCombat {version}");
            return Task.FromResult("optiCombat (moteur natif indisponible — repli ClamAV)");
        }

        /// <summary>
        /// Teste le chargement P/Invoke. Windows Security / SAC peut bloquer opticombat.dll
        /// avec FileLoadException (0x800711C7) — ne doit jamais faire crasher l'UI.
        /// </summary>
        private static bool TryNativeProbe(out string? version, out string? failureReason)
        {
            version = null;
            failureReason = null;
            if (!ValidateNativeDllPath(out failureReason))
                return false;
            try
            {
                version = OptiCombatNative.VersionManaged();
                return true;
            }
            catch (Exception ex)
            {
                failureReason = ex.Message;
                return false;
            }
        }

        /// <summary>
        /// Rejette opticombat.dll absente ou remplacée par optiCombat.dll (copie manuelle fréquente en dev).
        /// </summary>
        private static bool ValidateNativeDllPath(out string? failureReason)
        {
            failureReason = null;
            var baseDir = AppContext.BaseDirectory;
            var nativePath = Path.Combine(baseDir, "opticombat.dll");
            if (!File.Exists(nativePath))
            {
                failureReason =
                    "opticombat.dll introuvable — exécutez scripts\\build-engine.ps1 (Rust requis) puis rebuild.";
                return false;
            }

            var managedPath = Path.Combine(baseDir, "optiCombat.dll");
            if (File.Exists(managedPath))
            {
                try
                {
                    var nativeHash = Convert.ToHexString(
                        System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(nativePath)));
                    var managedHash = Convert.ToHexString(
                        System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(managedPath)));
                    if (string.Equals(nativeHash, managedHash, StringComparison.OrdinalIgnoreCase))
                    {
                        failureReason =
                            "opticombat.dll invalide (copie de optiCombat.dll) — supprimez-la et lancez scripts\\build-engine.ps1.";
                        return false;
                    }
                }
                catch
                {
                    // Continuer vers P/Invoke si la comparaison échoue.
                }
            }

            return true;
        }

        public Task<ScanResult> ScanFileAsync(
            string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            var result = new ScanResult { Type = ScanType.File, TargetPath = filePath };
            progress?.Report(new ScanProgress { Phase = ScanPhase.Scanning, Message = filePath, TotalFiles = 1 });
            ScanOne(filePath, result, progress);
            Finish(result);
            return Task.FromResult(result);
        }

        public Task<ScanResult> ScanFolderAsync(
            string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            var result = new ScanResult { Type = ScanType.Folder, TargetPath = folderPath };
            ScanTree(folderPath, result, progress, ct);
            Finish(result, ct);
            return Task.FromResult(result);
        }

        public Task<ScanResult> QuickScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            var result = new ScanResult { Type = ScanType.QuickScan, TargetPath = "QuickScan" };
            foreach (var dir in QuickScanTargets())
                ScanTree(dir, result, progress, ct);
            Finish(result, ct);
            return Task.FromResult(result);
        }

        public Task<ScanResult> FullScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            var result = new ScanResult { Type = ScanType.FullScan, TargetPath = "FullScan" };
            foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed))
                ScanTree(drive.RootDirectory.FullName, result, progress, ct);
            Finish(result, ct);
            return Task.FromResult(result);
        }

        // ── Cœur du mapping natif → modèles ──────────────────────────────────────

        private static void ScanOne(string filePath, ScanResult result, IProgress<ScanProgress>? progress)
        {
            result.FilesScanned++;
            string? json;
            try { json = OptiCombatNative.ScanJsonManaged(filePath); }
            catch (Exception ex)
            {
                result.Status = ScanStatus.Error;
                result.ErrorMessage = ex is DllNotFoundException
                    ? "opticombat.dll introuvable"
                    : $"Moteur natif bloqué ou indisponible : {ex.Message}";
                return;
            }

            if (string.IsNullOrEmpty(json)) return;

            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                var verdict = root.GetPropertyOrDefault("verdict", "Clean");
                if (verdict is not ("Malicious" or "Suspicious")) return;

                long size = -1;
                try { size = new FileInfo(filePath).Length; } catch (IOException) { }

                foreach (var det in root.GetArrayOrEmpty("detections"))
                {
                    var threat = new ThreatInfo
                    {
                        FilePath = filePath,
                        VirusName = det.GetPropertyOrDefault("name", verdict),
                        FileSize = size,
                        Status = ThreatStatus.Detected,
                        DetectedBy = MapEngine(det.GetPropertyOrDefault("engine", "optiCombat")),
                    };
                    result.Threats.Add(threat);
                    progress?.Report(new ScanProgress
                    {
                        Phase = ScanPhase.ThreatFound,
                        ThreatInfo = threat,
                        ThreatsFound = result.Threats.Count,
                        FilesScanned = result.FilesScanned,
                    });
                }
            }
            catch (JsonException) { /* JSON inattendu : on ignore, fichier traité comme propre */ }
        }

        private void ScanTree(string root, ScanResult result, IProgress<ScanProgress>? progress, CancellationToken ct)
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { return; }
            catch (DirectoryNotFoundException) { return; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                progress?.Report(new ScanProgress { Phase = ScanPhase.Scanning, Message = file, FilesScanned = result.FilesScanned });
                ScanOne(file, result, progress);
            }
        }

        private static IEnumerable<string> QuickScanTargets()
        {
            string[] candidates =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\Downloads",
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Temp",
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            };
            return candidates.Where(Directory.Exists);
        }

        private static string MapEngine(string engine) => engine switch
        {
            "clamav" => "ClamAV",
            "yara" => "YARA",
            _ => "optiCombat",
        };

        private static void Finish(ScanResult result, CancellationToken ct = default)
        {
            result.FinishedAt = DateTime.Now;
            if (result.Status == ScanStatus.Error) return;
            result.Status = ct.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
        }
    }

    /// <summary>Helpers JSON tolérants aux clés absentes.</summary>
    internal static class JsonElementExtensions
    {
        public static string GetPropertyOrDefault(this JsonElement e, string name, string fallback)
            => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString() ?? fallback
                : fallback;

        public static IEnumerable<JsonElement> GetArrayOrEmpty(this JsonElement e, string name)
            => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
                ? v.EnumerateArray()
                : Enumerable.Empty<JsonElement>();
    }
}
