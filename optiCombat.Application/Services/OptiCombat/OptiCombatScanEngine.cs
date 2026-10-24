// OptiCombatScanEngine.cs — implémentation IScanEngine adossée au cœur Rust optiCombat.
//
// FICHIER D'INTÉGRATION (à copier dans optiCombat/Services/OptiCombat/).
// Non inclus dans le projet par défaut pour ne pas imposer la DLL native au build.
// Compile contre .NET 8 ; nécessite opticombat_engine.dll déployée à côté de l'exécutable.
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
        private const string Dll = "opticombat_engine"; // opticombat_engine.dll / libopticombat_engine.so

        [DllImport(Dll, EntryPoint = "opticombat_scan_path", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ScanPath([MarshalAs(UnmanagedType.LPUTF8Str)] string path);

        [DllImport(Dll, EntryPoint = "opticombat_scan_json", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ScanJson([MarshalAs(UnmanagedType.LPUTF8Str)] string path);

        [DllImport(Dll, EntryPoint = "opticombat_string_free", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void StringFree(IntPtr s);

        [DllImport(Dll, EntryPoint = "opticombat_version", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr Version();

        [DllImport(Dll, EntryPoint = "opticombat_load_threat_intel", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long LoadThreatIntel([MarshalAs(UnmanagedType.LPUTF8Str)] string dir);

        [DllImport(Dll, EntryPoint = "opticombat_threat_intel_stats", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ThreatIntelStats();

        internal static string? ThreatIntelStatsManaged()
        {
            IntPtr ptr = ThreatIntelStats();
            if (ptr == IntPtr.Zero) return null;
            try { return Marshal.PtrToStringUTF8(ptr); }
            finally { StringFree(ptr); }
        }

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
        /// <summary>
        /// Filtre d'exclusion appliqué avant chaque fichier (renseigné par <see cref="ScanOrchestrator"/>).
        /// </summary>
        public Func<string, bool>? ExclusionFilter { get; set; }

        /// <summary>Dossier des exports abuse.ch lu par le cœur Rust.</summary>
        public string ThreatIntelDirectory { get; set; } = ThreatIntelFeedUpdater.DefaultDirectory;

        /// <summary>Appel natif de chargement (remplaçable dans les tests).</summary>
        internal Func<string, long> NativeLoadThreatIntel { get; set; } = OptiCombatNative.LoadThreatIntel;

        /// <summary>Appel natif de scan JSON (remplaçable dans les tests).</summary>
        internal Func<string, string?> NativeScanJson { get; set; } = OptiCombatNative.ScanJsonManaged;

        /// <summary>
        /// Entrées chargées lors du dernier chargement (−1 : jamais chargé ou moteur natif
        /// indisponible).
        /// </summary>
        public long ThreatIntelEntries => Interlocked.Read(ref _threatIntelEntries);

        private long _threatIntelEntries = -1;
        private int _threatIntelLoaded;

        /// <summary>
        /// Marque la threat intel comme à recharger : le prochain scan natif relit le dossier.
        /// N'appelle pas la DLL (sans effet si le moteur natif n'est pas utilisé).
        /// </summary>
        public void InvalidateThreatIntel() => Interlocked.Exchange(ref _threatIntelLoaded, 0);

        /// <summary>Charge la threat intel dans le cœur natif une fois (puis après chaque invalidation).</summary>
        internal void EnsureThreatIntelLoaded()
        {
            if (Interlocked.Exchange(ref _threatIntelLoaded, 1) == 0)
                ReloadThreatIntel();
        }

        /// <summary>
        /// Recharge les feeds abuse.ch dans le cœur natif. Renvoie le nombre d'entrées chargées,
        /// 0 si le dossier n'existe pas encore, −1 si la DLL est absente, bloquée ou trop ancienne.
        /// </summary>
        public long ReloadThreatIntel()
        {
            var dir = ThreatIntelDirectory;
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
            {
                Interlocked.Exchange(ref _threatIntelEntries, 0);
                return 0;
            }
            try
            {
                var n = NativeLoadThreatIntel(dir);
                Interlocked.Exchange(ref _threatIntelEntries, n);
                if (n < 0)
                    AppLogger.Warn("OptiCombatScanEngine", "Dossier de threat intel refusé par le moteur natif");
                else
                    AppLogger.Info("OptiCombatScanEngine", $"Threat intel abuse.ch chargée : {n} entrées");
                return n;
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException
                                       or BadImageFormatException or FileLoadException)
            {
                Interlocked.Exchange(ref _threatIntelEntries, -1);
                AppLogger.Info("OptiCombatScanEngine", $"Threat intel non chargée (moteur natif) : {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Énumération récursive tolérante : ignore les dossiers inaccessibles (au lieu d'interrompre
        /// toute l'analyse à la première exception) et ne suit pas les points de réanalyse
        /// (jonctions/liens symboliques → boucles et doublons).
        /// </summary>
        private static readonly EnumerationOptions TreeEnumeration = new()
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
            ReturnSpecialDirectories = false,
        };

        /// <summary>Disponibilité imposée (tests) ; sinon sonde de la DLL native.</summary>
        internal Func<bool>? AvailabilityOverride { get; set; }

        /// <summary>Dossier où opticombat_engine.dll est attendue (remplaçable dans les tests).</summary>
        internal string NativeBaseDirectory { get; set; } = AppContext.BaseDirectory;

        /// <summary>Lecture de la version native (remplaçable dans les tests).</summary>
        internal Func<string> NativeVersion { get; set; } = OptiCombatNative.VersionManaged;

        public bool IsAvailable
        {
            get
            {
                if (AvailabilityOverride != null)
                    return AvailabilityOverride();
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
        /// Teste le chargement P/Invoke. Windows Security / SAC peut bloquer opticombat_engine.dll
        /// avec FileLoadException (0x800711C7) — ne doit jamais faire crasher l'UI.
        /// </summary>
        private bool TryNativeProbe(out string? version, out string? failureReason)
        {
            version = null;
            failureReason = null;
            if (!ValidateNativeDllPath(NativeBaseDirectory, out failureReason))
                return false;
            try
            {
                version = NativeVersion();
                return true;
            }
            catch (Exception ex)
            {
                failureReason = ex.Message;
                return false;
            }
        }

        /// <summary>
        /// Rejette opticombat_engine.dll absente ou remplacée par une copie de optiCombat.dll.
        /// La bibliothèque s'appelait auparavant opticombat.dll : sur NTFS (insensible à la casse),
        /// c'était le même fichier que l'assembly optiCombat.dll du shell, que toute copie écrasait.
        /// </summary>
        internal static bool ValidateNativeDllPath(string baseDir, out string? failureReason)
        {
            failureReason = null;
            var nativePath = Path.Combine(baseDir, "opticombat_engine.dll");
            if (!File.Exists(nativePath))
            {
                failureReason =
                    "opticombat_engine.dll introuvable — exécutez scripts\\build-engine.ps1 (Rust requis) puis rebuild.";
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
                            "opticombat_engine.dll invalide (copie de optiCombat.dll) — supprimez-la et lancez scripts\\build-engine.ps1.";
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
            EnsureThreatIntelLoaded();
            var result = new ScanResult { Type = ScanType.File, TargetPath = filePath };
            progress?.Report(new ScanProgress { Phase = ScanPhase.Scanning, Message = filePath, TotalFiles = 1 });
            if (ExclusionFilter?.Invoke(filePath) == true)
                result.FilesSkipped++;
            else
                ScanOne(filePath, result, progress);
            Finish(result, ct);
            return Task.FromResult(result);
        }

        public Task<ScanResult> ScanFolderAsync(
            string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            // Les analyses récursives tournent hors du thread appelant (UI) : l'API P/Invoke est
            // synchrone et un dossier volumineux figeait l'interface.
            return Task.Run(() =>
            {
                EnsureThreatIntelLoaded();
                var result = new ScanResult { Type = ScanType.Folder, TargetPath = folderPath };
                ScanTree(folderPath, result, progress, ct);
                Finish(result, ct);
                return result;
            }, ct);
        }

        public Task<ScanResult> QuickScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            return Task.Run(() =>
            {
                EnsureThreatIntelLoaded();
                var result = new ScanResult { Type = ScanType.QuickScan, TargetPath = "QuickScan" };
                foreach (var dir in QuickScanTargets())
                    ScanTree(dir, result, progress, ct);
                Finish(result, ct);
                return result;
            }, ct);
        }

        public Task<ScanResult> FullScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            return Task.Run(() =>
            {
                EnsureThreatIntelLoaded();
                var result = new ScanResult { Type = ScanType.FullScan, TargetPath = "FullScan" };
                foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed))
                    ScanTree(drive.RootDirectory.FullName, result, progress, ct);
                Finish(result, ct);
                return result;
            }, ct);
        }

        // ── Cœur du mapping natif → modèles ──────────────────────────────────────

        private void ScanOne(string filePath, ScanResult result, IProgress<ScanProgress>? progress)
        {
            result.FilesScanned++;
            string? json;
            try { json = NativeScanJson(filePath); }
            catch (Exception ex)
            {
                result.Status = ScanStatus.Error;
                result.ErrorMessage = ex is DllNotFoundException
                    ? "opticombat_engine.dll introuvable"
                    : $"Moteur natif bloqué ou indisponible : {ex.Message}";
                return;
            }

            if (string.IsNullOrEmpty(json)) return;

            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                var verdict = root.GetPropertyOrDefault("verdict", "Clean");
                // Seul un verdict Malicious devient une menace (et peut donc être mis en
                // quarantaine automatiquement). Un verdict Suspicious — heuristique seule —
                // est journalisé : auparavant chaque indice devenait une « menace » distincte.
                if (verdict == "Suspicious")
                {
                    AppLogger.Info("OptiCombatScanEngine",
                        $"Fichier suspect (non mis en quarantaine) : {PathRedaction.RedactPath(filePath)}");
                    return;
                }
                if (verdict != "Malicious") return;

                // Pas de signature ClamAV complète (clamd injoignable) : à signaler une fois.
                if (root.TryGetProperty("clamd", out var clamd) && clamd.ValueKind == JsonValueKind.False)
                    WarnClamdUnavailableOnce();

                // Verdict obtenu sans moteur décisif (signature, réputation, OS) sur un binaire
                // signé par un éditeur de confiance : on ne le met pas en quarantaine.
                if (!HasDecisiveDetection(root) && AuthenticodeVerifier.IsTrustedSigned(filePath))
                {
                    AppLogger.Info("OptiCombatScanEngine",
                        $"Verdict heuristique ignoré (binaire signé Authenticode) : {PathRedaction.RedactPath(filePath)}");
                    return;
                }

                long size = -1;
                try { size = new FileInfo(filePath).Length; } catch (IOException) { }

                // Une seule menace par fichier : la détection au score le plus élevé.
                JsonElement? best = null;
                long bestScore = long.MinValue;
                foreach (var det in root.GetArrayOrEmpty("detections"))
                {
                    long score = det.TryGetProperty("score", out var s) && s.TryGetInt64(out var v) ? v : 0;
                    if (best == null || score > bestScore)
                    {
                        best = det;
                        bestScore = score;
                    }
                }

                var threat = new ThreatInfo
                {
                    FilePath = filePath,
                    VirusName = best?.GetPropertyOrDefault("name", verdict) ?? verdict,
                    FileSize = size,
                    Status = ThreatStatus.Detected,
                    DetectedBy = MapEngine(
                        best?.GetPropertyOrDefault("engine", "optiCombat") ?? "optiCombat",
                        best?.GetPropertyOrDefault("name", string.Empty)),
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
            catch (JsonException) { /* JSON inattendu : on ignore, fichier traité comme propre */ }
        }

        private void ScanTree(string root, ScanResult result, IProgress<ScanProgress>? progress, CancellationToken ct)
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(root, "*", TreeEnumeration); }
            catch (UnauthorizedAccessException) { return; }
            catch (DirectoryNotFoundException) { return; }
            catch (IOException) { return; }

            try
            {
                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    if (ExclusionFilter?.Invoke(file) == true)
                    {
                        result.FilesSkipped++;
                        continue;
                    }
                    progress?.Report(new ScanProgress { Phase = ScanPhase.Scanning, Message = file, FilesScanned = result.FilesScanned });
                    ScanOne(file, result, progress);
                }
            }
            catch (IOException ex)
            {
                // Volume retiré / erreur disque en cours d'énumération : on garde le résultat partiel.
                AppLogger.Warn("OptiCombatScanEngine", $"Énumération interrompue : {PathRedaction.RedactPath(root)}", ex);
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

        private static int _clamdWarned;

        private static void WarnClamdUnavailableOnce()
        {
            if (Interlocked.Exchange(ref _clamdWarned, 1) == 0)
                AppLogger.Warn("OptiCombatScanEngine",
                    "clamd injoignable : le cœur natif ne dispose que de la signature EICAR (activez clamd dans Options).");
        }

        /// <summary>Une détection provient-elle d'un moteur décisif (signatures, réputation, OS) ?</summary>
        internal static bool HasDecisiveDetection(JsonElement root)
        {
            foreach (var det in root.GetArrayOrEmpty("detections"))
            {
                if (det.GetPropertyOrDefault("engine", string.Empty) is "clamav" or "yara" or "reputation" or "windows")
                    return true;
            }
            return false;
        }

        internal static string MapEngine(string engine, string? name = null) => engine switch
        {
            "clamav" => "ClamAV",
            "yara" => "YARA",
            "reputation" when name?.StartsWith("MalwareBazaar:", StringComparison.Ordinal) == true => "MalwareBazaar",
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
