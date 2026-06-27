using optiCombat.Localization;
using optiCombat.Models;
using System.IO;
using System.Runtime.Versioning;

namespace optiCombat.Services
{
    /// <summary>Moteur ClamAV via daemon clamd (TCP) — signatures chargées en mémoire.</summary>
    [SupportedOSPlatform("windows")]
    internal sealed class ClamdEngine : IClamAvOrchestratorBackend
    {
        private readonly ClamAvEngine _fallbackProbe;
        private readonly object _parseLock = new();
        private readonly IUserPreferencesAccessor _prefs;
        private readonly IExclusionSettingsAccessor _exclusions;

        public ClamdEngine(
            IUserPreferencesAccessor? preferences = null,
            IExclusionSettingsAccessor? exclusions = null)
        {
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
            _fallbackProbe = new ClamAvEngine();
        }

        /// <summary>Dernier mode utilisé (diagnostic UI).</summary>
        public static string LastMode { get; internal set; } = "clamd";

        public bool IsClamAvInstalled() => _fallbackProbe.IsClamAvInstalled();

        public async Task<bool> TryEnsureReadyAsync(CancellationToken ct = default)
        {
            if (!_prefs.Current.UseClamdEngine)
                return false;
            if (!ClamdHost.Shared.IsBinaryPresent)
                return false;
            return await ClamdHost.Shared.EnsureRunningAsync(ct).ConfigureAwait(false);
        }

        public Task<ScanResult> ScanFileAsync(
            string filePath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("Fichier introuvable.", filePath);
            return RunScanAsync(ScanType.File, filePath, recursive: false, progress, ct);
        }

        public Task<ScanResult> ScanFolderAsync(
            string folderPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (!Directory.Exists(folderPath))
                throw new DirectoryNotFoundException($"Dossier introuvable : {folderPath}");
            return RunScanAsync(ScanType.Folder, folderPath, recursive: true, progress, ct);
        }

        public Task<ScanResult> ScanFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (files.Count == 0)
            {
                var now = DateTime.Now;
                return Task.FromResult(new ScanResult
                {
                    Type = ScanType.Folder,
                    TargetPath = targetPath,
                    StartedAt = now,
                    FinishedAt = now,
                    Status = ScanStatus.Completed,
                    FilesScanned = 0,
                });
            }

            return RunFileListViaClamdAsync(files, targetPath, progress, ct);
        }

        private async Task<ScanResult> RunFileListViaClamdAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<ScanProgress>? progress,
            CancellationToken ct)
        {
            if (!await TryEnsureReadyAsync(ct).ConfigureAwait(false))
                throw new InvalidOperationException(LocalizationService.GetString("Clamd_NotReady"));

            LastMode = "clamd";
            var merged = new ScanResult
            {
                Type = ScanType.Folder,
                TargetPath = targetPath,
                StartedAt = DateTime.Now,
                Status = ScanStatus.Running,
            };

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) break;
                if (!File.Exists(file)) continue;
                var partial = await ScanFileAsync(file, progress, ct).ConfigureAwait(false);
                foreach (var threat in partial.Threats)
                    merged.Threats.Add(threat);
                merged.FilesScanned += Math.Max(partial.FilesScanned, 1);
            }

            merged.FinishedAt = DateTime.Now;
            merged.Status = ct.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
            return merged;
        }

        private async Task<ScanResult> RunScanAsync(
            ScanType type, string targetPath, bool recursive,
            IProgress<ScanProgress>? progress, CancellationToken ct)
        {
            if (!await TryEnsureReadyAsync(ct).ConfigureAwait(false))
                throw new InvalidOperationException(LocalizationService.GetString("Clamd_NotReady"));

            LastMode = "clamd";

            var result = new ScanResult
            {
                Type = type,
                TargetPath = targetPath,
                StartedAt = DateTime.Now,
                Status = ScanStatus.Running,
            };

            progress?.Report(new ScanProgress
            {
                Message = LocalizationService.Format("Scan_Progress_Starting", Path.GetFileName(targetPath)),
                Phase = ScanPhase.Starting,
                CurrentFilePath = targetPath,
            });

            try
            {
                using var client = new ClamdClient();
                string output = recursive
                    ? await client.ScanRecursiveAsync(targetPath, ct).ConfigureAwait(false)
                    : await client.ScanFileAsync(targetPath, ct).ConfigureAwait(false);

                foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (ct.IsCancellationRequested) break;
                    lock (_parseLock)
                        ClamScanLineParser.ProcessLine(line, result, progress, _exclusions);
                }

                result.FinishedAt = DateTime.Now;
                result.Status = ct.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
            }
            catch (OperationCanceledException)
            {
                result.Status = ScanStatus.Cancelled;
                result.FinishedAt = DateTime.Now;
            }
            catch (Exception ex)
            {
                result.Status = ScanStatus.Error;
                result.ErrorMessage = ex.Message;
                result.FinishedAt = DateTime.Now;
                AppLogger.Error("ClamdEngine", $"Scan {targetPath}", ex);
            }

            progress?.Report(new ScanProgress
            {
                Message = result.SummaryDisplay,
                Phase = ScanPhase.Completed,
                FilesScanned = result.FilesScanned,
                ThreatsFound = result.ThreatsFound,
            });

            return result;
        }
    }
}
