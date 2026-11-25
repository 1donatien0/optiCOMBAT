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
        private readonly Func<CancellationToken, Task<bool>>? _ensureReady;
        private readonly Func<ClamdClient> _clientFactory;

        public ClamdEngine(
            IUserPreferencesAccessor? preferences = null,
            IExclusionSettingsAccessor? exclusions = null)
            : this(preferences, exclusions, null, () => new ClamdClient(), new ClamAvEngine())
        {
        }

        /// <summary>Constructeur de test : démon (disponibilité) et client clamd injectés.</summary>
        internal ClamdEngine(
            IUserPreferencesAccessor? preferences,
            IExclusionSettingsAccessor? exclusions,
            Func<CancellationToken, Task<bool>>? ensureReady,
            Func<ClamdClient> clientFactory,
            ClamAvEngine fallbackProbe)
        {
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
            _ensureReady = ensureReady;
            _clientFactory = clientFactory;
            _fallbackProbe = fallbackProbe;
        }

        /// <summary>Dernier mode utilisé (diagnostic UI).</summary>
        public static string LastMode { get; internal set; } = "clamd";

        public bool IsClamAvInstalled() => _fallbackProbe.IsClamAvInstalled();

        public async Task<bool> TryEnsureReadyAsync(CancellationToken ct = default)
        {
            if (!_prefs.Current.UseClamdEngine)
                return false;
            if (_ensureReady != null)
                return await _ensureReady(ct).ConfigureAwait(false);
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
                ScanResult partial;
                try
                {
                    partial = await ScanFileAsync(file, progress, ct).ConfigureAwait(false);
                }
                catch (FileNotFoundException)
                {
                    // Fichier supprimé entre le test d'existence et l'analyse (fichier temporaire).
                    continue;
                }
                if (partial.Status == ScanStatus.Cancelled)
                {
                    merged.Status = ScanStatus.Cancelled;
                    merged.FinishedAt = DateTime.Now;
                    return merged;
                }

                if (partial.Status == ScanStatus.Error)
                    throw new IOException(partial.ErrorMessage ?? "Erreur clamd sur un fichier de la liste.");

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
                using var client = _clientFactory();
                var response = recursive
                    ? await client.ScanRecursiveAsync(targetPath, ct).ConfigureAwait(false)
                    : await client.ScanFileAsync(targetPath, ct).ConfigureAwait(false);

                // Réponse tronquée ou absente : ne jamais conclure « aucune menace ».
                // L'exception remonte au backend composite, qui relance l'analyse avec clamscan.
                if (!response.Completed)
                    throw new ClamdIncompleteResponseException(
                        $"Réponse clamd incomplète pour {PathRedaction.RedactPath(targetPath)}");

                var errorLines = 0;
                foreach (var line in response.Text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (ct.IsCancellationRequested) break;
                    if (IsClamdErrorLine(line))
                    {
                        errorLines++;
                        continue;
                    }
                    lock (_parseLock)
                        ClamScanLineParser.ProcessLine(line, result, progress, _exclusions);
                }

                // clamd n'a pas pu lire la cible (droits, verrou, chemin) : rien n'a été
                // analysé, le résultat ne doit pas être « aucune menace ». L'exception
                // fait relancer l'analyse par clamscan (processus de l'utilisateur).
                if (!ct.IsCancellationRequested
                    && errorLines > 0
                    && result.FilesScanned == 0
                    && result.Threats.Count == 0)
                {
                    throw new IOException(
                        $"clamd n'a pas pu analyser {PathRedaction.RedactPath(targetPath)} ({errorLines} erreur(s)).");
                }

                if (errorLines > 0)
                    AppLogger.Warn("ClamdEngine", $"{errorLines} fichier(s) non lisible(s) par clamd sous {PathRedaction.RedactPath(targetPath)}");

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
                // Toute panne clamd (socket, réponse incomplète, parse) remonte au
                // backend composite, qui relance l'analyse avec clamscan. Ne pas
                // renvoyer ScanStatus.Error : ce statut était présenté comme un
                // scan terminé, sans repli.
                AppLogger.Error("ClamdEngine", $"Scan {PathRedaction.RedactPath(targetPath)}", ex);
                throw;
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

        /// <summary>
        /// Ligne d'erreur clamd : « chemin: raison ERROR » ou réponse globale
        /// (« UNKNOWN COMMAND », « COMMAND READ TIMED OUT »…).
        /// </summary>
        internal static bool IsClamdErrorLine(string line)
        {
            var t = line.TrimEnd();
            return t.EndsWith(" ERROR", StringComparison.Ordinal)
                || t.Equals("UNKNOWN COMMAND", StringComparison.OrdinalIgnoreCase)
                || t.Equals("COMMAND READ TIMED OUT", StringComparison.OrdinalIgnoreCase);
        }
    }
}
