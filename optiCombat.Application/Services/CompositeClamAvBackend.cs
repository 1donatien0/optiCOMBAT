using optiCombat.Models;

namespace optiCombat.Services
{
    /// <summary>
    /// Préfère clamd (daemon) si activé et disponible, sinon repli sur clamscan.exe.
    /// </summary>
    internal sealed class CompositeClamAvBackend : IClamAvOrchestratorBackend
    {
        private readonly Func<CancellationToken, Task<bool>> _tryClamdReady;
        private readonly IClamAvOrchestratorBackend _clamd;
        private readonly IClamAvOrchestratorBackend _clamscan;

        public CompositeClamAvBackend(ClamdEngine clamd, ClamAvEngine clamscan)
            : this(ct => clamd.TryEnsureReadyAsync(ct), clamd, clamscan)
        {
        }

        /// <summary>Constructeur de test (backends injectables).</summary>
        internal CompositeClamAvBackend(
            Func<CancellationToken, Task<bool>> tryClamdReady,
            IClamAvOrchestratorBackend clamdBackend,
            IClamAvOrchestratorBackend clamscanBackend)
        {
            _tryClamdReady = tryClamdReady;
            _clamd = clamdBackend;
            _clamscan = clamscanBackend;
        }

        /// <summary><c>clamd</c> ou <c>clamscan</c> — dernier moteur Clam utilisé.</summary>
        public string ActiveEngine => ClamdEngine.LastMode;

        public bool IsClamAvInstalled() => _clamscan.IsClamAvInstalled();

        public Task<ScanResult> ScanFileAsync(
            string filePath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
            => ScanWithClamdFallbackAsync(
                backend => backend.ScanFileAsync(filePath, progress, ct),
                "clamd fichier — repli clamscan",
                ct);

        public Task<ScanResult> ScanFolderAsync(
            string folderPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
            => ScanWithClamdFallbackAsync(
                backend => backend.ScanFolderAsync(folderPath, progress, ct),
                "clamd dossier — repli clamscan",
                ct);

        public Task<ScanResult> ScanFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            // clamscan --file-list = un seul processus ; plus rapide que N appels clamd.
            ClamdEngine.LastMode = "clamscan";
            return _clamscan.ScanFileListAsync(files, targetPath, progress, ct);
        }

        private async Task<ScanResult> ScanWithClamdFallbackAsync(
            Func<IClamAvOrchestratorBackend, Task<ScanResult>> run,
            string warnMessage,
            CancellationToken ct)
        {
            if (await _tryClamdReady(ct).ConfigureAwait(false))
            {
                try
                {
                    var result = await run(_clamd).ConfigureAwait(false);
                    if (result.Status != ScanStatus.Error)
                        return result;
                    AppLogger.Warn("CompositeClamAv", warnMessage + " (statut erreur)");
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("CompositeClamAv", warnMessage, ex);
                }
            }

            ClamdEngine.LastMode = "clamscan";
            return await run(_clamscan).ConfigureAwait(false);
        }
    }
}
