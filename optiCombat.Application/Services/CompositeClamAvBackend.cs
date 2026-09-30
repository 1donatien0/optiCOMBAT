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

        public async Task<Models.ScanResult> ScanFileAsync(
            string filePath,
            IProgress<Models.ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (await _tryClamdReady(ct).ConfigureAwait(false))
            {
                try
                {
                    return await _clamd.ScanFileAsync(filePath, progress, ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("CompositeClamAv", "clamd fichier — repli clamscan", ex);
                }
            }

            ClamdEngine.LastMode = "clamscan";
            return await _clamscan.ScanFileAsync(filePath, progress, ct).ConfigureAwait(false);
        }

        public async Task<Models.ScanResult> ScanFolderAsync(
            string folderPath,
            IProgress<Models.ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (await _tryClamdReady(ct).ConfigureAwait(false))
            {
                try
                {
                    return await _clamd.ScanFolderAsync(folderPath, progress, ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("CompositeClamAv", "clamd dossier — repli clamscan", ex);
                }
            }

            ClamdEngine.LastMode = "clamscan";
            return await _clamscan.ScanFolderAsync(folderPath, progress, ct).ConfigureAwait(false);
        }

        public Task<Models.ScanResult> ScanFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<Models.ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            // clamscan --file-list = un seul processus ; plus rapide que N appels clamd.
            ClamdEngine.LastMode = "clamscan";
            return _clamscan.ScanFileListAsync(files, targetPath, progress, ct);
        }
    }
}
