using optiCombat.Models;

namespace optiCombat.Services
{
    /// <summary>
    /// Normalise les événements <see cref="ScanProgress"/> pour un compteur de fichiers
    /// <b>monotone et croissant</b> (multi-moteurs ClamAV + YARA, multi-zones), comme les
    /// suites grand public : un seul nombre affiché, qui n'efface jamais un palier atteint.
    /// </summary>
    internal sealed class ScanProgressRelay
    {
        private readonly int _baseline;
        private int _filesHigh;
        private int _threatsHigh;
        private int _totalFilesHigh;
        private int _clamHigh;
        private int _yaraHigh;
        private int _prevClam;
        private int _prevYara;
        private int _parallelActivity;

        public ScanProgressRelay(int filesBaseline = 0)
        {
            _baseline = Math.Max(0, filesBaseline);
            _filesHigh = _baseline;
        }

        public int FilesScannedHigh => _filesHigh;

        public IProgress<ScanProgress>? ToParent(IProgress<ScanProgress>? parent)
        {
            if (parent == null)
                return null;

            return new RelayProgress(parent, this);
        }

        internal ScanProgress Normalize(ScanProgress p)
        {
            UpdateEngineHighs(p);

            int dClam = Math.Max(0, _clamHigh - _prevClam);
            int dYara = Math.Max(0, _yaraHigh - _prevYara);
            _prevClam = _clamHigh;
            _prevYara = _yaraHigh;

            if (p.Phase is ScanPhase.Scanning or ScanPhase.Starting or ScanPhase.ThreatFound)
                _parallelActivity += dClam + dYara;

            int maxEngine = Math.Max(_clamHigh, _yaraHigh);
            int displayLocal = maxEngine;

            if (p.Phase == ScanPhase.Completed)
            {
                maxEngine = Math.Max(_clamHigh, _yaraHigh);
                if (p.FilesScanned > 0)
                    maxEngine = Math.Max(maxEngine, p.FilesScanned);
                displayLocal = maxEngine;
                _parallelActivity = maxEngine;
                _filesHigh = _baseline + displayLocal;
            }
            else
            {
                if (_clamHigh > 0 && _yaraHigh > 0 && maxEngine > 0)
                {
                    // Les deux moteurs tournent : le compteur continue d'avancer avec le plus lent
                    // (évite un plateau quand ClamAV est en avance et YARA progresse encore).
                    int headroom = Math.Max(1, maxEngine / 5);
                    displayLocal = Math.Max(maxEngine, Math.Min(_parallelActivity, maxEngine + headroom));
                }

                if (displayLocal > 0)
                    _filesHigh = Math.Max(_filesHigh, _baseline + displayLocal);
            }

            if (p.ThreatsFound > 0)
                _threatsHigh = Math.Max(_threatsHigh, p.ThreatsFound);

            if (p.TotalFiles > 0)
                _totalFilesHigh = Math.Max(_totalFilesHigh, p.TotalFiles);
            if (_filesHigh > _totalFilesHigh)
                _totalFilesHigh = _filesHigh;

            var r = p.Clone();
            r.FilesScanned = _filesHigh;
            r.ClamFilesScanned = _clamHigh;
            r.YaraFilesScanned = _yaraHigh;
            if (_threatsHigh > 0)
                r.ThreatsFound = Math.Max(r.ThreatsFound, _threatsHigh);

            r.TotalFiles = _totalFilesHigh;

            r.Message = ScanUserDisplay.SyncFileCountInMessage(p.Message, _filesHigh);
            return r;
        }

        private void UpdateEngineHighs(ScanProgress p)
        {
            if (p.ClamFilesScanned > 0)
                _clamHigh = Math.Max(_clamHigh, p.ClamFilesScanned);
            if (p.YaraFilesScanned > 0)
                _yaraHigh = Math.Max(_yaraHigh, p.YaraFilesScanned);
        }

        private sealed class RelayProgress(IProgress<ScanProgress> parent, ScanProgressRelay relay) : IProgress<ScanProgress>
        {
            public void Report(ScanProgress value) => parent.Report(relay.Normalize(value));
        }
    }
}
