using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Strings;
using System.Linq;
using System.Windows.Input;
using WpfApp = System.Windows.Application;

namespace optiCombat.ViewModels
{
    public partial class ScanViewModel
    {
        private void QuarantineAllThreats()
        {
            if (Threats.Count == 0) return;
            if (!_confirm.ConfirmYesNo(
                    OpticombatStrings.Confirmations.QuarantineAll(Threats.Count),
                    OpticombatStrings.Confirmations.Title))
                return;

            var sessionId = ActiveScanSessionId;
            int count = _quarantine.QuarantineAll(Threats, sessionId);
            foreach (var threat in Threats.ToList())
            {
                if (IsPathCurrentlyQuarantined(threat.FilePath))
                    _quarantinedDuringScanPaths.Add(threat.FilePath);
            }
            LoadQuarantine();
            foreach (var threat in Threats.ToList())
            {
                if (IsPathCurrentlyQuarantined(threat.FilePath))
                    threat.Status = ThreatStatus.Quarantined;
            }
            StatusMessage = LocalizationService.Format("Vm_QuarantineBatch", count);
            _uiEvents.RequestScanHistoryViewsRefresh();
        }

        /// <summary>Appelé après une quarantaine réussie pendant un scan en cours.</summary>
        public void NotifyThreatQuarantinedDuringScan(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return;
            _quarantinedDuringScanPaths.Add(filePath);
            LoadQuarantine();
            _uiEvents.RequestScanHistoryViewsRefresh();
        }

        private bool IsPathCurrentlyQuarantined(string filePath) =>
            !string.IsNullOrWhiteSpace(filePath)
            && _quarantine.GetEntries().Any(e =>
                string.Equals(e.OriginalPath, filePath, StringComparison.OrdinalIgnoreCase));

        private void RestoreFromQuarantine(string? id)
        {
            if (string.IsNullOrEmpty(id)) return;
            bool ok = _quarantine.Restore(id);
            LoadQuarantine();
            StatusMessage = ok ? LocalizationService.GetString("Vm_RestoreOk") : LocalizationService.GetString("Vm_RestoreFail");
        }

        private void DeleteFromQuarantine(string? id)
        {
            if (string.IsNullOrEmpty(id)) return;
            bool ok = _quarantine.DeletePermanently(id);
            LoadQuarantine();
            StatusMessage = ok ? LocalizationService.GetString("Vm_DeleteOk") : LocalizationService.GetString("Vm_DeleteFail");
        }

        private void PurgeAll()
        {
            int total = _quarantine.Count;
            if (total == 0) return;
            if (!_confirm.ConfirmYesNo(
                    OpticombatStrings.Confirmations.PurgeQuarantine(total),
                    OpticombatStrings.Confirmations.Title))
                return;

            int count = _quarantine.PurgeAll();
            LoadQuarantine();
            StatusMessage = LocalizationService.Format("Vm_PurgeCount", count);
        }

        public void LoadQuarantine(bool reset = true)
        {
            WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                QuarantineTotalCount = _quarantine.Count;
                if (reset)
                    QuarantineEntries.Clear();
                var offset = QuarantineEntries.Count;
                foreach (var e in _quarantine.GetEntriesPaged(offset, QuarantinePageSize))
                    QuarantineEntries.Add(e);
                NotifyQuarantinePaging();
            });
        }

        private void LoadMoreQuarantinePage() => LoadQuarantine(reset: false);

        private void NotifyQuarantinePaging()
        {
            OnPropertyChanged(nameof(QuarantineHasMore));
            OnPropertyChanged(nameof(QuarantinePagingStatus));
            CommandManager.InvalidateRequerySuggested();
        }

        private void MigrateScanCountFromHistoryIfNeeded()
        {
            var prefs = _prefs.Current;
            if (prefs.TotalScansCount > 0) return;
            int n = _logger.GetHistory().Count;
            if (n <= 0) return;
            prefs.TotalScansCount = n;
            prefs.Save();
        }

        private void LoadHistory()
        {
            WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                History.Clear();
                foreach (var s in _logger.GetHistory())
                    History.Add(s);
            });
        }

        public void AppendLiveThreat(ThreatInfo threat)
        {
            if (string.IsNullOrWhiteSpace(threat.FilePath)) return;
            WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                if (Threats.Any(t => string.Equals(t.FilePath, threat.FilePath, StringComparison.OrdinalIgnoreCase)))
                    return;
                Threats.Add(threat);
                ThreatsFound = Threats.Count;
                OnPropertyChanged(nameof(SummaryDisplay));
            });
        }

        public void RemoveDetectedThreat(string? filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return;
            WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                var removed = Threats
                    .Where(t => string.Equals(t.FilePath, filePath, StringComparison.OrdinalIgnoreCase))
                    .ToList();
                if (removed.Count == 0)
                    return;
                foreach (var t in removed)
                    Threats.Remove(t);
                ThreatsFound = Threats.Count;
                OnPropertyChanged(nameof(SummaryDisplay));
            });
        }

        public void RefreshQuarantineList() => LoadQuarantine(reset: true);

        public void RefreshHistory()
        {
            LoadHistory();
            RefreshRecentTargets();
        }

        /// <summary>Recharge la liste des menaces depuis une session d'historique pour traitement dans Analyse.</summary>
        public void LoadThreatsFromHistorySession(ScanSession session)
        {
            if (session == null) return;
            WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                Threats.Clear();
                foreach (var t in session.Threats)
                    Threats.Add(t.Clone());
                ThreatsFound = Threats.Count;
                OnPropertyChanged(nameof(SummaryDisplay));
                StatusMessage = ThreatsFound > 0
                    ? LocalizationService.Format("Vm_HistReviewLoaded", session.StartedAt, ThreatsFound)
                    : LocalizationService.GetString("Scan_Ready");
            });
        }

        public void RefreshRecentTargets()
        {
            WpfApp.Current?.Dispatcher.Invoke(() =>
            {
                RecentTargets.Clear();
                foreach (var t in _prefs.Current.RecentTargets)
                    RecentTargets.Add(t);
            });
        }
    }
}
