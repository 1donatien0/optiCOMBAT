using optiCombat.Models;

namespace optiCombat.Services
{
    /// <summary>
    /// Garde une trace dans l'Historique des détections de la protection temps réel et de la
    /// surveillance des processus (jusqu'ici visibles uniquement par un toast éphémère).
    /// </summary>
    public static class DetectionHistoryRecorder
    {
        /// <summary>
        /// Enregistre le résultat d'analyse d'un fichier comme une session « Protection temps réel »
        /// (visible dans Historique → Menaces, avec ses actions Quarantaine / Ignorer / Supprimer).
        /// </summary>
        /// <returns><c>true</c> si une entrée a été écrite.</returns>
        public static bool Record(ScanLogManager? logger, IUiEventBus? uiEvents, ScanResult? result, string filePath)
        {
            if (logger is null || result is null || result.Threats.Count == 0)
                return false;

            try
            {
                var now = DateTime.Now;
                result.Type = ScanType.RealTime;
                result.TargetPath = filePath;
                result.FilesScanned = Math.Max(1, result.FilesScanned);
                result.FinishedAt ??= now;
                if (result.StartedAt == default)
                    result.StartedAt = now;
                if (result.Status != ScanStatus.Completed)
                    result.Status = ScanStatus.Completed;

                logger.SaveScanResult(result);
                uiEvents?.RequestScanHistoryViewsRefresh();
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("DetectionHistoryRecorder", $"Enregistrement impossible : {filePath}", ex);
                return false;
            }
        }
    }
}
