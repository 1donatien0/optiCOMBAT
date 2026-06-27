using optiCombat.Localization;
using optiCombat.Models;
using System.IO;
using System.Windows;
using SaveFileDialog = Microsoft.Win32.SaveFileDialog;

namespace optiCombat.Services
{
    /// <summary>Export HTML/PDF de l'historique — logique extraite de <see cref="MainWindow"/>.</summary>
    public sealed class HistoryExportService : IHistoryExportService
    {
        private readonly IUserPreferencesAccessor _prefs;

        public HistoryExportService(IUserPreferencesAccessor? preferences = null)
        {
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
        }

        public HistoryExportResult TryExportHtml(
            Window owner,
            ScanLogManager? logManager,
            IEnumerable<ThreatInfo> threats,
            IEnumerable<QuarantineEntry> quarantine)
        {
            try
            {
                var dlg = new SaveFileDialog
                {
                    Filter = LocalizationService.GetString("Export_HtmlFilter"),
                    FileName = $"optiCombat_rapport_{DateTime.Now:yyyyMMdd_HHmm}.html",
                    DefaultExt = ".html",
                    AddExtension = true
                };
                if (dlg.ShowDialog(owner) != true)
                    return HistoryExportResult.UserCancelled;

                var html = new HtmlExportService();
                var hist = logManager?.GetHistory() ?? Array.Empty<ScanSession>();
                html.ExportFullReport(hist, threats, quarantine, _prefs.Current, dlg.FileName);
                return HistoryExportResult.Succeeded(
                    LocalizationService.Format("Status_HtmlSaved", dlg.FileName));
            }
            catch (Exception ex)
            {
                AppLogger.Error("HistoryExportService", "Export HTML", ex);
                return HistoryExportResult.Failed(
                    LocalizationService.Format("Status_HtmlFailed", ex.Message));
            }
        }

        public HistoryExportResult TryExportSessionPdf(Window owner, ScanSession session)
        {
            try
            {
                var dlg = new SaveFileDialog
                {
                    Filter = LocalizationService.GetString("Export_PdfFilter"),
                    FileName = $"optiCombat_scan_{session.StartedAt:yyyyMMdd_HHmm}.pdf",
                    DefaultExt = ".pdf",
                    AddExtension = true
                };
                if (dlg.ShowDialog(owner) != true)
                    return HistoryExportResult.UserCancelled;

                var gen = new PdfReportGenerator();
                gen.GenerateReportFromSession(session, dlg.FileName);
                return HistoryExportResult.Succeeded(
                    LocalizationService.Format("Status_PdfSaved", dlg.FileName));
            }
            catch (Exception ex)
            {
                AppLogger.Error("HistoryExportService", "Export PDF", ex);
                return HistoryExportResult.Failed(
                    LocalizationService.Format("Status_PdfFailed", ex.Message));
            }
        }
    }

    public readonly struct HistoryExportResult
    {
        public bool WasCancelled { get; init; }
        public bool Success { get; init; }
        public string Message { get; init; }
        public bool IsError { get; init; }

        public static HistoryExportResult UserCancelled => new() { WasCancelled = true };

        public static HistoryExportResult Succeeded(string message) =>
            new() { Success = true, Message = message };

        public static HistoryExportResult Failed(string message) =>
            new() { Success = false, IsError = true, Message = message };
    }
}
