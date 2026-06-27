using optiCombat.Models;
using System.Windows;

namespace optiCombat.Services;

/// <summary>Contrat testable pour l'export HTML/PDF de l'historique.</summary>
public interface IHistoryExportService
{
    HistoryExportResult TryExportHtml(
        Window owner,
        ScanLogManager? logManager,
        IEnumerable<ThreatInfo> threats,
        IEnumerable<QuarantineEntry> quarantine);

    HistoryExportResult TryExportSessionPdf(Window owner, ScanSession session);
}
