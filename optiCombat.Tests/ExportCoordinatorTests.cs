using optiCombat.Coordinators;
using optiCombat.Models;
using optiCombat.Services;
using System.Windows;

namespace optiCombat.Tests;

public sealed class ExportCoordinatorTests
{
    private sealed class FakeExport : IHistoryExportService
    {
        public HistoryExportResult HtmlResult { get; init; } = HistoryExportResult.UserCancelled;
        public HistoryExportResult PdfResult { get; init; } = HistoryExportResult.UserCancelled;

        public HistoryExportResult TryExportHtml(
            Window owner,
            ScanLogManager? logManager,
            IEnumerable<ThreatInfo> threats,
            IEnumerable<QuarantineEntry> quarantine) => HtmlResult;

        public HistoryExportResult TryExportSessionPdf(Window owner, ScanSession session) => PdfResult;
    }

    [Fact]
    public void TryExportHtml_user_cancel_does_not_set_status()
    {
        var coordinator = new ExportCoordinator(new FakeExport());
        string? status = null;

        coordinator.TryExportHtml(new ExportContext(
            null!,
            null,
            Array.Empty<ThreatInfo>(),
            Array.Empty<QuarantineEntry>(),
            (msg, _, _) => status = msg));

        Assert.Null(status);
    }

    [Fact]
    public void TryExportHtml_success_reports_message()
    {
        var coordinator = new ExportCoordinator(new FakeExport
        {
            HtmlResult = HistoryExportResult.Succeeded("saved.html"),
        });
        string? status = null;
        bool? isError = null;

        coordinator.TryExportHtml(new ExportContext(
            null!,
            null,
            Array.Empty<ThreatInfo>(),
            Array.Empty<QuarantineEntry>(),
            (msg, err, _) => { status = msg; isError = err; }));

        Assert.Equal("saved.html", status);
        Assert.False(isError);
    }
}
