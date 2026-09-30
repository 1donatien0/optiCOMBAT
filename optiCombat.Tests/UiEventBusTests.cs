using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class UiEventBusTests
{
    [Fact]
    public void RequestScanHistoryViewsRefresh_invokes_subscriber()
    {
        var bus = new UiEventBus();
        int calls = 0;
        bus.ScanHistoryViewsRefreshRequested += (_, _) => calls++;

        bus.RequestScanHistoryViewsRefresh();

        Assert.Equal(1, calls);
    }

    [Fact]
    public void RequestExportSessionPdf_passes_session()
    {
        var bus = new UiEventBus();
        ScanSession? received = null;
        var session = new ScanSession { SessionId = Guid.NewGuid(), StartedAt = DateTime.UtcNow };
        bus.ExportScanSessionPdfRequested += (_, s) => received = s;

        bus.RequestExportScanSessionPdf(session);

        Assert.Same(session, received);
    }

    [Fact]
    public void ClearHandlers_drops_subscribers()
    {
        var bus = new UiEventBus();
        int calls = 0;
        bus.ProtectionStateRefreshRequested += (_, _) => calls++;
        bus.ClearHandlers();

        bus.RequestProtectionStateRefresh();

        Assert.Equal(0, calls);
    }
}
