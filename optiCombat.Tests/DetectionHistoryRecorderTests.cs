using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class DetectionHistoryRecorderTests : IDisposable
{
    private readonly string _logDir;
    private readonly ScanLogManager _logger;

    public DetectionHistoryRecorderTests()
    {
        _logDir = Path.Combine(Path.GetTempPath(), "opticombat_det_" + Guid.NewGuid().ToString("N"));
        _logger = new ScanLogManager(_logDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_logDir, recursive: true); } catch { }
    }

    private static ScanResult WithThreat(string path) => new()
    {
        Type = ScanType.File,
        TargetPath = path,
        Status = ScanStatus.Completed,
        Threats = { ThreatInfo.FromClamAv(path, "Test.Threat", 10) },
    };

    [Fact]
    public void Record_saves_realtime_session_visible_in_history_and_timeline()
    {
        var activity = new ActivityLogService(_logger, _logDir);
        _logger.BindActivityLog(activity);
        var ui = new UiEventBus();
        int refreshed = 0;
        ui.ScanHistoryViewsRefreshRequested += (_, _) => refreshed++;

        bool saved = DetectionHistoryRecorder.Record(_logger, ui, WithThreat(@"C:\x\bad.exe"), @"C:\x\bad.exe");

        Assert.True(saved);
        var session = Assert.Single(_logger.GetHistory());
        Assert.Equal(ScanType.RealTime, session.ScanTypeValue);
        Assert.Equal(@"C:\x\bad.exe", session.TargetPath);
        Assert.Single(session.Threats);
        Assert.Equal(1, refreshed);

        var feed = activity.GetActivityFeed(new QuarantineManager(Path.Combine(_logDir, "q")));
        var entry = Assert.Single(feed);
        Assert.True(entry.HasThreats);
        Assert.True(entry.HasPendingThreats);
    }

    [Fact]
    public void Record_ignores_clean_results_and_missing_logger()
    {
        var clean = new ScanResult { Type = ScanType.File, Status = ScanStatus.Completed };

        Assert.False(DetectionHistoryRecorder.Record(_logger, null, clean, @"C:\ok.txt"));
        Assert.False(DetectionHistoryRecorder.Record(null, null, WithThreat(@"C:\bad.exe"), @"C:\bad.exe"));
        Assert.Empty(_logger.GetHistory());
    }
}
