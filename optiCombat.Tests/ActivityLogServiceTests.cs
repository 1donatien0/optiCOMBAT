using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ActivityLogServiceTests : IDisposable
{
    private readonly string _logDir;
    private readonly ScanLogManager _logger;
    private readonly ActivityLogService _activityLog;
    private readonly QuarantineManager _quarantine;

    public ActivityLogServiceTests()
    {
        _logDir = Path.Combine(Path.GetTempPath(), "opticombat_actlog_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_logDir);
        _logger = new ScanLogManager(_logDir);
        _activityLog = new ActivityLogService(_logger, _logDir);
        _logger.BindActivityLog(_activityLog);
        _quarantine = new QuarantineManager(Path.Combine(_logDir, "q"));
        _quarantine.BindActivityLog(_activityLog);
    }

    public void Dispose()
    {
        try { Directory.Delete(_logDir, recursive: true); } catch { }
    }

    private string CreateSampleFile(string name, byte[]? payload = null)
    {
        payload ??= new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var path = Path.Combine(_logDir, name);
        File.WriteAllBytes(path, payload);
        return path;
    }

    [Fact]
    public void GetActivityFeed_orders_scan_clean_and_quarantine_events()
    {
        var sessionId = Guid.NewGuid();
        _logger.SaveScanResult(new ScanResult
        {
            SessionId = sessionId,
            StartedAt = new DateTime(2026, 1, 1, 12, 0, 0),
            Type = ScanType.QuickScan,
            TargetPath = @"C:\",
            Status = ScanStatus.Completed,
            FilesScanned = 5,
        });
        _logger.SaveCleanSession(new CleanSession
        {
            StartedAt = new DateTime(2026, 1, 2, 8, 0, 0),
            FinishedAt = new DateTime(2026, 1, 2, 8, 5, 0),
            TargetsSummary = "Temp",
            BytesFreed = 2048,
        });

        var sample = CreateSampleFile("evil.exe");
        var threat = new ThreatInfo
        {
            FilePath = sample,
            VirusName = "Test.Malware",
            FileSize = 4,
            DetectedAt = new DateTime(2026, 1, 3, 10, 0, 0),
        };
        Assert.True(_quarantine.Quarantine(threat, sessionId));

        var feed = _activityLog.GetActivityFeed(_quarantine);
        Assert.Equal(3, feed.Count);
        Assert.Equal(ActivityKind.Quarantine, feed[0].Kind);
        Assert.Equal(ActivityKind.Clean, feed[1].Kind);
        Assert.Equal(ActivityKind.Scan, feed[2].Kind);
    }

    [Fact]
    public void GetActivityFeed_marks_still_quarantined_files()
    {
        var sample = CreateSampleFile("q.exe");
        var threat = new ThreatInfo
        {
            FilePath = sample,
            VirusName = "Q.Test",
            FileSize = 4,
            DetectedAt = DateTime.UtcNow,
        };
        Assert.True(_quarantine.Quarantine(threat));

        var feed = _activityLog.GetActivityFeed(_quarantine);
        var q = Assert.Single(feed);
        Assert.True(q.IsStillQuarantined);
    }

    [Fact]
    public void Trim_retains_at_most_150_newest_events()
    {
        for (var i = 0; i < 160; i++)
        {
            _logger.SaveScanResult(new ScanResult
            {
                SessionId = Guid.NewGuid(),
                StartedAt = DateTime.UtcNow.AddMinutes(-i),
                FinishedAt = DateTime.UtcNow.AddMinutes(-i),
                Type = ScanType.QuickScan,
                TargetPath = $@"C:\scan_{i}",
                Status = ScanStatus.Completed,
                FilesScanned = 1,
            });
        }

        var feed = _activityLog.GetActivityFeed(_quarantine);
        Assert.True(feed.Count <= 150);
    }
}
