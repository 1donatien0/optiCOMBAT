using optiCombat.Models;
using optiCombat.Services;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Text.Json;

namespace optiCombat.Tests;

public sealed class ScanLogManagerTests : IDisposable
{
    private readonly string _logDir;
    private readonly ScanLogManager _manager;

    public ScanLogManagerTests()
    {
        _logDir = Path.Combine(Path.GetTempPath(), "opticombat_logs_" + Guid.NewGuid().ToString("N"));
        _manager = new ScanLogManager(_logDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_logDir, recursive: true); } catch { }
    }

    [Fact]
    public void ActivityLog_feed_merges_scans_and_cleans_newest_first()
    {
        var activityLog = new ActivityLogService(_manager, _logDir);
        _manager.BindActivityLog(activityLog);
        var quarantine = new QuarantineManager(Path.Combine(_logDir, "q"));

        var scanTime = new DateTime(2026, 1, 10, 12, 0, 0);
        var cleanTime = new DateTime(2026, 1, 11, 8, 0, 0);

        _manager.SaveScanResult(new ScanResult
        {
            StartedAt = scanTime,
            Type = ScanType.QuickScan,
            TargetPath = @"C:\scan",
            Status = ScanStatus.Completed,
            FilesScanned = 10,
        });
        _manager.SaveCleanSession(new CleanSession
        {
            StartedAt = cleanTime,
            FinishedAt = cleanTime.AddMinutes(2),
            TargetsSummary = "Temp",
            BytesFreed = 1024,
        });

        var feed = activityLog.GetActivityFeed(quarantine);
        Assert.Equal(2, feed.Count);
        Assert.Equal(ActivityKind.Clean, feed[0].Kind);
        Assert.Equal(cleanTime, feed[0].StartedAt);
        Assert.Equal(ActivityKind.Scan, feed[1].Kind);
        Assert.Equal(scanTime, feed[1].StartedAt);
    }

    [Fact]
    public void ReconcileQuarantinedThreats_removes_paths_already_in_quarantine()
    {
        var sessionId = Guid.NewGuid();
        _manager.SaveScanResult(new ScanResult
        {
            SessionId = sessionId,
            StartedAt = DateTime.Now,
            Type = ScanType.RemovableDrive,
            TargetPath = @"F:\",
            Status = ScanStatus.Completed,
            FilesScanned = 1,
            Threats = { ThreatInfo.FromClamAv(@"F:\cob.exe", "Test.Eicar", 68) },
        });

        var session = Assert.Single(_manager.GetHistory());
        Assert.Single(session.Threats);

        int removed = _manager.ReconcileQuarantinedThreats(new[]
        {
            new QuarantineEntry { OriginalPath = @"F:\cob.exe" },
        });

        Assert.Equal(1, removed);
        session = Assert.Single(_manager.GetHistory());
        Assert.Empty(session.Threats);
    }

    [Fact]
    public void SaveScanResult_trims_50_oldest_when_reaching_100_then_grows_again()
    {
        for (int i = 0; i < 100; i++)
            _manager.SaveScanResult(new ScanResult { Type = ScanType.QuickScan, TargetPath = $"t-{i}", Status = ScanStatus.Completed, FilesScanned = i });

        Assert.Equal(50, _manager.GetHistory().Count);
        Assert.Equal(99, _manager.GetHistory()[0].FilesScanned);

        for (int i = 100; i < 105; i++)
            _manager.SaveScanResult(new ScanResult { Type = ScanType.QuickScan, TargetPath = $"t-{i}", Status = ScanStatus.Completed, FilesScanned = i });

        Assert.Equal(55, _manager.GetHistory().Count);
        Assert.Equal(104, _manager.GetHistory()[0].FilesScanned);
    }

    [Fact]
    public void SaveScanResult_persists_threat_details()
    {
        _manager.SaveScanResult(new ScanResult
        {
            Type = ScanType.File, TargetPath = @"C:\test.exe", Status = ScanStatus.Completed, FilesScanned = 1,
            Threats = { ThreatInfo.FromClamAv(@"C:\infected.dll", "Test.Virus", 1024) }
        });

        var session = _manager.GetHistory()[0];
        Assert.Single(session.Threats);
        Assert.Equal(@"C:\infected.dll", session.Threats[0].FilePath);
        Assert.Equal("Test.Virus", session.Threats[0].VirusName);
    }

    [Fact]
    public void TryRemoveThreatFromSession_updates_count_and_persists()
    {
        var sessionId = Guid.NewGuid();
        _manager.SaveScanResult(new ScanResult
        {
            SessionId = sessionId, Type = ScanType.File, TargetPath = @"C:\folder", Status = ScanStatus.Completed,
            Threats = { ThreatInfo.FromClamAv(@"C:\a.exe", "A", 1), ThreatInfo.FromClamAv(@"C:\b.exe", "B", 1) }
        });

        Assert.Equal(2, _manager.GetHistory().First(s => s.SessionId == sessionId).ThreatsFound);
        Assert.True(_manager.TryRemoveThreatFromSession(sessionId, @"C:\a.exe"));

        var session = _manager.GetHistory().First(s => s.SessionId == sessionId);
        Assert.Single(session.Threats);
        Assert.Equal(1, session.ThreatsFound);
        Assert.DoesNotContain(session.Threats, t => t.FilePath == @"C:\a.exe");
    }

    [Fact]
    public void WriteToLog_and_ReadLastLogLines_roundtrip()
    {
        _manager.WriteToLog("ligne de test optiCombat");
        var lines = _manager.ReadLastLogLines(10);
        Assert.Contains(lines, l => l.Contains("ligne de test optiCombat", StringComparison.Ordinal));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void History_persisted_as_encrypted_dat_not_plaintext_json()
    {
        _manager.SaveScanResult(new ScanResult
        {
            Type = ScanType.QuickScan, TargetPath = @"C:\secret\folder", Status = ScanStatus.Completed, FilesScanned = 10,
            Threats = { ThreatInfo.FromClamAv(@"C:\secret\malware.exe", "Evil.Trojan", 512) }
        });

        var datPath = Path.Combine(_logDir, "scan_history.dat");
        var jsonPath = Path.Combine(_logDir, "scan_history.json");

        Assert.True(File.Exists(datPath), "scan_history.dat devrait exister");
        Assert.False(File.Exists(jsonPath), "scan_history.json ne doit plus etre cree");

        var raw = File.ReadAllText(datPath);
        Assert.DoesNotContain(@"C:\secret", raw, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Evil.Trojan", raw, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void History_survives_reload_after_encryption()
    {
        var sessionId = Guid.NewGuid();
        _manager.SaveScanResult(new ScanResult
        {
            SessionId = sessionId, Type = ScanType.QuickScan, TargetPath = @"C:\test",
            Status = ScanStatus.Completed, FilesScanned = 42,
            Threats = { ThreatInfo.FromClamAv(@"C:\test\bad.exe", "Test.Malware", 100) }
        });

        var reloaded = new ScanLogManager(_logDir);
        var history = reloaded.GetHistory();

        Assert.Single(history);
        Assert.Equal(sessionId, history[0].SessionId);
        Assert.Equal(42, history[0].FilesScanned);
        Assert.Single(history[0].Threats);
        Assert.Equal(@"C:\test\bad.exe", history[0].Threats[0].FilePath);
        Assert.Equal("Test.Malware", history[0].Threats[0].VirusName);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void History_migrates_legacy_plaintext_json_on_first_load()
    {
        var legacySessions = new List<ScanSession>
        {
            new ScanSession
            {
                SessionId = Guid.NewGuid(), StartedAt = DateTime.Now.AddDays(-1),
                FinishedAt = DateTime.Now.AddDays(-1).AddMinutes(5),
                TargetPath = @"C:\Users\Bob\Documents", FilesScanned = 500, ThreatsFound = 1,
                StatusDisplay = "Completed",
                Threats = { ThreatInfo.FromClamAv(@"C:\Users\Bob\Documents\bad.doc", "Doc.Macro", 2048) }
            }
        };

        var jsonPath = Path.Combine(_logDir, "scan_history.json");
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(legacySessions));

        var mgr = new ScanLogManager(_logDir);
        var history = mgr.GetHistory();

        Assert.Single(history);
        Assert.Equal(@"C:\Users\Bob\Documents", history[0].TargetPath);
        Assert.Equal(@"C:\Users\Bob\Documents\bad.doc", history[0].Threats[0].FilePath);

        Assert.False(File.Exists(jsonPath), "scan_history.json devrait etre renomme en .legacy");
        Assert.True(File.Exists(jsonPath + ".legacy"), "scan_history.json.legacy devrait exister");
        Assert.True(File.Exists(Path.Combine(_logDir, "scan_history.dat")));
    }
}
