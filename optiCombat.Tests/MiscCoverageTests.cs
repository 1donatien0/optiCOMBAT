using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Services.OptiCombat;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

public sealed class NativeDllProbeTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "oc_probe_" + Guid.NewGuid().ToString("N"));

    public NativeDllProbeTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    [Fact]
    public void Missing_dll_is_reported()
    {
        Assert.False(OptiCombatScanEngine.ValidateNativeDllPath(_dir, out var reason));
        Assert.Contains("opticombat_engine.dll", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Copy_of_the_managed_assembly_is_rejected()
    {
        File.WriteAllText(Path.Combine(_dir, "optiCombat.dll"), "même contenu");
        File.WriteAllText(Path.Combine(_dir, "opticombat_engine.dll"), "même contenu");
        Assert.False(OptiCombatScanEngine.ValidateNativeDllPath(_dir, out var reason));
        Assert.Contains("invalide", reason, StringComparison.Ordinal);

        File.WriteAllText(Path.Combine(_dir, "opticombat_engine.dll"), "vrai moteur natif");
        Assert.True(OptiCombatScanEngine.ValidateNativeDllPath(_dir, out _));
    }

    [Fact]
    public async Task Version_probe_success_and_load_failure()
    {
        File.WriteAllText(Path.Combine(_dir, "opticombat_engine.dll"), "native");
        var ok = new OptiCombatScanEngine { NativeBaseDirectory = _dir, NativeVersion = () => "9.9.9" };
        Assert.True(ok.IsAvailable);
        Assert.Equal("optiCombat 9.9.9", await ok.GetVersionAsync());

        var blocked = new OptiCombatScanEngine
        {
            NativeBaseDirectory = _dir,
            NativeVersion = () => throw new FileLoadException("bloquée par la stratégie"),
        };
        Assert.False(blocked.IsAvailable);
        Assert.Contains("ClamAV", await blocked.GetVersionAsync(), StringComparison.Ordinal);
    }
}

[Collection("OpticombatPrefs")]
public sealed class LogsAndActivityTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "oc_logs_" + Guid.NewGuid().ToString("N"));

    public LogsAndActivityTests() => OpticombatDataRoots.TestRootOverride = _root;

    public void Dispose()
    {
        OpticombatDataRoots.TestRootOverride = TestDataRoot.Session;
        try { Directory.Delete(_root, true); } catch { }
    }

    private static ScanResult Result(string target, params ThreatInfo[] threats) => new()
    {
        SessionId = Guid.NewGuid(),
        Type = ScanType.Folder,
        TargetPath = target,
        Status = ScanStatus.Error,
        ErrorMessage = "disque retiré",
        FilesScanned = 3,
        FilesSkipped = 2,
        StartedAt = DateTime.Now.AddMinutes(-1),
        FinishedAt = DateTime.Now,
        Threats = threats.ToList(),
    };

    [Fact]
    public void Scan_detail_includes_skipped_and_error_then_history_can_be_cleared()
    {
        var logger = new ScanLogManager(Path.Combine(_root, "logs"));
        var result = Result("/cible", new ThreatInfo { FilePath = "/cible/a.exe", VirusName = "V" });
        logger.SaveScanResult(result);

        var fromResult = ScanLogManager.FormatScanDetail(result);
        var fromSession = ScanLogManager.FormatScanDetail(logger.GetHistory()[0]);
        Assert.Contains("disque retiré", fromResult, StringComparison.Ordinal);
        Assert.Contains("2", fromSession, StringComparison.Ordinal);
        Assert.False(logger.TryRemoveThreatFromSession(Guid.NewGuid(), "/x"));
        Assert.False(logger.TryRemoveThreatFromSession(result.SessionId, "/autre"));
        Assert.StartsWith(Path.Combine(_root, "logs"), logger.LogDirectory, StringComparison.Ordinal);
        Assert.EndsWith(".log", logger.TextLogPath, StringComparison.Ordinal);

        logger.ClearHistory();
        Assert.Empty(logger.GetHistory());
        Assert.Contains(logger.ReadLastLogLines(), l => l.Contains("Historique effacé", StringComparison.Ordinal));
    }

    [Fact]
    public void Activity_migration_includes_scans_cleanups_and_quarantine()
    {
        var logs = Path.Combine(_root, "logs");
        var logger = new ScanLogManager(logs);
        logger.SaveScanResult(Result("/s"));
        logger.SaveCleanSession(new CleanSession
        {
            StartedAt = DateTime.Now.AddMinutes(-2),
            FinishedAt = DateTime.Now,
            TargetsSummary = "Temp",
            BytesFreed = 1024,
        });
        var q = new QuarantineManager(Path.Combine(_root, "q"), new FixedPreferencesAccessor(new UserPreferences()));
        var file = Path.Combine(_root, "evil.bin");
        File.WriteAllText(file, "x");
        Assert.True(q.Quarantine(new ThreatInfo { FilePath = file, VirusName = "Q", FileSize = 1 }));

        var activity = new ActivityLogService(logger, logs);
        activity.EnsureMigrated(q);
        activity.EnsureMigrated(q); // idempotent
        var feed = activity.GetActivityFeed(q);
        Assert.True(feed.Count >= 3, $"{feed.Count} événements");
    }

    [Fact]
    public void Runtime_report_flags_and_startup_log()
    {
        var report = RuntimeDependencies.Evaluate();
        _ = report.IsClamAvReady;
        _ = report.IsYaraReady;
        Assert.False(string.IsNullOrWhiteSpace(report.BuildSummaryLine()));
        Assert.False(string.IsNullOrWhiteSpace(report.BuildDetailedMessage()));
        RuntimeDependencies.LogReportIfIncomplete();

        var ready = new RuntimeDependencies.Report
        {
            Items = new[]
            {
                new RuntimeDependencies.DependencyStatus { Name = "ClamAV", IsReady = true },
                new RuntimeDependencies.DependencyStatus { Name = "YARA", IsReady = true },
            },
        };
        Assert.True(ready.IsFullyReady && ready.IsClamAvReady && ready.IsYaraReady);
        Assert.False(string.IsNullOrWhiteSpace(ready.BuildSummaryLine()));
    }
}

public sealed class AutoUpdateTimerCallbackTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "oc_timer_" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_root, true); } catch { }
    }

    [Fact]
    public async Task Freshclam_timer_runs_an_update()
    {
        var bin = Path.Combine(_root, "clamav");
        Directory.CreateDirectory(Path.Combine(bin, "database"));
        var updater = new FreshclamUpdater(bin); // pas de freshclam.exe : succès silencieux
        var completed = 0;
        updater.UpdateCompleted += (_, _) => Interlocked.Increment(ref completed);

        updater.EnableAutoUpdate(TimeSpan.FromMilliseconds(150));
        try
        {
            await Eventually.TrueAsync(() => Volatile.Read(ref completed) > 0, 10_000);
        }
        finally
        {
            updater.DisableAutoUpdate();
        }
    }

    [Fact]
    public async Task YaraForge_timer_runs_an_update_against_a_fake_server()
    {
        var http = new FakeHttpHandler(); // 503 partout : la mise à jour échoue proprement
        var updater = new YaraForgeUpdater(Path.Combine(_root, "rules"), new System.Net.Http.HttpClient(http));
        updater.EnableAutoUpdate(TimeSpan.FromMilliseconds(150));
        try
        {
            await Eventually.TrueAsync(() => http.Requests.Count > 0, 10_000);
        }
        finally
        {
            updater.DisableAutoUpdate();
        }
    }
}
