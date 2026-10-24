using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

[Collection("OpticombatPrefs")]
public sealed class WatchdogAndPostureTests : IDisposable
{
    private readonly IsolatedServices _env = new();

    public void Dispose() => _env.Dispose();

    [Fact]
    public async Task Posture_fix_enables_signature_auto_update()
    {
        var r = await PostureFixService.FixAsync("sigauto", _env.Container, (_, _) => true);
        Assert.Equal(PostureFixStatus.Done, r.Status);
        Assert.True(_env.Prefs.SignatureAutoUpdateEnabled);
        Assert.True(_env.Container.FreshclamUpdater.IsAutoUpdateEnabled);
        Assert.True(_env.Container.ThreatIntelUpdater.IsAutoUpdateEnabled);
        _env.Container.ApplySignatureAutoUpdate(false);
    }

    [Fact]
    public void Watchdog_check_returns_early_or_relaunches_without_throwing()
    {
        var excl = ExclusionSettings.Current;
        var prefs = UserPreferences.Current;
        var (rtp, tamper, platform) = (excl.RealTimeEnabled, prefs.TamperProtectionEnabled, prefs.UsePlatformProtectionService);
        try
        {
            excl.RealTimeEnabled = false;
            TamperProtectionService.RunWatchdogCheck(); // RTP coupée : rien à faire

            excl.RealTimeEnabled = true;
            prefs.TamperProtectionEnabled = true;
            prefs.UsePlatformProtectionService = false;
            // Aucune instance (pas de mutex) : tentative de relance de optiCombat.exe, absent du
            // dossier de test → échec journalisé, jamais d'exception.
            TamperProtectionService.RunWatchdogCheck();
        }
        finally
        {
            excl.RealTimeEnabled = rtp;
            prefs.TamperProtectionEnabled = tamper;
            prefs.UsePlatformProtectionService = platform;
        }
    }
}

public sealed class RealTimeEdgeCaseTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "oc_rtpe_" + Guid.NewGuid().ToString("N"));
    private readonly string _watch;
    private readonly ScriptedClamBackend _clam = new();
    private readonly ExclusionSettings _excl = new();
    private readonly RealTimeProtection _rtp;

    public RealTimeEdgeCaseTests()
    {
        _watch = Path.Combine(_root, "w");
        Directory.CreateDirectory(_watch);
        var prefs = new FixedPreferencesAccessor(new UserPreferences { ActionNotificationsEnabled = false });
        var excl = new FixedExclusionsAccessor(_excl);
        var orch = new ScanOrchestrator(_clam, new NoopYaraBackend(), prefs, excl, optiCombat: null);
        _rtp = new RealTimeProtection(new ProtectionScanGateway(orch, prefs),
            new QuarantineManager(Path.Combine(_root, "q"), prefs), new NotificationService(prefs), prefs, excl)
        {
            WatchFoldersOverride = () => new[] { _watch },
        };
    }

    public void Dispose()
    {
        _rtp.Dispose();
        try { Directory.Delete(_root, true); } catch { }
    }

    [Fact]
    public async Task Individually_excluded_file_is_not_scanned()
    {
        var file = Path.Combine(_watch, "trusted.exe");
        _excl.ExcludedFilePaths.Add(file);
        _clam.ThreatsByPath[file] = "Never";
        var detected = 0;
        _rtp.ThreatDetected += (_, _) => Interlocked.Increment(ref detected);
        _rtp.Start();

        await File.WriteAllTextAsync(file, "MZ");
        await Task.Delay(1500);

        Assert.Equal(0, Volatile.Read(ref detected));
    }

    [Fact]
    public async Task Repeated_rename_within_thirty_seconds_is_scanned_once()
    {
        var a = Path.Combine(_watch, "a.txt");
        var b = Path.Combine(_watch, "b.ps1");
        _clam.ThreatsByPath[b] = "PS.Test";
        var detected = 0;
        _rtp.ThreatDetected += (_, _) => Interlocked.Increment(ref detected);
        _rtp.Start();

        await File.WriteAllTextAsync(a, "x");
        File.Move(a, b);
        await Eventually.TrueAsync(() => Volatile.Read(ref detected) == 1, 10_000);
        File.Move(b, a);
        File.Move(a, b);
        await Task.Delay(1500);
        Assert.Equal(1, Volatile.Read(ref detected));
    }
}
