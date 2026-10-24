using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary>Événements réels du <see cref="FileSystemWatcher"/> sur un dossier temporaire.</summary>
public sealed class RealTimeWatcherTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "oc_rtpw_" + Guid.NewGuid().ToString("N"));
    private readonly string _watch;
    private readonly ScriptedClamBackend _clam = new();
    private readonly ExclusionSettings _excl = new() { AutoQuarantineEnabled = false };
    private readonly UserPreferences _prefs = new() { ActionNotificationsEnabled = false };
    private readonly RealTimeProtection _rtp;
    private readonly QuarantineManager _quarantine;

    public RealTimeWatcherTests()
    {
        _watch = Path.Combine(_root, "watch");
        Directory.CreateDirectory(_watch);
        var prefs = new FixedPreferencesAccessor(_prefs);
        var excl = new FixedExclusionsAccessor(_excl);
        var orchestrator = new ScanOrchestrator(_clam, new NoopYaraBackend(), prefs, excl, optiCombat: null);
        _quarantine = new QuarantineManager(Path.Combine(_root, "q"), prefs);
        _rtp = new RealTimeProtection(
            new ProtectionScanGateway(orchestrator, prefs), _quarantine, new NotificationService(prefs), prefs, excl)
        {
            WatchFoldersOverride = () => new[] { _watch },
        };
    }

    public void Dispose()
    {
        _rtp.Dispose();
        try { Directory.Delete(_root, true); } catch { }
    }

    private readonly List<ThreatInfo> _detected = new();

    private void Track() => _rtp.ThreatDetected += (_, t) => { lock (_detected) _detected.Add(t); };

    private int Detected
    {
        get { lock (_detected) return _detected.Count; }
    }

    [Fact]
    public async Task New_risky_file_is_scanned_and_reported()
    {
        Track();
        _rtp.Start();
        var file = Path.Combine(_watch, "payload.exe");
        _clam.ThreatsByPath[file] = "Win.Test.Rtp";
        await File.WriteAllTextAsync(file, "MZ-fake");

        await Eventually.TrueAsync(() => Detected == 1, 10_000);
        lock (_detected)
            Assert.Equal("Win.Test.Rtp", _detected[0].VirusName);
        Assert.True(File.Exists(file), "pas de quarantaine automatique");
    }

    [Fact]
    public async Task Renamed_to_risky_extension_is_scanned_and_auto_quarantined()
    {
        _excl.AutoQuarantineEnabled = true;
        Track();
        _rtp.Start();
        var txt = Path.Combine(_watch, "notes.txt");
        var ps1 = Path.Combine(_watch, "notes.ps1");
        _clam.ThreatsByPath[ps1] = "PS.Test";
        await File.WriteAllTextAsync(txt, "Invoke-Expression");
        await Task.Delay(200);
        File.Move(txt, ps1);

        await Eventually.TrueAsync(() => Detected >= 1, 10_000);
        await Eventually.TrueAsync(() => !File.Exists(ps1), 10_000);
        Assert.NotEmpty(_quarantine.GetEntries());
    }

    [Fact]
    public async Task Suspended_or_non_risky_files_are_ignored()
    {
        Track();
        _rtp.Start();
        var txt = Path.Combine(_watch, "readme.txt");
        _clam.ThreatsByPath[txt] = "Never";
        await File.WriteAllTextAsync(txt, "texte");

        _rtp.Suspend();
        var exe = Path.Combine(_watch, "paused.exe");
        _clam.ThreatsByPath[exe] = "Never";
        await File.WriteAllTextAsync(exe, "MZ");
        await Task.Delay(1500);
        _rtp.Resume();

        Assert.Equal(0, Detected);
        Assert.Equal(0, _clam.Calls);
    }

    [Fact]
    public async Task Same_file_is_not_rescanned_within_thirty_seconds()
    {
        Track();
        _rtp.Start();
        var file = Path.Combine(_watch, "twice.bat");
        _clam.ThreatsByPath[file] = "Bat.Test";
        await File.WriteAllTextAsync(file, "echo 1");
        await Eventually.TrueAsync(() => Detected == 1, 10_000);

        await File.AppendAllTextAsync(file, "echo 2");
        await Task.Delay(1500);
        Assert.Equal(1, Detected);
    }

    [Fact]
    public async Task Excluded_folder_is_not_watched_and_excluded_file_is_skipped()
    {
        _excl.ExcludedFolders.Add(_watch);
        Track();
        _rtp.Start();
        var file = Path.Combine(_watch, "skip.exe");
        _clam.ThreatsByPath[file] = "Never";
        await File.WriteAllTextAsync(file, "MZ");
        await Task.Delay(1500);
        Assert.Equal(0, Detected);
        _rtp.Stop();
        Assert.False(_rtp.IsEnabled);
    }

    [Fact]
    public async Task Deleted_before_stabilization_is_ignored_and_missing_folder_is_tolerated()
    {
        _rtp.WatchFoldersOverride = () => new[] { _watch, Path.Combine(_root, "absent") };
        Track();
        _rtp.Start();
        var file = Path.Combine(_watch, "flash.exe");
        _clam.ThreatsByPath[file] = "Never";
        await File.WriteAllTextAsync(file, "MZ");
        File.Delete(file);
        await Task.Delay(1500);
        Assert.Equal(0, Detected);
    }
}
