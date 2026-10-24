using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary>Démarrage de processus simulé (sans WMI) : image, scripts en argument, anti-rafale, quarantaine.</summary>
[Collection("OpticombatPrefs")]
public sealed class ProcessStartMonitorFlowTests : IDisposable
{
    private readonly IsolatedServices _iso = new();
    private readonly ProcessStartMonitor _monitor;

    public ProcessStartMonitorFlowTests()
    {
        _monitor = _iso.Container.ProcessStartMonitor;
        _monitor.SettleDelay = TimeSpan.Zero;
    }

    public void Dispose() => _iso.Dispose();

    [Fact]
    public async Task Launched_executable_is_scanned_and_auto_quarantined_once()
    {
        var exe = _iso.CreateFile("dropper.exe");
        _iso.Clam.ThreatsByPath[exe] = "Win.Dropper.Test";
        _iso.Exclusions.AutoQuarantineEnabled = true;
        _iso.Prefs.BackupBeforeQuarantine = true;
        _monitor.ImagePathProbe = _ => exe;
        var detected = new List<string>();
        _monitor.ThreatDetected += (_, t) => detected.Add(t.VirusName);

        await _monitor.OnProcessStarted("dropper.exe", 4242, null);

        Assert.Equal(["Win.Dropper.Test"], detected);
        Assert.False(File.Exists(exe));
        Assert.Equal(1, _iso.Container.Quarantine.Count);
        // Une seule copie de sécurité (QuarantineManager) — il y en avait deux.
        Assert.Single(Directory.GetFiles(ThreatRemediationService.BackupRoot));
    }

    [Fact]
    public async Task Script_host_arguments_are_scanned_quoted_or_not()
    {
        var quoted = _iso.CreateFile("payload one.ps1");
        var bare = _iso.CreateFile("second.vbs");
        _monitor.ImagePathProbe = _ => null;

        await _monitor.OnProcessStarted("powershell.exe", 1, $"powershell -File \"{quoted}\" {bare} -NoProfile");

        Assert.Equal(2, _iso.Clam.Calls);
    }

    [Fact]
    public async Task Non_script_hosts_ignore_their_command_line()
    {
        var script = _iso.CreateFile("x.ps1");
        _monitor.ImagePathProbe = _ => null;

        await _monitor.OnProcessStarted("notepad.exe", 1, $"notepad \"{script}\"");

        Assert.Equal(0, _iso.Clam.Calls);
    }

    [Fact]
    public async Task Same_file_is_not_rescanned_within_the_burst_window()
    {
        var exe = _iso.CreateFile("tool.exe");
        _monitor.ImagePathProbe = _ => exe;

        await _monitor.OnProcessStarted("tool.exe", 1, null);
        await _monitor.OnProcessStarted("tool.exe", 2, null);

        Assert.Equal(1, _iso.Clam.Calls);
    }

    [Fact]
    public async Task Excluded_missing_or_suspended_cases_do_not_scan()
    {
        var exe = _iso.CreateFile("excluded.exe");
        _iso.Exclusions.ExcludedFilePaths.Add(exe);
        _monitor.ImagePathProbe = _ => exe;
        await _monitor.OnProcessStarted("excluded.exe", 1, null);

        _monitor.ImagePathProbe = _ => Path.Combine(_iso.Root, "absent.exe");
        await _monitor.OnProcessStarted("absent.exe", 2, null);
        await _monitor.OnProcessStarted(null, 3, null);
        await _monitor.OnProcessStarted(" ", 4, null);

        Assert.Equal(0, _iso.Clam.Calls);
    }

    [Fact]
    public async Task Scan_failure_is_logged_and_does_not_escape()
    {
        var exe = _iso.CreateFile("crash.exe");
        _iso.Clam.ThrowOnScan = new IOException("moteur arrêté");
        _monitor.ImagePathProbe = _ => exe;

        await _monitor.OnProcessStarted("crash.exe", 1, null);
    }
}
