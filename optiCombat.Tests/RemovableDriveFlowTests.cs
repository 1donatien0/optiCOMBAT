using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary>
/// Parcours complet d'un lecteur amovible simulé (un dossier temporaire) : éligibilité, scan rapide
/// ou complet, quarantaine automatique, évènements — sans WMI ni vrai lecteur.
/// </summary>
[Collection("OpticombatPrefs")]
public sealed class RemovableDriveFlowTests : IDisposable
{
    private readonly IsolatedServices _iso = new();
    private readonly RemovableDriveScanService _usb;
    private readonly string _drive;

    public RemovableDriveFlowTests()
    {
        _usb = _iso.Container.RemovableDriveScan;
        _usb.MountSettleDelayMilliseconds = 0;
        _usb.DriveSizeProbe = _ => 8L * 1024 * 1024 * 1024;
        _iso.Prefs.RemovableDriveScanEnabled = true;
        _iso.Prefs.RemovableDriveMaxSizeGb = 64;
        _drive = Path.Combine(_iso.Root, "usb");
        Directory.CreateDirectory(_drive);
    }

    public void Dispose() => _iso.Dispose();

    private string Put(string name, string content = "MZ fake")
    {
        var path = Path.Combine(_drive, name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    private List<RemovableDriveScanStatusEventArgs> Track()
    {
        var events = new List<RemovableDriveScanStatusEventArgs>();
        _usb.ScanStatusChanged += (_, e) => { lock (events) events.Add(e); };
        return events;
    }

    [Fact]
    public async Task Quick_scan_finds_and_auto_quarantines_a_risky_file()
    {
        var bad = Put("autorun.exe");
        Put("photo.jpg", "jpeg");
        _iso.Clam.ThreatsByPath[bad] = "Win.Worm.Usb";
        _iso.Exclusions.AutoQuarantineEnabled = true;
        var events = Track();
        var detected = new List<string>();
        _usb.ThreatDetected += (_, t) => detected.Add(t.VirusName);

        await _usb.ScanRootIfEligibleAsync(_drive);

        Assert.False(File.Exists(bad));
        Assert.Equal(1, _iso.Container.Quarantine.Count);
        Assert.Equal(["Win.Worm.Usb"], detected);
        Assert.Equal([RemovableDriveScanPhase.Started, RemovableDriveScanPhase.Completed], events.Select(e => e.Phase));
        Assert.Equal(1, events[^1].ThreatsFound);
    }

    [Fact]
    public async Task Detailed_mode_scans_the_whole_drive_without_quarantine_when_disabled()
    {
        var bad = Put(Path.Combine("docs", "rapport.pdf"));
        _iso.Clam.ThreatsByPath[bad] = "Pdf.Exploit.Test";
        _iso.Prefs.RemovableDriveScanDetailed = true;
        _iso.Exclusions.AutoQuarantineEnabled = false;
        var events = Track();

        await _usb.ScanRootIfEligibleAsync(_drive);

        Assert.True(File.Exists(bad));
        Assert.Equal(0, _iso.Container.Quarantine.Count);
        Assert.Equal(1, events[^1].ThreatsFound);
    }

    [Fact]
    public async Task Drive_without_risky_files_completes_with_nothing_scanned()
    {
        Put("musique.mp3", "id3");
        var events = Track();

        await _usb.ScanRootIfEligibleAsync(_drive);

        Assert.Equal(0, _iso.Clam.Calls);
        Assert.Equal(RemovableDriveScanPhase.Completed, events[^1].Phase);
        Assert.Equal(0, events[^1].FilesScanned);
    }

    [Fact]
    public async Task Engine_failure_reports_a_failed_scan()
    {
        Put("setup.exe");
        _iso.Clam.ThrowOnScan = new IOException("lecteur retiré");
        var events = Track();

        await _usb.ScanRootIfEligibleAsync(_drive);

        Assert.Equal(RemovableDriveScanPhase.Failed, events[^1].Phase);
    }

    [Fact]
    public async Task Ineligible_drives_are_not_scanned()
    {
        Put("setup.exe");
        var events = Track();

        _usb.DriveSizeProbe = _ => null; // pas prêt / pas amovible
        await _usb.ScanRootIfEligibleAsync(_drive);

        _usb.DriveSizeProbe = _ => 2L * 1024 * 1024 * 1024 * 1024; // 2 To > limite
        await _usb.ScanRootIfEligibleAsync(_drive);

        _usb.DriveSizeProbe = _ => 1024;
        _iso.Exclusions.ExcludedFolders.Add(_drive);
        await _usb.ScanRootIfEligibleAsync(_drive);

        _iso.Exclusions.ExcludedFolders.Clear();
        _iso.Prefs.RemovableDriveScanEnabled = false;
        await _usb.ScanRootIfEligibleAsync(_drive);

        Assert.Empty(events);
        Assert.Equal(0, _iso.Clam.Calls);
    }

    [Fact]
    public async Task A_new_drive_is_claimed_once_even_when_poll_and_wmi_race()
    {
        Put("setup.exe");
        var events = Track();
        _usb.NewRootsProbe = known => known.Contains(_drive) ? [] : [_drive];

        await Task.WhenAll(
            _usb.ScheduleScanNewDrivesAsync(),
            _usb.HandleVolumeEvent(2, null),
            _usb.ScheduleScanNewDrivesAsync());

        Assert.Single(events, e => e.Phase == RemovableDriveScanPhase.Started);
    }

    [Fact]
    public async Task Removed_drive_is_forgotten_and_rescanned_when_plugged_back()
    {
        Put("setup.exe");
        var events = Track();
        _usb.NewRootsProbe = known => known.Contains(_drive) ? [] : [_drive];
        await _usb.ScheduleScanNewDrivesAsync();

        // Lettre de lecteur factice : le retrait ne touche que l'entrée correspondante.
        await _usb.HandleVolumeEvent(3, "Z:");
        await _usb.ScheduleScanNewDrivesAsync();
        Assert.Single(events, e => e.Phase == RemovableDriveScanPhase.Started);

        await _usb.HandleVolumeEvent(99, null); // évènement ignoré
        Assert.Single(events, e => e.Phase == RemovableDriveScanPhase.Started);
    }

    [Fact]
    public async Task Disabled_scanning_ignores_new_drives()
    {
        _iso.Prefs.RemovableDriveScanEnabled = false;
        var probed = false;
        _usb.NewRootsProbe = _ => { probed = true; return [_drive]; };

        await _usb.ScheduleScanNewDrivesAsync();

        Assert.False(probed);
    }
}
