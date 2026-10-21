using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.Tests;

[Collection("OpticombatPrefs")]
public sealed class AntivirusViewModelTests : IDisposable
{
    private readonly IsolatedServices _env = new();
    private readonly RecordingConfirmService _confirm = new();

    public void Dispose() => _env.Dispose();

    private async Task<AntivirusViewModel> CreateAsync()
    {
        var vm = new AntivirusViewModel(_env.Container) { Confirm = _confirm };
        await Eventually.TrueAsync(() => !vm.IsInitializing, 15000);
        return vm;
    }

    private string SampleFolderWithThreat(out string threatPath)
    {
        threatPath = _env.CreateFile("bad.exe");
        _env.CreateFile("clean.txt", "hello");
        _env.Clam.ThreatsByPath[threatPath] = "Win.Test.Fake";
        return Path.GetDirectoryName(threatPath)!;
    }

    [Fact]
    public async Task Initialization_loads_empty_state()
    {
        var vm = await CreateAsync();

        Assert.False(vm.IsScanning);
        Assert.True(vm.CanScan);
        Assert.False(vm.CanStop);
        Assert.Equal(Guid.Empty, vm.ActiveScanSessionId);
        Assert.Equal(LocalizationService.GetString("Av_NoScanYet"), vm.LastScanDisplay);
        Assert.Equal(0, vm.QuarantineCount);
        Assert.Equal(0, vm.QuarantineTotalCount);
        Assert.False(vm.QuarantineHasMore);
        Assert.Equal(string.Empty, vm.QuarantinePagingStatus);
        Assert.False(string.IsNullOrWhiteSpace(vm.ProtectionBadgeText));
        Assert.Empty(vm.RecentTargets);
        Assert.False(vm.ShowUpdateProgress);
    }

    [Fact]
    public async Task ScanFolder_collects_threats_saves_history_and_recent_target()
    {
        var vm = await CreateAsync();
        var folder = SampleFolderWithThreat(out var threat);
        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        await vm.ScanFolderAsync(folder);

        Assert.False(vm.IsScanning);
        var single = Assert.Single(vm.Threats);
        Assert.Equal(threat, single.FilePath, ignoreCase: true);
        Assert.Equal(1, vm.ThreatsFound);
        Assert.Equal(2, vm.FilesScanned);
        Assert.Contains(nameof(vm.IsScanning), changed);
        Assert.Contains(nameof(vm.CanScan), changed);
        Assert.NotEqual(LocalizationService.GetString("Av_NoScanYet"), vm.LastScanDisplay);
        Assert.Single(_env.Container.Logger.GetHistory());
        Assert.Contains(vm.RecentTargets, t => t.ScanType == ScanType.Folder && t.Path == folder);
        Assert.Equal(ScanType.Folder, _env.Prefs.FavoriteScanType);
    }

    [Fact]
    public async Task ScanFile_with_auto_quarantine_moves_threat_to_quarantine()
    {
        _env.Exclusions.AutoQuarantineEnabled = true;
        var vm = await CreateAsync();
        var threat = _env.CreateFile("auto.exe");
        _env.Clam.ThreatsByPath[threat] = "Win.Test.Auto";

        await vm.ScanFileAsync(threat);

        Assert.Equal(1, vm.QuarantineCount);
        Assert.Single(vm.QuarantineEntries);
        Assert.False(File.Exists(threat));
    }

    [Fact]
    public async Task Scan_error_is_reported_in_status_message()
    {
        _env.Clam.ThrowOnScan = new InvalidOperationException("moteur KO");
        var vm = await CreateAsync();

        await vm.ScanFileAsync(_env.CreateFile("x.bin"));

        Assert.False(vm.IsScanning);
        Assert.Contains("moteur KO", vm.StatusMessage);
    }

    [Fact]
    public async Task StopScan_cancels_running_scan()
    {
        _env.Clam.WaitForCancellation = true;
        var vm = await CreateAsync();

        var scan = vm.ScanFileAsync(_env.CreateFile("slow.bin"));
        await Eventually.TrueAsync(() => vm.IsScanning);
        Assert.NotEqual(Guid.Empty, vm.ActiveScanSessionId);
        Assert.True(vm.CanStop);

        // Un second lancement pendant l'analyse est ignoré.
        await vm.QuickScanAsync().WaitAsync(TimeSpan.FromSeconds(5));

        vm.StopScan();
        await scan.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.False(vm.IsScanning);
        Assert.Equal(1, _env.Clam.Calls);
    }

    [Fact]
    public async Task Context_menu_scan_rejects_invalid_path()
    {
        var vm = await CreateAsync();
        var missing = Path.Combine(_env.Root, "missing", "nothing.exe");

        await vm.RequestContextMenuScanAsync(missing);

        Assert.Equal(LocalizationService.Format("ShellScan_InvalidPath", missing), vm.StatusMessage);
        Assert.Equal(0, _env.Clam.Calls);
    }

    [Fact]
    public async Task Context_menu_scan_of_existing_file_runs_a_scan()
    {
        var vm = await CreateAsync();

        await vm.RequestContextMenuScanAsync(_env.CreateFile("menu.txt"));

        Assert.Equal(1, _env.Clam.Calls);
    }

    [Fact]
    public async Task ScanRecent_replays_folder_target_and_ignores_null()
    {
        var vm = await CreateAsync();
        var folder = SampleFolderWithThreat(out _);

        await vm.ScanRecentAsync(null);
        Assert.Equal(0, _env.Clam.Calls);

        await vm.ScanRecentAsync(new RecentScanTarget { Path = folder, ScanType = ScanType.Folder });
        Assert.Equal(1, _env.Clam.Calls);
        Assert.Single(vm.Threats);
    }

    [Fact]
    public async Task LoadThreatsFromHistorySession_fills_threat_list()
    {
        var vm = await CreateAsync();
        var path = _env.CreateFile("hist.exe");
        var session = new ScanSession { StartedAt = DateTime.Now.AddHours(-1) };
        session.Threats.Add(ThreatInfo.FromClamAv(path, "Win.Hist", 3));

        vm.LoadThreatsFromHistorySession(session);

        Assert.Single(vm.Threats);
        Assert.Equal(1, vm.ThreatsFound);
        Assert.NotEqual(LocalizationService.GetString("Scan_Ready"), vm.StatusMessage);

        vm.LoadThreatsFromHistorySession(new ScanSession());
        Assert.Empty(vm.Threats);
        Assert.Equal(LocalizationService.GetString("Scan_Ready"), vm.StatusMessage);
    }

    [Fact]
    public async Task RemoveDetectedThreat_ignores_blank_and_unknown_paths()
    {
        var vm = await CreateAsync();
        var path = _env.CreateFile("keep.exe");
        var session = new ScanSession();
        session.Threats.Add(ThreatInfo.FromClamAv(path, "Win.Keep", 1));
        vm.LoadThreatsFromHistorySession(session);

        vm.RemoveDetectedThreat(null);
        vm.RemoveDetectedThreat("   ");
        vm.RemoveDetectedThreat(Path.Combine(_env.Root, "other.exe"));
        Assert.Single(vm.Threats);

        vm.RemoveDetectedThreat(path.ToUpperInvariant());
        Assert.Empty(vm.Threats);
        Assert.Equal(0, vm.ThreatsFound);
    }

    [Fact]
    public async Task QuarantineThreat_removes_row_and_refreshes_quarantine()
    {
        var vm = await CreateAsync();
        var path = _env.CreateFile("q.exe");
        var session = new ScanSession();
        session.Threats.Add(ThreatInfo.FromClamAv(path, "Win.Q", 4));
        vm.LoadThreatsFromHistorySession(session);
        var refreshed = 0;
        _env.Container.ScanHistoryViewsRefreshRequested += (_, _) => refreshed++;

        vm.QuarantineThreat(null);
        vm.QuarantineThreat(path);

        Assert.Empty(vm.Threats);
        Assert.Equal(1, vm.QuarantineCount);
        Assert.Equal(1, refreshed);
        Assert.Equal(LocalizationService.Format("Vm_QuarantineAllShown", 1), vm.QuarantinePagingStatus);
    }

    [Fact]
    public async Task IgnoreThreat_excludes_file_and_removes_row()
    {
        var vm = await CreateAsync();
        var path = _env.CreateFile("ignore.exe");
        var session = new ScanSession();
        session.Threats.Add(ThreatInfo.FromClamAv(path, "Win.Ign", 1));
        vm.LoadThreatsFromHistorySession(session);

        vm.IgnoreThreat("");
        vm.IgnoreThreat(path);

        Assert.Empty(vm.Threats);
        Assert.True(_env.Exclusions.IsFileExcluded(path));
    }

    [Fact]
    public async Task DeleteThreat_requires_confirmation()
    {
        var vm = await CreateAsync();
        var path = _env.CreateFile("del.exe");
        var session = new ScanSession();
        session.Threats.Add(ThreatInfo.FromClamAv(path, "Win.Del", 1));
        vm.LoadThreatsFromHistorySession(session);

        _confirm.Answer = false;
        vm.DeleteThreat(path);
        Assert.True(File.Exists(path));
        Assert.Single(vm.Threats);
        Assert.True(Assert.Single(_confirm.Questions).Warning);

        _confirm.Answer = true;
        vm.DeleteThreat(path);
        Assert.False(File.Exists(path));
        Assert.Empty(vm.Threats);

        vm.DeleteThreat(null);
        Assert.Equal(2, _confirm.Questions.Count);
    }

    [Fact]
    public async Task ShowReputation_without_api_key_warns_user()
    {
        var vm = await CreateAsync();

        await vm.ShowReputationAsync(null);
        Assert.Empty(_confirm.Warnings);

        await vm.ShowReputationAsync(_env.CreateFile("rep.exe"));

        Assert.Single(_confirm.Warnings);
        Assert.Empty(_confirm.Infos);
    }

    [Fact]
    public async Task QuarantineAll_then_restore_and_delete_entries()
    {
        var vm = await CreateAsync();
        var a = _env.CreateFile("a.exe");
        var b = _env.CreateFile("b.exe");
        var session = new ScanSession();
        session.Threats.Add(ThreatInfo.FromClamAv(a, "Win.A", 1));
        session.Threats.Add(ThreatInfo.FromClamAv(b, "Win.B", 1));
        vm.LoadThreatsFromHistorySession(session);

        vm.QuarantineAllThreats();

        Assert.Empty(vm.Threats);
        Assert.Equal(0, vm.ThreatsFound);
        Assert.Equal(2, vm.QuarantineCount);
        Assert.Equal(LocalizationService.Format("Vm_QuarantineBatch", 2), vm.StatusMessage);

        var restoreId = vm.QuarantineEntries.First(e => e.OriginalPath == a).Id;
        vm.RestoreQuarantineEntry(null);
        vm.RestoreQuarantineEntry(restoreId);
        Assert.True(File.Exists(a));
        Assert.Equal(1, vm.QuarantineCount);
        Assert.Equal(LocalizationService.GetString("Ui_RestoreOk"), vm.StatusMessage);

        var deleteId = vm.QuarantineEntries.Single().Id;
        _confirm.Answer = false;
        vm.DeleteQuarantineEntry(deleteId);
        Assert.Equal(1, vm.QuarantineCount);

        _confirm.Answer = true;
        vm.DeleteQuarantineEntry(deleteId);
        Assert.Equal(0, vm.QuarantineCount);
        Assert.Equal(LocalizationService.GetString("Vm_DeleteOk"), vm.StatusMessage);

        vm.DeleteQuarantineEntry(" ");
    }

    [Fact]
    public async Task QuarantineAll_without_threats_does_nothing()
    {
        var vm = await CreateAsync();
        vm.QuarantineAllThreats();
        Assert.Equal(0, vm.QuarantineCount);
    }

    [Fact]
    public async Task PurgeQuarantine_asks_then_empties()
    {
        var vm = await CreateAsync();
        vm.PurgeQuarantine();
        Assert.Empty(_confirm.Questions);

        _env.Container.Quarantine.Quarantine(ThreatInfo.FromClamAv(_env.CreateFile("p1.exe"), "Win.P", 1));
        _env.Container.Quarantine.Quarantine(ThreatInfo.FromClamAv(_env.CreateFile("p2.exe"), "Win.P", 1));
        vm.LoadQuarantine();
        Assert.Equal(2, vm.QuarantineCount);

        _confirm.Answer = false;
        vm.PurgeQuarantine();
        Assert.Equal(2, _env.Container.Quarantine.Count);

        _confirm.Answer = true;
        vm.PurgeQuarantine();
        Assert.Equal(0, vm.QuarantineCount);
        Assert.Equal(LocalizationService.Format("Vm_PurgeCount", 2), vm.StatusMessage);
    }

    [Fact]
    public async Task LoadMoreQuarantine_is_noop_when_everything_is_shown()
    {
        var vm = await CreateAsync();
        _env.Container.Quarantine.Quarantine(ThreatInfo.FromClamAv(_env.CreateFile("m.exe"), "Win.M", 1));
        vm.LoadQuarantine(reset: true);

        vm.LoadMoreQuarantine();

        Assert.Single(vm.QuarantineEntries);
        Assert.False(vm.QuarantineHasMore);
    }

    [Fact]
    public async Task StopSignatureUpdate_is_ignored_when_idle()
    {
        var vm = await CreateAsync();
        var before = vm.StatusMessage;

        vm.StopSignatureUpdate();

        Assert.Equal(before, vm.StatusMessage);
        Assert.False(vm.IsUpdating);
    }

    [Fact]
    public async Task Signature_properties_raise_change_notifications()
    {
        var vm = await CreateAsync();
        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        vm.YaraVersion = "y1";
        vm.YaraLastUpdate = "hier";
        vm.ClamVersion = "c1";
        vm.ClamLastUpdate = "aujourd'hui";
        await vm.RefreshSignaturesAsync(force: true);
        vm.RefreshRecentTargets();
        vm.RefreshLastScan();
        vm.RefreshProtectionBadge();

        Assert.Contains(nameof(vm.YaraVersion), changed);
        Assert.Contains(nameof(vm.YaraLastUpdate), changed);
        Assert.Contains(nameof(vm.ClamVersion), changed);
        Assert.Contains(nameof(vm.ClamLastUpdate), changed);
        Assert.Contains(nameof(vm.ProtectionBadgeLevel), changed);
        Assert.Equal(string.Empty, vm.SignatureLog);
    }
}
