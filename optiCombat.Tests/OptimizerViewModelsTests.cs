using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.Tests;

[Collection("Localization")]
public sealed class UpdatesViewModelTests
{
    private readonly FakeWinget _winget = new();
    private readonly RecordingConfirmService _confirm = new();

    public UpdatesViewModelTests() => LocalizationService.ApplyCulture("fr-FR");

    private UpdatesViewModel Create() => new(SyncUiThreadScheduler.Instance, _confirm, _winget);

    private static WingetPackageUpdate Pkg(string id) => new()
    {
        Id = id,
        Name = id + " App",
        InstalledVersion = "1.0",
        AvailableVersion = "2.0",
    };

    [Fact]
    public void Initial_state_shows_hint_and_allows_scan()
    {
        var vm = Create();

        Assert.Equal(LocalizationService.GetString("Upd_LogHint"), vm.LogText);
        Assert.True(vm.CanScan);
        Assert.False(vm.IsBusy);
        Assert.False(vm.CanUpdateSelected);
        Assert.False(vm.ShowEmptyState);
        Assert.True(vm.CanUpdateAll);
    }

    [Fact]
    public async Task Scan_without_winget_logs_missing_tool()
    {
        _winget.Path = null;
        var vm = Create();

        await vm.ScanAsync();

        Assert.Contains(LocalizationService.GetString("Upd_LogWingetMissing"), vm.LogText);
        Assert.False(vm.CanUpdateAll);
        Assert.Empty(vm.Rows);
    }

    [Fact]
    public async Task Scan_lists_updates_and_empty_state()
    {
        _winget.Updates.AddRange(new[] { Pkg("A"), Pkg("B") });
        var vm = Create();

        await vm.ScanAsync();

        Assert.Equal(2, vm.Rows.Count);
        Assert.True(vm.CanUpdateSelected);
        Assert.False(vm.ShowEmptyState);
        Assert.Contains(LocalizationService.Format("Upd_LogFound", 2), vm.LogText);

        _winget.Updates.Clear();
        await vm.ScanAsync();

        Assert.Empty(vm.Rows);
        Assert.True(vm.ShowEmptyState);
        Assert.Contains(LocalizationService.GetString("Upd_LogNone"), vm.LogText);
    }

    [Fact]
    public async Task Scan_failure_is_logged()
    {
        _winget.ThrowOnList = new InvalidOperationException("réseau");
        var vm = Create();

        await vm.ScanAsync();

        Assert.Contains("réseau", vm.LogText);
        Assert.False(vm.IsBusy);
    }

    [Fact]
    public async Task UpdateSelected_requires_checked_rows_and_confirmation()
    {
        _winget.Updates.Add(Pkg("A"));
        var vm = Create();
        await vm.ScanAsync();

        vm.Rows[0].IsSelected = false;
        await vm.UpdateSelectedAsync();
        Assert.Contains(LocalizationService.GetString("Upd_LogNoneChecked"), vm.LogText);
        Assert.Empty(_confirm.Questions);

        vm.Rows[0].IsSelected = true;
        _confirm.Answer = false;
        await vm.UpdateSelectedAsync();
        Assert.Single(_confirm.Questions);
        Assert.Equal(0, _winget.UpgradeCalls);
        Assert.False(vm.IsBusy);
    }

    [Fact]
    public async Task UpdateSelected_applies_each_result_to_its_row()
    {
        var ok = Pkg("Ok");
        var already = Pkg("Already");
        var reboot = Pkg("Reboot");
        var cancelled = Pkg("Cancel");
        var failed = Pkg("Fail");
        _winget.Updates.AddRange(new[] { ok, already, reboot, cancelled, failed });
        _winget.Statuses[ok.Id] = WingetUpgradeStatus.Succeeded;
        _winget.Statuses[already.Id] = WingetUpgradeStatus.AlreadyUpToDate;
        _winget.Statuses[reboot.Id] = WingetUpgradeStatus.RebootRequired;
        _winget.Statuses[cancelled.Id] = WingetUpgradeStatus.CancelledByUser;
        _winget.Statuses[failed.Id] = WingetUpgradeStatus.Failed;
        _confirm.Answer = true;
        var vm = Create();
        await vm.ScanAsync();

        // Comme sur le thread UI : les rapports Progress<T> sont sérialisés, jamais concurrents.
        var previous = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(new SerialSynchronizationContext());
        try
        {
            await vm.UpdateSelectedAsync();
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }
        await Eventually.TrueAsync(() => vm.Rows.Count == 3 && vm.Rows.All(r => !r.IsSelected));

        Assert.DoesNotContain(vm.Rows, r => r.Package == ok || r.Package == already);
        Assert.True(vm.Rows.Single(r => r.Package == reboot).IsWarning);
        Assert.True(vm.Rows.Single(r => r.Package == cancelled).IsWarning);
        var failedRow = vm.Rows.Single(r => r.Package == failed);
        Assert.True(failedRow.IsDanger);
        Assert.Equal($"[{LocalizationService.GetString("Upd_TagFailed")}]", failedRow.Tag);
        Assert.Contains("Real winget line", vm.LogText);
        Assert.DoesNotContain("█", vm.LogText);
    }

    [Fact]
    public async Task UpdateAll_declined_does_not_run_winget()
    {
        _confirm.Answer = false;
        var vm = Create();

        await vm.UpdateAllAsync();

        Assert.Equal(0, _winget.UpgradeAllCalls);
        Assert.Single(_confirm.Questions);
    }

    [Fact]
    public async Task UpdateAll_runs_then_rescans()
    {
        _winget.Updates.Add(Pkg("Left"));
        _confirm.Answer = true;
        var vm = Create();

        await vm.UpdateAllAsync();

        Assert.Equal(1, _winget.UpgradeAllCalls);
        Assert.Equal(1, _winget.ListCalls);
        Assert.Single(vm.Rows);
        Assert.Contains(LocalizationService.GetString("Upd_LogUpgradeAllDone"), vm.LogText);
        Assert.Contains(LocalizationService.GetString("Upd_LogRescan"), vm.LogText);
    }

    [Fact]
    public async Task UpdateAll_failure_is_logged_without_rescan()
    {
        _winget.ThrowOnUpgradeAll = new InvalidOperationException("winget planté");
        _confirm.Answer = true;
        var vm = Create();

        await vm.UpdateAllAsync();

        Assert.Contains("winget planté", vm.LogText);
        Assert.Equal(0, _winget.ListCalls);
    }

    [Fact]
    public void Attach_replaces_confirmation_service()
    {
        var vm = Create();
        var other = new RecordingConfirmService();
        vm.Attach(SyncUiThreadScheduler.Instance, other);
        Assert.NotNull(vm);
    }

    [Fact]
    public void UpdateRow_mark_and_reselect()
    {
        var row = new UpdateRowViewModel(Pkg("Row"));
        var changed = new List<string?>();
        row.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        Assert.Equal("Row App   1.0 → 2.0", row.Label);
        Assert.True(row.IsSelected);

        row.Mark("Échec", UpdateRowSeverity.Danger);
        Assert.False(row.IsSelected);
        Assert.Equal("[Échec]", row.Tag);
        Assert.True(row.IsDanger);
        Assert.False(row.IsWarning);

        row.IsSelected = true;
        Assert.Equal(string.Empty, row.Tag);
        Assert.Equal(UpdateRowSeverity.None, row.Severity);
        Assert.Contains(nameof(row.IsDanger), changed);

        changed.Clear();
        row.IsSelected = true;
        Assert.Empty(changed);
    }

    private sealed class FakeWinget : IWingetUpdateService
    {
        public string? Path { get; set; } = @"C:\fake\winget.exe";

        public List<WingetPackageUpdate> Updates { get; } = new();

        public Dictionary<string, WingetUpgradeStatus> Statuses { get; } = new();

        public Exception? ThrowOnList { get; set; }

        public Exception? ThrowOnUpgradeAll { get; set; }

        public int ListCalls { get; private set; }

        public int UpgradeCalls { get; private set; }

        public int UpgradeAllCalls { get; private set; }

        public string? ResolveWingetPath() => Path;

        public Task<IReadOnlyList<WingetPackageUpdate>> GetAvailableUpdatesAsync(CancellationToken cancellationToken = default)
        {
            ListCalls++;
            if (ThrowOnList != null)
                throw ThrowOnList;
            return Task.FromResult<IReadOnlyList<WingetPackageUpdate>>(Updates.ToList());
        }

        public Task<IReadOnlyList<WingetUpgradeResult>> UpgradePackagesAsync(
            IEnumerable<WingetPackageUpdate> packages,
            Action<string> onOutputLine,
            IProgress<WingetUpgradeResult>? onPackageCompleted = null,
            CancellationToken cancellationToken = default)
        {
            UpgradeCalls++;
            onOutputLine("██████▒▒▒▒");
            onOutputLine("-\\|/");
            onOutputLine("ok");
            onOutputLine("Real winget line");
            var results = new List<WingetUpgradeResult>();
            foreach (var p in packages)
            {
                var r = new WingetUpgradeResult
                {
                    Package = p,
                    Status = Statuses.GetValueOrDefault(p.Id, WingetUpgradeStatus.Succeeded),
                    ExitCode = Statuses.GetValueOrDefault(p.Id) == WingetUpgradeStatus.Failed ? 5 : 0,
                };
                results.Add(r);
                onPackageCompleted?.Report(r);
            }
            return Task.FromResult<IReadOnlyList<WingetUpgradeResult>>(results);
        }

        public Task<int> UpgradeAllAsync(
            Action<string> onOutputLine,
            IEnumerable<WingetPackageUpdate>? packagesToClean = null,
            CancellationToken cancellationToken = default)
        {
            UpgradeAllCalls++;
            if (ThrowOnUpgradeAll != null)
                throw ThrowOnUpgradeAll;
            onOutputLine("Upgrading all");
            return Task.FromResult(0);
        }
    }
}

[Collection("Localization")]
public sealed class TweaksViewModelTests
{
    private readonly RecordingConfirmService _confirm = new();

    public TweaksViewModelTests() => LocalizationService.ApplyCulture("fr-FR");

    private TweaksViewModel Create() => new(SyncUiThreadScheduler.Instance, _confirm);

    [Fact]
    public async Task Apply_without_selection_logs_hint()
    {
        var vm = Create();
        Assert.Equal(LocalizationService.GetString("Twk_LogHint"), vm.LogText);

        await vm.ApplyAsync();

        Assert.Contains(LocalizationService.GetString("Twk_LogNone"), vm.LogText);
        Assert.DoesNotContain(LocalizationService.GetString("Twk_LogHint"), vm.LogText);
        Assert.Empty(_confirm.Questions);
        Assert.True(vm.CanApply);
        Assert.False(vm.IsBusy);
    }

    [Fact]
    public async Task Apply_lists_every_selected_tweak_and_respects_refusal()
    {
        var vm = Create();
        vm.PowerPlan = vm.VisualFx = vm.Telemetry = vm.Ads = vm.Suggestions = vm.Tailored = true;
        vm.ShowExt = vm.ShowHidden = vm.TaskbarLeft = vm.HideWidgets = vm.SearchIcon = vm.ThisPc = true;
        vm.Dism = true;
        _confirm.Answer = false;

        await vm.ApplyAsync();

        var (message, _, warning) = Assert.Single(_confirm.Questions);
        Assert.False(warning);
        foreach (var key in new[]
                 {
                     "Twk_PowerPlan", "Twk_VisualFx", "Twk_Telemetry", "Twk_Ads", "Twk_Suggestions",
                     "Twk_Tailored", "Twk_ShowExt", "Twk_ShowHidden", "Twk_TaskbarLeft", "Twk_HideWidgets",
                     "Twk_SearchIcon", "Twk_ThisPC", "Twk_Dism",
                 })
        {
            Assert.Contains(LocalizationService.GetString(key), message);
        }
        Assert.Contains(LocalizationService.GetString("Twk_Cancelled"), vm.LogText);
    }

    [Fact]
    public async Task Refusal_is_not_a_warning()
    {
        var vm = Create();
        vm.ShowExt = true;

        await vm.ApplyAsync();

        Assert.False(Assert.Single(_confirm.Questions).Warning);
    }

    [Fact]
    public void Setting_same_value_does_not_raise_change()
    {
        var vm = Create();
        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        vm.Ads = true;
        vm.Ads = true;
        vm.Attach(SyncUiThreadScheduler.Instance, new RecordingConfirmService());

        Assert.Equal(new[] { nameof(vm.Ads) }, changed);
    }
}

[Collection("OpticombatPrefs")]
public sealed class CleanViewModelTests : IDisposable
{
    private readonly IsolatedServices _env = new();

    public void Dispose() => _env.Dispose();

    [Fact]
    public void Defaults_and_selection_snapshot()
    {
        var vm = new CleanViewModel(_env.Container);

        Assert.NotNull(vm.Updates);
        Assert.NotNull(vm.Tweaks);
        Assert.True(vm.CanAnalyze);
        Assert.False(vm.CanClean);
        Assert.False(vm.HasLog);

        vm.TempWin = false;
        vm.Logs = vm.Brave = vm.Opera = vm.Vivaldi = vm.Arc = vm.WUCache = vm.Dns = vm.History = true;
        var sel = vm.BuildSelection();

        Assert.False(sel.TempWin);
        Assert.True(sel.TempUser);
        Assert.True(sel.Logs && sel.Brave && sel.Opera && sel.Vivaldi && sel.Arc && sel.WUCache && sel.Dns && sel.History);
        Assert.True(sel.Edge && sel.Chrome && sel.Firefox && sel.Recycle);
    }

    [Fact]
    public async Task Analyze_without_selection_only_logs_hint()
    {
        var vm = new CleanViewModel(_env.Container);
        vm.TempWin = vm.TempUser = vm.Recycle = vm.Edge = vm.Chrome = vm.Firefox = false;

        await vm.AnalyzeAsync();

        Assert.True(vm.HasLog);
        Assert.Contains(LocalizationService.GetString("Clean_LogHint"), vm.LogText);
        Assert.False(vm.CanClean);
    }

    [Fact]
    public async Task Analyze_dns_only_enables_cleaning_without_measurable_size()
    {
        var vm = new CleanViewModel(_env.Container, SyncUiThreadScheduler.Instance, new RecordingConfirmService());
        vm.TempWin = vm.TempUser = vm.Recycle = vm.Edge = vm.Chrome = vm.Firefox = false;
        vm.Dns = true;
        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        await vm.AnalyzeAsync();

        Assert.True(vm.CanClean);
        Assert.False(vm.IsBusy);
        Assert.Contains(nameof(vm.IsBusy), changed);
        Assert.Contains(nameof(vm.TotalSize), changed);
        Assert.Contains(LocalizationService.GetString("Clean_LogAnalyzeEnd"), vm.LogText);
    }

    [Fact]
    public async Task Clean_is_ignored_until_analysis_allows_it()
    {
        var vm = new CleanViewModel(_env.Container);

        await vm.CleanAsync();

        Assert.False(vm.HasLog);
        Assert.Empty(_env.Container.Logger.GetCleanHistory());
    }

    [Fact]
    public void AttachWindow_wires_child_panels()
    {
        var vm = new CleanViewModel(_env.Container);
        vm.AttachWindow(SyncUiThreadScheduler.Instance, new RecordingConfirmService());
        Assert.True(vm.Tweaks.CanApply);
        Assert.True(vm.Updates.CanScan);
    }
}
