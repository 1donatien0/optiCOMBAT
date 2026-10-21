using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;
using optiCombat.WinUI.Services;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.Tests;

[Collection("OpticombatPrefs")]
public sealed class OptionsViewModelTests : IDisposable
{
    private readonly IsolatedServices _env = new();
    private readonly FakeThemeController _theme = new();

    public void Dispose() => _env.Dispose();

    private OptionsViewModel Create() => new(_env.Container, _theme);

    private string SavedPreferencesFile => Path.Combine(_env.Root, "roaming", "preferences.dat");

    [Theory]
    [InlineData(ScanType.QuickScan, 0)]
    [InlineData(ScanType.FullScan, 1)]
    [InlineData(ScanType.Folder, 2)]
    [InlineData(ScanType.File, 3)]
    public void Load_maps_favorite_scan_type_to_index(ScanType type, int expected)
    {
        _env.Prefs.FavoriteScanType = type;
        Assert.Equal(expected, Create().FavoriteScanIndex);
    }

    [Fact]
    public void Load_reflects_preferences_and_exclusions()
    {
        _env.Prefs.ThemePresetId = "ember";
        _env.Prefs.ThemeAccentColor = "#112233";
        _env.Prefs.UiCulture = "";
        _env.Prefs.VirusTotalApiKey = null!;
        _env.Prefs.CleanSuggestThresholdDays = 21;
        _env.Prefs.SignatureStaleThresholdDays = 3;
        _env.Prefs.HighContrastEnabled = true;
        _env.Prefs.DarkTheme = true;
        _env.Exclusions.ExcludedFolders.Add(@"D:\Jeux");

        var vm = Create();

        Assert.Equal("ember", vm.ThemePresetId);
        Assert.Equal("#112233", vm.ThemeAccentColor);
        Assert.Equal("fr-FR", vm.UiCulture);
        Assert.Equal(string.Empty, vm.VirusTotalApiKey);
        Assert.Equal(21, vm.CleanThresholdDays);
        Assert.Equal(3, vm.SignatureStaleDays);
        Assert.True(vm.HighContrast);
        Assert.True(vm.DarkTheme);
        Assert.Contains(@"D:\Jeux", vm.Exclusions);
        Assert.False(string.IsNullOrWhiteSpace(vm.AppVersionLabel));
        Assert.False(string.IsNullOrWhiteSpace(vm.DefenderComplementCaption));
    }

    [Fact]
    public void Load_defaults_blank_theme_preset_to_combat()
    {
        _env.Prefs.ThemePresetId = " ";
        _env.Prefs.ThemeAccentColor = null!;

        var vm = Create();

        Assert.Equal("combat", vm.ThemePresetId);
        Assert.Equal(string.Empty, vm.ThemeAccentColor);
    }

    [Fact]
    public void Simple_toggles_are_persisted_to_isolated_storage()
    {
        var vm = Create();

        vm.SaveAggressiveSignatures(true);
        vm.SaveRemovableDriveDetailed(true);
        vm.SaveIncludeRemovableInFullScan(true);
        vm.SaveBackupBeforeQuarantine(false);
        vm.SaveAutoQuarantine(true);
        vm.SaveNotifications(true);

        Assert.True(_env.Prefs.AggressiveSignatureUpdates);
        Assert.True(_env.Prefs.RemovableDriveScanDetailed);
        Assert.True(_env.Prefs.IncludeRemovableInFullScan);
        Assert.False(_env.Prefs.BackupBeforeQuarantine);
        Assert.True(_env.Exclusions.AutoQuarantineEnabled);
        Assert.True(_env.Prefs.ActionNotificationsEnabled);
        Assert.True(_env.Container.Notifications.IsEnabled);
        Assert.True(File.Exists(SavedPreferencesFile));
        Assert.True(File.Exists(Path.Combine(_env.Root, "local", "exclusions.dat")));
    }

    [Fact]
    public void Disabling_protection_features_updates_preferences()
    {
        var vm = Create();
        var refreshes = 0;
        _env.Container.ProtectionStateRefreshRequested += (_, _) => refreshes++;

        vm.SaveRealtimeProtection(false);
        vm.SaveAutoUpdate(false);
        vm.SaveProcessMonitor(false);
        vm.SaveRemovableDriveScan(false);
        vm.SaveUseClamd(false);
        vm.SaveGameMode(false);

        Assert.False(_env.Exclusions.RealTimeEnabled);
        Assert.False(_env.Prefs.SignatureAutoUpdateEnabled);
        Assert.False(_env.Prefs.ProcessMonitorEnabled);
        Assert.False(_env.Prefs.RemovableDriveScanEnabled);
        Assert.False(_env.Prefs.UseClamdEngine);
        Assert.False(_env.Prefs.GameModeAutoEnabled);
        Assert.False(_env.Container.RealTimeProtection.IsEnabled);
        Assert.True(refreshes >= 4);
    }

    [Theory]
    [InlineData(0, ScanType.QuickScan)]
    [InlineData(1, ScanType.FullScan)]
    [InlineData(2, ScanType.Folder)]
    [InlineData(3, ScanType.File)]
    [InlineData(9, ScanType.QuickScan)]
    public void SaveFavoriteScan_maps_index_to_scan_type(int index, ScanType expected)
    {
        var vm = Create();
        var raised = new List<string?>();
        vm.PropertyChanged += (_, e) => { lock (raised) raised.Add(e.PropertyName); };

        vm.SaveFavoriteScan(index);

        Assert.Equal(expected, _env.Prefs.FavoriteScanType);
        Assert.Equal(index, vm.FavoriteScanIndex);
        lock (raised)
            Assert.Contains(nameof(vm.FavoriteScanIndex), raised);
    }

    [Fact]
    public void SaveVirusTotalKey_trims_and_persists()
    {
        var vm = Create();

        vm.SaveVirusTotalKey("  abc123  ");
        Assert.Equal("abc123", vm.VirusTotalApiKey);
        Assert.Equal("abc123", _env.Prefs.VirusTotalApiKey);

        vm.SaveVirusTotalKey(null!);
        Assert.Equal(string.Empty, vm.VirusTotalApiKey);
    }

    [Fact]
    public void SaveThresholds_never_goes_below_one_day()
    {
        var vm = Create();
        vm.CleanThresholdDays = 0;
        vm.SignatureStaleDays = -5;

        vm.SaveThresholds();

        Assert.Equal(1, _env.Prefs.CleanSuggestThresholdDays);
        Assert.Equal(1, _env.Prefs.SignatureStaleThresholdDays);
    }

    [Fact]
    public void Exclusions_can_be_added_once_and_removed()
    {
        var vm = Create();
        var folder = Path.Combine(_env.Root, "excluded");

        vm.AddExclusion("");
        vm.AddExclusion(folder);
        vm.AddExclusion(folder.ToUpperInvariant());

        Assert.Single(vm.Exclusions);
        Assert.Contains(folder, _env.Exclusions.ExcludedFolders);

        vm.RemoveExclusion(folder);

        Assert.Empty(vm.Exclusions);
        Assert.DoesNotContain(folder, _env.Exclusions.ExcludedFolders);
    }

    [Fact]
    public void Theme_actions_are_forwarded_to_the_shell_controller()
    {
        var vm = Create();
        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        vm.ApplyTheme(dark: true);
        Assert.True(vm.DarkTheme);
        Assert.False(vm.SyncWindowsTheme);
        Assert.Equal(true, _theme.ExplicitDark);

        _theme.IsDarkTheme = false;
        vm.SaveSyncWindowsTheme(true);
        Assert.True(vm.SyncWindowsTheme);
        Assert.False(vm.DarkTheme);
        Assert.Equal(true, _theme.Sync);

        vm.SaveHighContrast(true);
        Assert.True(vm.HighContrast);
        Assert.Equal(true, _theme.HighContrast);

        vm.SetThemePreset("ocean");
        Assert.Equal("ocean", vm.ThemePresetId);
        Assert.Equal("ocean", _theme.Preset);

        vm.SetThemePreset("  ");
        Assert.Equal("combat", vm.ThemePresetId);

        vm.SetThemeAccentColor("#ABCDEF");
        Assert.Equal("#ABCDEF", vm.ThemeAccentColor);
        Assert.Equal("#ABCDEF", _theme.Accent);

        vm.SetThemeAccentColor(null);
        Assert.Equal(string.Empty, vm.ThemeAccentColor);

        Assert.Contains(nameof(vm.DarkTheme), changed);
        Assert.Contains(nameof(vm.HighContrast), changed);
        Assert.Contains(nameof(vm.ThemePresetId), changed);
        Assert.Contains(nameof(vm.ThemeAccentColor), changed);
    }

    [Fact]
    public void SaveUiCulture_with_current_culture_does_not_restart()
    {
        var vm = Create();
        var raised = false;
        vm.PropertyChanged += (_, _) => raised = true;

        vm.SaveUiCulture("FR-fr");

        Assert.False(raised);
        Assert.Equal("fr-FR", vm.UiCulture);
    }

    [Fact]
    public void OpenBundledDocument_warns_when_file_is_missing()
    {
        var confirm = new RecordingConfirmService();
        var vm = Create();
        vm.Confirm = confirm;

        vm.OpenBundledDocument(Path.Combine("docs", "absent-" + Guid.NewGuid().ToString("N") + ".pdf"));

        Assert.Single(confirm.Warnings);
    }

    [Fact]
    public async Task App_update_check_and_schedule_status_produce_messages()
    {
        var vm = Create();

        await vm.CheckAppUpdatesAsync();
        await vm.RefreshScheduledStatusAsync();

        Assert.False(string.IsNullOrWhiteSpace(vm.UpdateStatusMessage));
        Assert.False(string.IsNullOrWhiteSpace(vm.ScheduledStatus));
    }

    [Fact]
    public void Defender_complement_mode_turns_off_local_realtime_protection()
    {
        var vm = Create();
        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        vm.SaveDefenderComplementMode(true);

        Assert.True(vm.DefenderComplementMode);
        Assert.False(vm.RealtimeProtection);
        Assert.False(vm.ProcessMonitor);
        Assert.True(_env.Prefs.DefenderComplementModeEnabled);
        Assert.False(_env.Exclusions.RealTimeEnabled);
        Assert.Contains(nameof(vm.DefenderComplementMode), changed);
    }

    [Fact]
    public async Task Startup_refresh_updates_stale_signatures_in_background()
    {
        _env.Prefs.SignatureAutoUpdateEnabled = true;
        _env.Prefs.AggressiveSignatureUpdates = true;

        SignatureUpdatePolicy.ApplyAutoUpdateTimers(
            _env.Container.FreshclamUpdater, _env.Container.RulesUpdater, enabled: true, _env.PrefsAccessor);
        SignatureUpdatePolicy.ScheduleStartupRefreshIfStale(_env.Container, _env.PrefsAccessor);

        await Eventually.TrueAsync(() => _env.Http.Requests.Count > 0, 10000);
        Assert.True(_env.Container.FreshclamUpdater.IsAutoUpdateEnabled);
        Assert.True(_env.Container.RulesUpdater.IsAutoUpdateEnabled);
    }

    [Fact]
    public void Startup_refresh_is_skipped_when_auto_update_is_off()
    {
        _env.Prefs.SignatureAutoUpdateEnabled = false;

        SignatureUpdatePolicy.ScheduleStartupRefreshIfStale(_env.Container, _env.PrefsAccessor);
        SignatureUpdatePolicy.ApplyAutoUpdateTimers(
            _env.Container.FreshclamUpdater, _env.Container.RulesUpdater, enabled: false, _env.PrefsAccessor);

        Assert.Empty(_env.Http.Requests);
        Assert.False(_env.Container.FreshclamUpdater.IsAutoUpdateEnabled);
    }

    private sealed class FakeThemeController : IShellThemeController
    {
        public bool IsDarkTheme { get; set; }

        public bool? ExplicitDark { get; private set; }

        public bool? Sync { get; private set; }

        public bool? HighContrast { get; private set; }

        public string? Preset { get; private set; }

        public string? Accent { get; private set; }

        public void ApplyExplicit(bool dark) => ExplicitDark = dark;

        public void SetSyncWithWindows(bool sync) => Sync = sync;

        public void SetHighContrast(bool enabled) => HighContrast = enabled;

        public void SetThemePreset(string presetId) => Preset = presetId;

        public void SetCustomAccentColor(string? hexColor) => Accent = hexColor;
    }
}

public sealed class WinUiThemePacksTests
{
    [Theory]
    [InlineData(null, "combat")]
    [InlineData("", "combat")]
    [InlineData("  EMBER ", "ember")]
    [InlineData("Midnight", "midnight")]
    [InlineData("inconnu", "combat")]
    public void Get_resolves_case_insensitively_with_combat_fallback(string? id, string expected) =>
        Assert.Equal(expected, WinUiThemePacks.Get(id).Id);

    [Fact]
    public void Every_pack_has_localized_name_and_valid_accents()
    {
        LocalizationService.ApplyCulture("fr-FR");
        Assert.Equal(4, WinUiThemePacks.All.Count);
        foreach (var pack in WinUiThemePacks.All)
        {
            Assert.NotEqual(pack.NameKey, LocalizationService.GetString(pack.NameKey));
            Assert.Matches("^#[0-9A-F]{6}$", pack.LightAccent);
            Assert.Matches("^#[0-9A-F]{6}$", pack.DarkAccent);
        }
    }
}
