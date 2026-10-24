using optiCombat.Services;
using optiCombat.Tests.TestSupport;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.Tests;

/// <summary>Méthodes Apply* du conteneur et planification depuis Options (schtasks factice).</summary>
[Collection("OpticombatPrefs")]
public sealed class ContainerApplyTests : IDisposable
{
    private readonly IsolatedServices _env = new();

    public void Dispose() => _env.Dispose();

    private string[] Verbs() => FakeTools.Calls(_env.Schtasks).Select(c => c[0]).ToArray();

    [Fact]
    public void Startup_with_tamper_protection_registers_the_watchdog()
    {
        _env.Prefs.TamperProtectionEnabled = true;
        _env.Prefs.GameModeAutoEnabled = false;
        FakeTools.Script(_env.Schtasks);

        _env.Container.ApplyPreferencesOnStartup();

        Assert.Equal(new[] { "/Delete", "/Create" }, Verbs());
        Assert.False(_env.Container.RealTimeProtection.IsEnabled);
    }

    [Fact]
    public void Startup_without_tamper_protection_deletes_the_watchdog()
    {
        _env.Prefs.TamperProtectionEnabled = false;
        _env.Container.ApplyPreferencesOnStartup();
        Assert.Equal(new[] { "/Delete" }, Verbs());
    }

    [Fact]
    public void ApplyTamperProtection_persists_and_toggles_the_task()
    {
        _env.Container.ApplyTamperProtection(true);
        Assert.True(_env.Prefs.TamperProtectionEnabled);
        _env.Container.ApplyTamperProtection(false);
        Assert.False(_env.Prefs.TamperProtectionEnabled);
        Assert.Equal(new[] { "/Delete", "/Create", "/Delete" }, Verbs());
    }

    [Fact]
    public void Platform_service_cannot_be_enabled_without_signed_driver()
    {
        if (!PlatformProtectionFeatureGate.IsUserActivatable)
        {
            _env.Container.ApplyPlatformProtectionService(true);
            Assert.False(_env.Prefs.UsePlatformProtectionService);
        }
    }

    [Fact]
    public void Process_monitor_and_removable_scan_can_be_turned_off()
    {
        _env.Container.ApplyProcessMonitor(false);
        Assert.False(_env.Prefs.ProcessMonitorEnabled);
        _env.Container.ApplyRemovableDriveScan(false);
        Assert.False(_env.Prefs.RemovableDriveScanEnabled);
        _env.Container.ApplyAutoQuarantine(true);
        Assert.True(_env.Exclusions.AutoQuarantineEnabled);
    }

    [Fact]
    public async Task Options_schedule_toggle_status_and_run_now()
    {
        var vm = new OptionsViewModel(_env.Container, new NullTheme());
        var confirm = new RecordingConfirmService();
        vm.Confirm = confirm;
        vm.ScheduledHour = 30; // borné à 23
        vm.ScheduledMinute = -4; // borné à 0

        FakeTools.Script(_env.Schtasks);
        await vm.ToggleScheduledScanAsync(true);
        var create = FakeTools.Calls(_env.Schtasks).Single(c => c[0] == "/Create");
        Assert.Contains("23:00", create);
        Assert.False(string.IsNullOrWhiteSpace(vm.ScheduledStatus));

        await vm.RunScheduleNowAsync();
        Assert.Single(confirm.Infos);
        Assert.Contains(FakeTools.Calls(_env.Schtasks), c => c[0] == "/Run");

        FakeTools.Script(_env.Schtasks, "Run", exit: 1);
        await vm.RunScheduleNowAsync();
        Assert.Single(confirm.Warnings);

        FakeTools.Script(_env.Schtasks, exit: 1); // la tâche n'existe plus
        foreach (var f in Directory.GetFiles(Path.GetDirectoryName(_env.Schtasks)!, "schtasks.exe.fake.*"))
            File.Delete(f);
        await vm.RunScheduleNowAsync();
        Assert.Equal(2, confirm.Infos.Count);

        var before = FakeTools.Calls(_env.Schtasks).Count;
        await vm.ToggleScheduledScanAsync(false);
        Assert.Contains(FakeTools.Calls(_env.Schtasks).Skip(before), c => c[0] == "/Delete");
    }

    [Fact]
    public void Options_engine_and_tamper_switches_persist()
    {
        var vm = new OptionsViewModel(_env.Container, new NullTheme());
        vm.SaveUseNativeEngine(true);
        Assert.True(_env.Prefs.UseNativeEngine);
        Assert.True(vm.UseNativeEngine);
        vm.SaveTamperProtection(false);
        Assert.False(_env.Prefs.TamperProtectionEnabled);
    }

    private sealed class NullTheme : IShellThemeController
    {
        public bool IsDarkTheme => false;

        public void ApplyExplicit(bool dark) { }

        public void SetSyncWithWindows(bool sync) { }

        public void SetHighContrast(bool enabled) { }

        public void SetThemePreset(string presetId) { }

        public void SetCustomAccentColor(string? hexColor) { }
    }
}
