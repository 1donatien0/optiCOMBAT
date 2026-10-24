using System.Diagnostics;
using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.Tests;

/// <summary>
/// Actions qui modifient le système, vérifiées par la commande ou la clé exacte qu'elles
/// produiraient (enregistreur <see cref="RecordingShell"/> : rien n'est exécuté ni écrit).
/// </summary>
[Collection("OpticombatPrefs")]
public sealed class SystemActionsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "opticombat_sys_" + Guid.NewGuid().ToString("N"));

    public SystemActionsTests()
    {
        Directory.CreateDirectory(_dir);
        LocalizationService.ApplyCulture("fr-FR");
    }

    public void Dispose()
    {
        PlatformProtectionBootstrap.RemoteProbeOverride = null;
        PlatformProtectionBootstrap.BaseDirectoryOverride = null;
        PlatformProtectionBootstrap.StartPollDelay = TimeSpan.FromMilliseconds(500);
        PlatformProtectionBootstrap.Initialize(new DefaultUserPreferencesAccessor());
        PlatformRegistration.BaseDirectoryOverride = null;
        PlatformRegistration.DriversDirectoryOverride = null;
        ThreatRepairService.MpCmdRunPathOverride = null;
        WindowsDefenderExclusionService.DefenderPresentOverride = null;
        WindowsDefenderExclusionService.RunningElevatedOverride = null;
        ElevationHelper.ExecutablePathOverride = null;
        LocalizationService.RestartExecutableOverride = null;
        OptionsViewModel.AutoStartExecutableOverride = null;
        SystemTweaksService.FlushDnsOverride = null;
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private static ProcessOutcome Ok(string output = "") => new(true, 0, output);

    private string Touch(string name)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, "x");
        return path;
    }

    // ── Tweaks HKCU / powercfg ───────────────────────────────────────────────

    [Fact]
    public void Hkcu_tweaks_write_the_expected_values()
    {
        using var shell = RecordingShell.Install();
        const string adv = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";

        Assert.True(SystemTweaksService.SetVisualEffectsBestPerformance());
        Assert.True(SystemTweaksService.DisableAdvertisingId());
        Assert.True(SystemTweaksService.DisableSuggestions());
        Assert.True(SystemTweaksService.DisableTailoredExperiences());
        Assert.True(SystemTweaksService.ShowFileExtensions());
        Assert.True(SystemTweaksService.ShowHiddenFiles());
        Assert.True(SystemTweaksService.AlignTaskbarLeft());
        Assert.True(SystemTweaksService.HideTaskbarWidgets());
        Assert.True(SystemTweaksService.ExplorerOpensThisPc());
        Assert.True(SystemTweaksService.SearchBoxAsIcon());

        var u = shell.CurrentUser;
        Assert.Equal(2, u[RecordingShell.Key(@"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting")]);
        Assert.Equal(0, u[RecordingShell.Key(@"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled")]);
        Assert.Equal(0, u[RecordingShell.Key(@"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SystemPaneSuggestionsEnabled")]);
        Assert.Equal(0, u[RecordingShell.Key(@"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled")]);
        Assert.Equal(0, u[RecordingShell.Key(adv, "HideFileExt")]);
        Assert.Equal(1, u[RecordingShell.Key(adv, "Hidden")]);
        Assert.Equal(0, u[RecordingShell.Key(adv, "TaskbarAl")]);
        Assert.Equal(0, u[RecordingShell.Key(adv, "TaskbarDa")]);
        Assert.Equal(1, u[RecordingShell.Key(adv, "LaunchTo")]);
        Assert.Equal(1, u[RecordingShell.Key(@"Software\Microsoft\Windows\CurrentVersion\Search", "SearchboxTaskbarMode")]);
        Assert.Equal(8 + 9, u.Count);
        Assert.Empty(shell.Runs);
    }

    [Fact]
    public void Registry_failure_is_reported_as_false()
    {
        using var shell = new ThrowingShell();
        SystemShell.Current = shell;
        Assert.False(SystemTweaksService.SetVisualEffectsBestPerformance());
        Assert.False(SystemTweaksService.DisableAdvertisingId());
        Assert.False(SystemTweaksService.DisableSuggestions());
        Assert.False(SystemTweaksService.DisableTailoredExperiences());
        Assert.False(SystemTweaksService.ShowFileExtensions());
        Assert.False(SystemTweaksService.SearchBoxAsIcon());
        Assert.False(SystemTweaksService.EnableHighPerformancePowerPlan());
        Assert.False(SystemTweaksService.OpenStartupAppsManager());
        Assert.False(SystemTweaksService.OpenWindowsUpdateSettings());
        Assert.False(SystemTweaksService.RunElevatedBatch(["sc stop DiagTrack"], waitForExit: true));
    }

    [Fact]
    public void Power_plan_uses_the_high_performance_guid_and_checks_the_exit_code()
    {
        using var shell = RecordingShell.Install();
        shell.Respond = _ => Ok();
        Assert.True(SystemTweaksService.EnableHighPerformancePowerPlan());
        Assert.Equal("powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", Assert.Single(shell.CommandLines));

        shell.Respond = _ => new ProcessOutcome(true, 1, string.Empty);
        Assert.False(SystemTweaksService.EnableHighPerformancePowerPlan());
    }

    [Fact]
    public void Settings_shortcuts_open_the_right_targets()
    {
        using var shell = RecordingShell.Install();
        shell.Respond = _ => new ProcessOutcome(true, -1, string.Empty);

        Assert.True(SystemTweaksService.OpenStartupAppsManager());
        Assert.True(SystemTweaksService.OpenWindowsUpdateSettings());

        Assert.Equal(["taskmgr.exe /0 /startup", "ms-settings:windowsupdate "], shell.CommandLines);
        Assert.All(shell.Runs, r => Assert.True(r.UseShellExecute));
    }

    [Fact]
    public async Task Explorer_is_restarted_only_if_windows_does_not_bring_it_back()
    {
        using var shell = RecordingShell.Install();
        shell.Processes["explorer"] = 2;

        await SystemTweaksService.RestartExplorer(TimeSpan.Zero);

        Assert.Equal(["explorer"], shell.Killed);
        Assert.Equal("explorer.exe ", Assert.Single(shell.CommandLines));

        shell.Runs.Clear();
        shell.Processes["explorer"] = 0;
        var restarted = SystemTweaksService.RestartExplorer(TimeSpan.FromMilliseconds(50));
        shell.Processes["explorer"] = 1; // Windows l'a relancé entre-temps
        await restarted;
        Assert.Empty(shell.Runs);
    }

    [Fact]
    public void Dns_flush_reports_failure_of_the_native_call()
    {
        SystemTweaksService.FlushDnsOverride = () => 1;
        Assert.True(SystemTweaksService.FlushDnsCache());
        SystemTweaksService.FlushDnsOverride = () => throw new EntryPointNotFoundException();
        Assert.False(SystemTweaksService.FlushDnsCache());
    }

    // ── Lots élevés ───────────────────────────────────────────────────────────

    [Fact]
    public void Elevated_batch_runs_one_runas_cmd_and_handles_refusal()
    {
        using var shell = RecordingShell.Install();
        shell.Respond = _ => Ok();

        Assert.True(SystemTweaksService.RunElevatedBatch(SystemTweaksService.ElevatedTelemetryCommands(), waitForExit: true));
        var run = Assert.Single(shell.Runs);
        Assert.Equal("runas", run.Verb);
        Assert.EndsWith("cmd.exe", run.FileName, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("sc config DiagTrack start= disabled", run.Arguments, StringComparison.Ordinal);
        Assert.Equal(Timeout.Infinite, shell.Timeouts[0]);

        shell.Respond = _ => ProcessOutcome.UserCancelled;
        Assert.False(SystemTweaksService.RunElevatedBatch(SystemTweaksService.ElevatedDismCleanupCommands(), waitForExit: false));
        Assert.Null(shell.Timeouts[1]);
    }

    [Fact]
    public void Elevated_command_runner_reports_exit_code_timeout_and_refusal()
    {
        using var shell = RecordingShell.Install();
        Assert.True(ElevatedCommandRunner.RunElevatedBatch([], waitForExit: true));
        Assert.Empty(shell.Runs);

        shell.Respond = _ => Ok();
        Assert.True(ElevatedCommandRunner.RunElevatedBatch(["net share x /delete"], waitForExit: true, timeoutMs: 1000));
        Assert.Equal("runas", shell.Runs[^1].Verb);
        Assert.Equal("/d /c net share x /delete", shell.Runs[^1].Arguments);

        shell.Respond = _ => new ProcessOutcome(true, 5, string.Empty);
        Assert.False(ElevatedCommandRunner.RunElevatedBatch(["a"], waitForExit: true));
        Assert.True(ElevatedCommandRunner.RunElevatedBatch(["a"], waitForExit: false));

        shell.Respond = _ => new ProcessOutcome(true, -1, string.Empty, TimedOut: true);
        Assert.False(ElevatedCommandRunner.RunElevatedBatch(["a"], waitForExit: true));

        shell.Respond = _ => ProcessOutcome.UserCancelled;
        Assert.False(ElevatedCommandRunner.RunElevatedBatch(["a"], waitForExit: true));

        shell.Respond = _ => throw new InvalidOperationException("boom");
        Assert.False(ElevatedCommandRunner.RunElevatedBatch(["a"], waitForExit: true));
    }

    [Fact]
    public void Relaunch_elevated_passes_each_argument_separately()
    {
        using var shell = RecordingShell.Install();
        ElevationHelper.ExecutablePathOverride = @"C:\Apps\optiCombat.exe";
        shell.Respond = _ => new ProcessOutcome(true, -1, string.Empty);

        Assert.True(ElevationHelper.RelaunchElevated("--scan", @"C:\Dossier avec espaces\x.exe"));
        var run = Assert.Single(shell.Runs);
        Assert.Equal("runas", run.Verb);
        Assert.Equal(["--scan", @"C:\Dossier avec espaces\x.exe"], run.ArgumentList);

        shell.Respond = _ => ProcessOutcome.UserCancelled;
        Assert.False(ElevationHelper.RelaunchElevated("--x"));
        shell.Respond = _ => throw new InvalidOperationException();
        Assert.False(ElevationHelper.RelaunchElevated("--x"));
    }

    // ── Service Windows / AMSI / minifiltre ───────────────────────────────────

    [Fact]
    public void Service_is_registered_with_sc_when_missing_then_started()
    {
        using var shell = RecordingShell.Install();
        Touch("optiCombat.Service.exe");
        PlatformProtectionBootstrap.BaseDirectoryOverride = _dir;
        PlatformProtectionBootstrap.StartPollDelay = TimeSpan.Zero;
        PlatformProtectionBootstrap.Initialize(new FixedPreferencesAccessor(new UserPreferences { UsePlatformProtectionService = true }));
        var installed = false;
        var reachable = false;
        PlatformProtectionBootstrap.RemoteProbeOverride = () => reachable;
        shell.Respond = psi =>
        {
            if (psi.Arguments.StartsWith("query", StringComparison.Ordinal))
                return installed ? Ok("SERVICE_NAME: optiCombatProtection") : new ProcessOutcome(true, 1060, "absent");
            if (psi.Arguments.StartsWith("create", StringComparison.Ordinal))
                installed = true;
            if (psi.Arguments.StartsWith("start", StringComparison.Ordinal))
                reachable = true;
            return Ok();
        };

        Assert.True(PlatformProtectionBootstrap.TryStartWindowsService());

        var lines = shell.CommandLines;
        Assert.Contains(lines, l => l.StartsWith("sc.exe create optiCombatProtection binPath= \"", StringComparison.Ordinal)
                                    && l.Contains("start= auto", StringComparison.Ordinal));
        Assert.Contains(lines, l => l.StartsWith("sc.exe description optiCombatProtection", StringComparison.Ordinal));
        Assert.Contains("sc.exe start optiCombatProtection", lines);
    }

    [Fact]
    public void Missing_service_executable_installs_nothing()
    {
        using var shell = RecordingShell.Install();
        PlatformProtectionBootstrap.BaseDirectoryOverride = _dir;
        Assert.False(PlatformProtectionBootstrap.TryInstallWindowsService());
        Assert.False(PlatformProtectionBootstrap.TryStartWindowsService());
        Assert.DoesNotContain(shell.CommandLines, l => l.Contains("create", StringComparison.Ordinal));
    }

    [Fact]
    public void Ensure_running_falls_back_to_the_service_host_process()
    {
        using var shell = RecordingShell.Install();
        Touch("optiCombat.exe");
        PlatformProtectionBootstrap.BaseDirectoryOverride = _dir;
        PlatformProtectionBootstrap.StartPollDelay = TimeSpan.Zero;
        PlatformProtectionBootstrap.RemoteProbeOverride = () => false;
        PlatformProtectionBootstrap.Initialize(new FixedPreferencesAccessor(new UserPreferences { UsePlatformProtectionService = true }));
        shell.Respond = _ => new ProcessOutcome(true, 1060, string.Empty);

        PlatformProtectionBootstrap.EnsurePlatformProtectionRunning();

        var host = shell.Runs.Last();
        Assert.EndsWith("optiCombat.exe", host.FileName, StringComparison.Ordinal);
        Assert.Equal(["--service-host"], host.ArgumentList);
    }

    [Fact]
    public void Ensure_running_does_nothing_when_disabled_or_already_reachable()
    {
        using var shell = RecordingShell.Install();
        PlatformProtectionBootstrap.Initialize(new FixedPreferencesAccessor(new UserPreferences { UsePlatformProtectionService = false }));
        PlatformProtectionBootstrap.EnsurePlatformProtectionRunning();
        Assert.False(PlatformProtectionBootstrap.IsRemoteProtectionActive());

        PlatformProtectionBootstrap.Initialize(new FixedPreferencesAccessor(new UserPreferences { UsePlatformProtectionService = true }));
        PlatformProtectionBootstrap.RemoteProbeOverride = () => true;
        PlatformProtectionBootstrap.EnsurePlatformProtectionRunning();
        Assert.Empty(shell.Runs);
    }

    [Fact]
    public void Stop_and_uninstall_only_touch_an_installed_service()
    {
        using var shell = RecordingShell.Install();
        shell.Respond = psi => psi.Arguments.StartsWith("query", StringComparison.Ordinal)
            ? Ok("SERVICE_NAME: optiCombatProtection")
            : Ok();

        PlatformProtectionBootstrap.TryUninstallWindowsService();
        Assert.Contains("sc.exe stop optiCombatProtection", shell.CommandLines);
        Assert.Contains("sc.exe delete optiCombatProtection", shell.CommandLines);

        shell.Runs.Clear();
        shell.Respond = _ => new ProcessOutcome(true, 1060, string.Empty);
        PlatformProtectionBootstrap.TryUninstallWindowsService();
        Assert.All(shell.CommandLines, l => Assert.StartsWith("sc.exe query", l, StringComparison.Ordinal));
    }

    [Fact]
    public void Amsi_provider_and_minifilter_registration()
    {
        using var shell = RecordingShell.Install();
        PlatformRegistration.BaseDirectoryOverride = _dir;
        var drivers = Path.Combine(_dir, "drivers");
        Directory.CreateDirectory(drivers);
        PlatformRegistration.DriversDirectoryOverride = drivers;

        PlatformRegistration.TryRegisterAmsiProvider();
        PlatformRegistration.TryLoadMinifilter();
        Assert.Empty(shell.LocalMachine); // binaires absents : rien d'enregistré
        Assert.Empty(shell.Runs);

        var dll = Touch("optiCombat.AmsiProvider.dll");
        Touch("optiCombat.Minifilter.sys");
        PlatformRegistration.TryRegisterAmsiProvider();
        PlatformRegistration.TryLoadMinifilter();
        PlatformRegistration.TryUnloadMinifilter();

        const string key = @"SOFTWARE\Microsoft\AMSI\Providers\{A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B}";
        Assert.Equal(dll, shell.LocalMachine[RecordingShell.Key(key, "Path")]);
        Assert.Equal("optiCombat AMSI Provider", shell.LocalMachine[RecordingShell.Key(key, string.Empty)]);
        Assert.True(File.Exists(Path.Combine(drivers, "optiCombat.Minifilter.sys")));
        Assert.Equal(["fltmc.exe load optiCombatMinifilter", "fltmc.exe unload optiCombatMinifilter"], shell.CommandLines);
    }

    // ── Defender ──────────────────────────────────────────────────────────────

    [Fact]
    public void Defender_targeted_scan_passes_the_path_as_a_single_argument()
    {
        using var shell = RecordingShell.Install();
        ThreatRepairService.MpCmdRunPathOverride = Touch("MpCmdRun.exe");
        shell.Respond = _ => Ok();
        var tricky = @"C:\x"" -RemoveDefinitions -All "".exe";

        var result = ThreatRepairService.TryDefenderTargetedScan(tricky);

        Assert.True(result.Success);
        Assert.True(result.UsedDefenderFallback);
        Assert.Equal(["-Scan", "-ScanType", "3", "-File", tricky, "-DisableRemediation"], Assert.Single(shell.Runs).ArgumentList);

        ThreatRepairService.MpCmdRunPathOverride = Path.Combine(_dir, "absent.exe");
        Assert.False(ThreatRepairService.TryDefenderTargetedScan(tricky).Success);
    }

    [Fact]
    public async Task Defender_exclusions_outcomes_follow_the_powershell_result()
    {
        using var shell = RecordingShell.Install();
        WindowsDefenderExclusionService.DefenderPresentOverride = () => true;
        WindowsDefenderExclusionService.RunningElevatedOverride = () => true;

        shell.Respond = _ => Ok("OK:3");
        Assert.Equal(DefenderExclusionOutcome.Added, await WindowsDefenderExclusionService.ApplyOnUserRequestAsync());
        var ps = shell.Runs[^1];
        Assert.Equal("powershell.exe", ps.FileName);
        Assert.Contains("-NonInteractive", ps.ArgumentList);
        Assert.Contains(ps.ArgumentList, a => a.Contains("Add-MpPreference -ExclusionPath", StringComparison.Ordinal));

        shell.Respond = _ => Ok("OK:0");
        Assert.Equal(DefenderExclusionOutcome.AlreadyConfigured, await WindowsDefenderExclusionService.ApplyOnUserRequestAsync());

        shell.Respond = _ => new ProcessOutcome(true, 2, "DEFENDER_DISABLED");
        Assert.Equal(DefenderExclusionOutcome.DefenderUnavailable, await WindowsDefenderExclusionService.ApplyOnUserRequestAsync());

        // Accès refusé alors que déjà élevé : refus définitif, pas de nouvelle invite UAC.
        shell.Respond = _ => new ProcessOutcome(true, 3, "PREF_READ_FAILED");
        Assert.Equal(DefenderExclusionOutcome.Refused, await WindowsDefenderExclusionService.ApplyOnUserRequestAsync());

        // Non élevé : relance élevée proposée.
        WindowsDefenderExclusionService.RunningElevatedOverride = () => false;
        ElevationHelper.ExecutablePathOverride = @"C:\Apps\optiCombat.exe";
        shell.Respond = psi => psi.Verb == "runas" ? new ProcessOutcome(true, -1, string.Empty) : new ProcessOutcome(true, 3, "PREF_READ_FAILED");
        Assert.Equal(DefenderExclusionOutcome.ElevationRequested, await WindowsDefenderExclusionService.ApplyOnUserRequestAsync());
        Assert.Contains(HeadlessScanArguments.DefenderExclusions, shell.Runs[^1].ArgumentList);

        shell.Respond = _ => ProcessOutcome.NotStarted;
        Assert.Equal(DefenderExclusionOutcome.Refused, await WindowsDefenderExclusionService.ApplyOnUserRequestAsync());

        WindowsDefenderExclusionService.DefenderPresentOverride = () => false;
        Assert.Equal(DefenderExclusionOutcome.DefenderUnavailable, await WindowsDefenderExclusionService.ApplyOnUserRequestAsync());
    }

    [Theory]
    [InlineData((int)DefenderExclusionOutcome.Added, "Def_Added")]
    [InlineData((int)DefenderExclusionOutcome.AlreadyConfigured, "Def_AlreadyConfigured")]
    [InlineData((int)DefenderExclusionOutcome.DefenderUnavailable, "Def_Unavailable")]
    [InlineData((int)DefenderExclusionOutcome.ElevationRequested, "Def_ElevationRequested")]
    [InlineData((int)DefenderExclusionOutcome.Busy, "Def_Busy")]
    [InlineData((int)DefenderExclusionOutcome.Refused, "Def_Refused")]
    public void Defender_outcomes_have_a_message(int value, string key)
    {
        var outcome = (DefenderExclusionOutcome)value;
        Assert.Equal(LocalizationService.GetString(key), WindowsDefenderExclusionService.DescribeOutcome(outcome));
        Assert.False(string.IsNullOrWhiteSpace(WindowsDefenderExclusionService.DescribeOutcome(outcome)));
    }

    [Fact]
    public void Process_exclusions_use_full_paths_of_deployed_binaries_only()
    {
        Touch("optiCombat.exe");
        Directory.CreateDirectory(Path.Combine(_dir, "yara"));
        File.WriteAllText(Path.Combine(_dir, "yara", Environment.Is64BitProcess ? "yara64.exe" : "yara32.exe"), "y");

        var list = WindowsDefenderExclusionService.CollectProcessExclusions(_dir);

        Assert.Contains(Path.GetFullPath(Path.Combine(_dir, "optiCombat.exe")), list);
        Assert.DoesNotContain(list, p => p.EndsWith("optiCombat.Service.exe", StringComparison.Ordinal));
        Assert.All(list, p => Assert.True(Path.IsPathRooted(p)));
        Assert.NotEmpty(WindowsDefenderExclusionService.CollectExclusionPaths());
    }

    // ── Langue, démarrage automatique, dossiers ───────────────────────────────

    [Fact]
    public void Culture_is_persisted_in_preferences_and_registry_then_read_back()
    {
        using var iso = new IsolatedServices();
        using var shell = RecordingShell.Install();
        LocalizationService.ConfigurePreferencesAccessor(iso.PrefsAccessor);

        LocalizationService.SetUserCulture("en-GB");

        Assert.Equal("en-US", iso.Prefs.UiCulture);
        Assert.Equal("en-US", shell.CurrentUser.Values.OfType<string>().First(v => v == "en-US"));
        Assert.Contains(shell.CurrentUser.Keys, k => k.Contains(@"\command|", StringComparison.Ordinal));
    }

    [Fact]
    public void Restart_relaunches_then_exits()
    {
        using var shell = RecordingShell.Install();
        LocalizationService.RestartExecutableOverride = @"C:\Apps\optiCombat.exe";

        LocalizationService.RestartApplication();

        Assert.Equal(@"C:\Apps\optiCombat.exe", Assert.Single(shell.Runs).FileName);
        Assert.Equal(0, shell.ExitCode);
    }

    [Fact]
    public void Auto_start_is_written_quoted_and_removed()
    {
        using var shell = RecordingShell.Install();
        OptionsViewModel.AutoStartExecutableOverride = @"C:\Program Files\optiCombat\optiCombat.exe";
        const string run = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

        Assert.False(OptionsViewModel.IsAutoStartRegistered());
        OptionsViewModel.SetAutoStart(true);
        Assert.Equal("\"C:\\Program Files\\optiCombat\\optiCombat.exe\"", shell.CurrentUser[RecordingShell.Key(run, "optiCombat")]);
        Assert.True(OptionsViewModel.IsAutoStartRegistered());

        OptionsViewModel.SetAutoStart(false);
        Assert.False(OptionsViewModel.IsAutoStartRegistered());
    }

    [Fact]
    public void Logs_folder_and_bundled_documents_open_through_the_shell()
    {
        using var iso = new IsolatedServices();
        using var shell = RecordingShell.Install();
        var confirm = new RecordingConfirmService();
        var vm = new OptionsViewModel(iso.Container, new NullTheme()) { Confirm = confirm };

        shell.Respond = _ => new ProcessOutcome(true, -1, string.Empty);
        vm.OpenLogsFolder();
        Assert.Equal(AppLogger.LogDirectory, Assert.Single(shell.Runs).FileName);
        Assert.Empty(confirm.Warnings);

        shell.Respond = _ => ProcessOutcome.NotStarted;
        vm.OpenLogsFolder();
        Assert.Single(confirm.Warnings);

        vm.OpenBundledDocument("absent-" + Guid.NewGuid().ToString("N") + ".pdf");
        Assert.Equal(2, confirm.Warnings.Count);
    }

    // ── Panneau Tweaks ────────────────────────────────────────────────────────

    [Fact]
    public async Task Confirmed_tweaks_are_applied_with_one_elevation_and_an_explorer_restart()
    {
        using var shell = RecordingShell.Install();
        shell.Respond = _ => Ok();
        shell.Processes["explorer"] = 1;
        var confirm = new RecordingConfirmService { Answer = true };
        var vm = new TweaksViewModel(SyncUiThreadScheduler.Instance, confirm)
        {
            PowerPlan = true,
            VisualFx = true,
            Ads = true,
            Suggestions = true,
            Tailored = true,
            ShowExt = true,
            ShowHidden = true,
            TaskbarLeft = true,
            HideWidgets = true,
            SearchIcon = true,
            ThisPc = true,
            Telemetry = true,
            Dism = true,
        };

        await vm.ApplyAsync();

        Assert.Single(shell.Runs, r => r.Verb == "runas");
        Assert.Contains("explorer", shell.Killed);
        Assert.Contains(LocalizationService.GetString("Twk_LogEnd"), vm.LogText, StringComparison.Ordinal);
        Assert.Contains(LocalizationService.GetString("Twk_LogExplorerRestart"), vm.LogText, StringComparison.Ordinal);
        Assert.False(vm.IsBusy);
    }

    [Fact]
    public async Task Refused_elevation_is_logged_and_hkcu_tweaks_still_apply()
    {
        using var shell = RecordingShell.Install();
        shell.Respond = _ => ProcessOutcome.UserCancelled;
        var vm = new TweaksViewModel(SyncUiThreadScheduler.Instance, new RecordingConfirmService { Answer = true })
        {
            Ads = true,
            Telemetry = true,
        };

        await vm.ApplyAsync();

        Assert.Contains(LocalizationService.GetString("Twk_LogElevDenied"), vm.LogText, StringComparison.Ordinal);
        Assert.Equal(0, shell.CurrentUser[RecordingShell.Key(@"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled")]);
    }

    [Fact]
    public void Startup_apps_button_logs_only_when_task_manager_opened()
    {
        using var shell = RecordingShell.Install();
        var vm = new TweaksViewModel(SyncUiThreadScheduler.Instance, new RecordingConfirmService());
        vm.OpenStartupApps();
        Assert.DoesNotContain(LocalizationService.GetString("Twk_LogStartupOpened"), vm.LogText, StringComparison.Ordinal);

        shell.Respond = _ => new ProcessOutcome(true, -1, string.Empty);
        vm.OpenStartupApps();
        Assert.Contains(LocalizationService.GetString("Twk_LogStartupOpened"), vm.LogText, StringComparison.Ordinal);
    }

    /// <summary>Shell dont chaque opération échoue (registre verrouillé, processus introuvable).</summary>
    private sealed class ThrowingShell : ISystemShell, IDisposable
    {
        private readonly ISystemShell _previous = SystemShell.Current;

        public ProcessOutcome Run(ProcessStartInfo startInfo, int? timeoutMs) => throw new InvalidOperationException("refus");
        public int CountProcesses(string name) => throw new InvalidOperationException();
        public int KillProcesses(string name) => throw new InvalidOperationException();
        public void SetCurrentUserValue(string subKey, string name, object value, Microsoft.Win32.RegistryValueKind kind) => throw new UnauthorizedAccessException();
        public object? GetCurrentUserValue(string subKey, string name) => throw new UnauthorizedAccessException();
        public void DeleteCurrentUserValue(string subKey, string name) => throw new UnauthorizedAccessException();
        public void DeleteCurrentUserSubKeyTree(string subKey) => throw new UnauthorizedAccessException();
        public void SetLocalMachineValue(string subKey, string name, object value, Microsoft.Win32.RegistryValueKind kind) => throw new UnauthorizedAccessException();
        public void ExitProcess(int exitCode) { }
        public void Dispose() => SystemShell.Current = _previous;
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
