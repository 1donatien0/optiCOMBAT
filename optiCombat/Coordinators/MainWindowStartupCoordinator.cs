using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Strings;
using optiCombat.ViewModels;
using System.Windows;

namespace optiCombat.Coordinators;

/// <summary>Orchestration du chargement initial de <see cref="MainWindow"/> (runtime, RTP, navigation).</summary>
public static class MainWindowStartupCoordinator
{
    public sealed class Host
    {
        public required ServiceContainer Container { get; init; }
        public required INavigationService Navigation { get; init; }
        public required ScanViewModel? ViewModel { get; init; }
        public required Window? Window { get; init; }
        public required Action RegisterPanels { get; init; }
        public required Action RefreshAntivirusStatus { get; init; }
        public required Action RefreshQuarantineList { get; init; }
        public required Action RefreshHistory { get; init; }
        public required Func<Task> RefreshSignaturesDisplayAsync { get; init; }
        public required Action RefreshOverviewProtection { get; init; }
        public required Action ApplyElevationBanner { get; init; }
        public required Action<string, bool, bool> SetStatus { get; init; }
        public required Func<Task> WarmUpYaraRulesAsync { get; init; }
        public required Action ShowWindow { get; init; }
        public required ShellScanCoordinator? ShellScan { get; init; }
        public required bool GuardSession { get; init; }
        public string? PendingShellScanPath { get; set; }
        public required Action<Window, ServiceContainer> ShowOnboardingIfNeeded { get; init; }
    }

    public static async Task RunAsync(Host host)
    {
        host.RegisterPanels();

        RuntimeDependencies.LogReportIfIncomplete();
        var runtimeReport = RuntimeDependencies.Evaluate();

        bool clamAvOk = host.Container.ClamAv.IsClamAvInstalled();
        if (!runtimeReport.IsClamAvReady)
            host.SetStatus(runtimeReport.BuildSummaryLine() + LocalizationService.GetString("Main_RuntimeHint"), true, false);
        else
            host.SetStatus(
                clamAvOk ? LocalizationService.GetString("Main_ClamOperational") : LocalizationService.GetString("Main_ClamNotFound"),
                false,
                !clamAvOk);

        host.RefreshAntivirusStatus();
        host.RefreshQuarantineList();
        host.RefreshHistory();
        await host.RefreshSignaturesDisplayAsync().ConfigureAwait(false);
        host.ApplyElevationBanner();

        try
        {
            host.Container.ApplyPreferencesOnStartup();
        }
        catch (Exception ex)
        {
            AppLogger.Warn("MainWindowStartup", "ApplyPreferencesOnStartup", ex);
        }

        host.ViewModel?.RefreshProtectionStatus();
        host.RefreshOverviewProtection();
        host.Navigation.NavigateTo(OpticombatStrings.PanelIds.Overview);
        host.SetStatus(OpticombatStrings.UiMessages.ProtectionActive, false, false);

        if (!host.GuardSession && host.Window != null)
            host.ShowOnboardingIfNeeded(host.Window, host.Container);

        _ = host.WarmUpYaraRulesAsync();

        if (host.GuardSession)
        {
            if (host.Window != null)
            {
                host.Window.ShowInTaskbar = false;
                host.Window.WindowState = WindowState.Minimized;
                host.Window.Hide();
            }
            host.SetStatus(LocalizationService.GetString("Main_GuardSession"), false, false);
            return;
        }

        if (!string.IsNullOrWhiteSpace(host.PendingShellScanPath) && host.ShellScan != null)
        {
            var shellPath = host.PendingShellScanPath;
            host.PendingShellScanPath = null;
            await host.ShellScan.RunShellScanAsync(shellPath).ConfigureAwait(false);
        }
    }
}
