using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Strings;

namespace optiCombat.WinUI.Services;

/// <summary>Initialisation WinUI : runtime, préférences, protection au démarrage.</summary>
public static class WinUiStartupCoordinator
{
    public sealed class Host
    {
        public required ServiceContainer Container { get; init; }
        public required Action RefreshOverview { get; init; }
        public required Action RefreshAntivirus { get; init; }
        public required Action RefreshHistory { get; init; }
        public required Func<Task> RefreshSignaturesAsync { get; init; }
        public required Action<string> SetStatus { get; init; }
        public required Func<Task> WarmUpYaraRulesAsync { get; init; }
        public string? PendingShellScanPath { get; set; }
        public required Func<string, Task> RunShellScanAsync { get; init; }
    }

    public static async Task RunAsync(Host host)
    {
        RuntimeDependencies.LogReportIfIncomplete();
        var runtimeReport = RuntimeDependencies.Evaluate();
        bool clamAvOk = host.Container.ClamAv.IsClamAvInstalled();

        if (!runtimeReport.IsClamAvReady)
            host.SetStatus(runtimeReport.BuildSummaryLine() + LocalizationService.GetString("Main_RuntimeHint"));
        else
            host.SetStatus(clamAvOk
                ? LocalizationService.GetString("Main_ClamOperational")
                : LocalizationService.GetString("Main_ClamNotFound"));

        host.RefreshOverview();
        host.RefreshAntivirus();
        host.RefreshHistory();
        await host.RefreshSignaturesAsync().ConfigureAwait(true);

        try
        {
            host.Container.ApplyPreferencesOnStartup();
        }
        catch (Exception ex)
        {
            AppLogger.Warn("WinUiStartup", "ApplyPreferencesOnStartup", ex);
        }

        host.SetStatus(OpticombatStrings.UiMessages.ProtectionActive);
        _ = host.WarmUpYaraRulesAsync();

        if (!string.IsNullOrWhiteSpace(host.PendingShellScanPath))
        {
            var shellPath = host.PendingShellScanPath;
            host.PendingShellScanPath = null;
            await host.RunShellScanAsync(shellPath).ConfigureAwait(true);
        }
    }
}
