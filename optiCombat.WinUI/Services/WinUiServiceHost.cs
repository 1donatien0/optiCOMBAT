using optiCombat.Coordinators;
using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Views;
using optiCombat.ViewModels;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.WinUI.Services;

/// <summary>Point d'entrée services partagés pour le shell WinUI 3.</summary>
public sealed class WinUiServiceHost
{
    public static WinUiServiceHost Instance { get; } = new();

    public ServiceContainer Container { get; } = ServiceContainer.Default;

    public AntivirusViewModel Antivirus { get; } = new(ServiceContainer.Default);

    public HistoryViewModel History { get; } = new(ServiceContainer.Default);

    public CleanViewModel Clean { get; } = new(ServiceContainer.Default);

    public OptionsViewModel Options { get; } = new(ServiceContainer.Default);

    private WinUiServiceHost()
    {
        LocalizationService.Initialize();
    }

    public void RefreshOverview(IOverviewPanel panel)
    {
        OverviewRefreshCoordinator.RefreshProtectionAndRecommendations(
            OverviewRefreshContextBuilder.FromContainer(panel, Container));

        var sessions = Container.Logger.GetHistory();
        panel.UpdateProtectionStatistics(sessions);

        var last = sessions.Count == 0
            ? null
            : sessions.OrderByDescending(s => s.StartedAt).First();
        panel.UpdateLastScanSummary(last);

        panel.UpdateAntivirusCardStatus(
            Container.ClamAv.IsClamAvInstalled(),
            Container.Yara.RulesCount,
            Container.ClamActiveEngine);
    }

    public async Task RefreshOverviewAsync(IOverviewPanel panel, bool forceSignatures = false)
    {
        RefreshOverview(panel);
        await OverviewRefreshCoordinator.RefreshSignaturesAsync(
            new SignaturesRefreshContext(
                Container.SignatureStatus,
                panel,
                AntivirusPanel: null,
                ApplySnapshot: null,
                AfterSignaturesRefreshed: () => RefreshOverview(panel)),
            forceSignatures).ConfigureAwait(true);
    }

    public async Task RefreshAntivirusAsync(IAntivirusSignaturesPanel? panel = null, bool forceSignatures = false)
    {
        Antivirus.RefreshProtectionBadge();
        Antivirus.RefreshLastScan();
        Antivirus.LoadQuarantine();
        await OverviewRefreshCoordinator.RefreshSignaturesAsync(
            new SignaturesRefreshContext(
                Container.SignatureStatus,
                panel as IOverviewPanel,
                panel,
                ApplySnapshot: null,
                AfterSignaturesRefreshed: () => Antivirus.RefreshProtectionBadge()),
            forceSignatures).ConfigureAwait(true);
    }
}
