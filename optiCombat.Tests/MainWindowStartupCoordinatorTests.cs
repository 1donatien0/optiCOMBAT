using Moq;
using optiCombat.Coordinators;
using optiCombat.Services;
using optiCombat.Strings;

namespace optiCombat.Tests;

public sealed class MainWindowStartupCoordinatorTests
{
    [Fact]
    public async Task RunAsync_navigates_to_overview_and_sets_protection_active()
    {
        string? navigated = null;
        string? status = null;
        var nav = new Mock<INavigationService>();
        nav.Setup(n => n.NavigateTo(It.IsAny<string>())).Callback<string>(id => navigated = id);

        var host = new MainWindowStartupCoordinator.Host
        {
            Container = ServiceContainer.Default,
            Navigation = nav.Object,
            ViewModel = null,
            Window = null,
            RegisterPanels = () => { },
            RefreshAntivirusStatus = () => { },
            RefreshQuarantineList = () => { },
            RefreshHistory = () => { },
            RefreshSignaturesDisplayAsync = () => Task.CompletedTask,
            RefreshOverviewProtection = () => { },
            ApplyElevationBanner = () => { },
            SetStatus = (msg, _, _) => status = msg,
            WarmUpYaraRulesAsync = () => Task.CompletedTask,
            ShowWindow = () => { },
            ShellScan = null,
            GuardSession = true,
            ShowOnboardingIfNeeded = (_, _) => { },
        };

        await MainWindowStartupCoordinator.RunAsync(host);

        Assert.Equal(OpticombatStrings.PanelIds.Overview, navigated);
        Assert.NotNull(status);
    }
}
