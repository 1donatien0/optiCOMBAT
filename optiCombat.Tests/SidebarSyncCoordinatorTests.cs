using optiCombat.Coordinators;
using optiCombat.Services;
using optiCombat.Strings;

namespace optiCombat.Tests;

public sealed class SidebarSyncCoordinatorTests
{
    [Fact]
    public void ApplySync_invokes_matching_sidebar_action()
    {
        var navigation = new NavigationService();
        string? selected = null;
        var coordinator = new SidebarSyncCoordinator(
            navigation,
            action => action(),
            new Dictionary<string, Action>
            {
                [OpticombatStrings.PanelIds.History] = () => selected = OpticombatStrings.PanelIds.History,
            });

        coordinator.ApplySync(OpticombatStrings.PanelIds.History);

        Assert.Equal(OpticombatStrings.PanelIds.History, selected);
        Assert.False(coordinator.IsSyncing);
    }

    [Fact]
    public void ApplySync_ignores_unknown_panel()
    {
        var navigation = new NavigationService();
        int calls = 0;
        var coordinator = new SidebarSyncCoordinator(
            navigation,
            action => action(),
            new Dictionary<string, Action>
            {
                [OpticombatStrings.PanelIds.Overview] = () => calls++,
            });

        coordinator.ApplySync(OpticombatStrings.PanelIds.Clean);

        Assert.Equal(0, calls);
    }

    [Fact]
    public void Detach_stops_navigated_handler()
    {
        var navigation = new NavigationService();
        int calls = 0;
        var coordinator = new SidebarSyncCoordinator(
            navigation,
            action => action(),
            new Dictionary<string, Action>
            {
                [OpticombatStrings.PanelIds.Options] = () => calls++,
            });

        coordinator.Detach();
        navigation.NavigateTo(OpticombatStrings.PanelIds.Options);

        Assert.Equal(0, calls);
    }
}
