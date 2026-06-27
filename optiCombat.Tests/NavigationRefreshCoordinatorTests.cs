using optiCombat.Services;
using optiCombat.Strings;
using System.Windows;

namespace optiCombat.Tests;

public sealed class NavigationRefreshCoordinatorTests
{
    private sealed class RefreshCounters
    {
        public int History;
        public int Status;
        public int Signatures;
        public int AntivirusData;
    }

    private sealed class FakeNavigationService : INavigationService
    {
        public string CurrentView { get; private set; } = string.Empty;
        public event EventHandler<string>? Navigated;

        public void RegisterPanel(string name, UIElement panel) { }

        public void NavigateTo(string name)
        {
            CurrentView = name;
            Navigated?.Invoke(this, name);
        }

        public bool HasPanel(string name) => true;

        public void Raise(string panelName) => Navigated?.Invoke(this, panelName);
    }

    private static NavigationRefreshCoordinator CreateCoordinator(
        FakeNavigationService nav,
        RefreshCounters c) =>
        new(
            nav,
            System.Windows.Threading.Dispatcher.CurrentDispatcher,
            () => { c.History++; return Task.CompletedTask; },
            () => { c.Status++; return Task.CompletedTask; },
            () => { c.Signatures++; return Task.CompletedTask; },
            () => { c.AntivirusData++; return Task.CompletedTask; });

    [Fact]
    public async Task ApplyRefreshesForPanel_overview_invokes_history_status_and_signature_cache()
    {
        var nav = new FakeNavigationService();
        var c = new RefreshCounters();
        var coord = CreateCoordinator(nav, c);

        await coord.ApplyRefreshesForPanelAsync(OpticombatStrings.PanelIds.Overview);

        Assert.Equal(1, c.History);
        Assert.Equal(1, c.Status);
        Assert.Equal(1, c.Signatures);
        Assert.Equal(0, c.AntivirusData);
    }

    [Fact]
    public async Task ApplyRefreshesForPanel_antivirus_invokes_antivirus_data_only()
    {
        var nav = new FakeNavigationService();
        var c = new RefreshCounters();
        var coord = CreateCoordinator(nav, c);

        await coord.ApplyRefreshesForPanelAsync(OpticombatStrings.PanelIds.Antivirus);

        Assert.Equal(0, c.History);
        Assert.Equal(0, c.Status);
        Assert.Equal(0, c.Signatures);
        Assert.Equal(1, c.AntivirusData);
    }

    [Fact]
    public async Task ApplyRefreshesForPanel_history_invokes_history_only()
    {
        var nav = new FakeNavigationService();
        var c = new RefreshCounters();
        var coord = CreateCoordinator(nav, c);

        await coord.ApplyRefreshesForPanelAsync(OpticombatStrings.PanelIds.History);

        Assert.Equal(1, c.History);
        Assert.Equal(0, c.Status);
        Assert.Equal(0, c.Signatures);
        Assert.Equal(0, c.AntivirusData);
    }

    [Fact]
    public async Task ApplyRefreshesForPanel_propagates_async_completion()
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var coord = new NavigationRefreshCoordinator(
            new FakeNavigationService(),
            System.Windows.Threading.Dispatcher.CurrentDispatcher,
            () => Task.CompletedTask,
            () => Task.CompletedTask,
            () => tcs.Task,
            () => Task.CompletedTask);

        var pending = coord.ApplyRefreshesForPanelAsync(OpticombatStrings.PanelIds.Overview);
        Assert.False(pending.IsCompleted);

        tcs.SetResult();
        await pending;
    }

    [Fact]
    public void Detach_unsubscribes_without_throw()
    {
        var nav = new FakeNavigationService();
        var c = new RefreshCounters();
        var coord = CreateCoordinator(nav, c);
        coord.Detach();
        nav.Raise(OpticombatStrings.PanelIds.History);
        Assert.Equal(0, c.History);
    }
}
