using optiCombat.Services;
using optiCombat.Strings;
using optiCombat.ViewModels;
using System.Windows;
using System.Windows.Threading;

namespace optiCombat.Coordinators;

/// <summary>Scan menu contextuel Explorateur (IPC second instance + chemin en attente au démarrage).</summary>
public sealed class ShellScanCoordinator
{
    private readonly Dispatcher _dispatcher;
    private readonly NavigationService _navigation;
    private readonly Func<ScanViewModel?> _viewModel;
    private readonly Action _showWindow;

    public ShellScanCoordinator(
        Dispatcher dispatcher,
        NavigationService navigation,
        Func<ScanViewModel?> viewModel,
        Action showWindow)
    {
        _dispatcher = dispatcher;
        _navigation = navigation;
        _viewModel = viewModel;
        _showWindow = showWindow;
    }

    public void Hook(Window window) =>
        IpcManager.HookShellScanRequest(window, OnShellScanRequested);

    private void OnShellScanRequested()
    {
        _dispatcher.BeginInvoke(async () =>
        {
            var path = ShellScanRequest.TryConsume();
            if (!string.IsNullOrWhiteSpace(path))
                await RunShellScanAsync(path);
            _showWindow();
        }, DispatcherPriority.Normal);
    }

    public async Task RunShellScanAsync(string path)
    {
        var vm = _viewModel();
        if (vm == null || !ShellScanArguments.IsValidScanTarget(path))
            return;

        _navigation.NavigateTo(OpticombatStrings.PanelIds.Antivirus);
        _showWindow();
        await vm.RequestContextMenuScanAsync(path);
    }
}
