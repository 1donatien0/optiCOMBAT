using optiCombat.Services;
using optiCombat.ViewModels;
using System.ComponentModel;

namespace optiCombat.Coordinators;

/// <summary>Libération tray, coordinateurs et <see cref="ServiceContainer"/> à la fermeture réelle.</summary>
public static class MainWindowShutdownCoordinator
{
    public sealed class Host
    {
        public required TrayCoordinator Tray { get; init; }
        public SignatureRefreshCoordinator? SignatureRefresh { get; init; }
        public required Action UnhookServiceEvents { get; init; }
        public ScanViewModel? ViewModel { get; init; }
        public PropertyChangedEventHandler? ViewModelPropertyChanged { get; init; }
        public NavigationRefreshCoordinator? NavRefresh { get; init; }
        public SidebarSyncCoordinator? SidebarSync { get; init; }
        public required ServiceContainer Container { get; init; }
    }

    public static void PerformCleanShutdown(Host host)
    {
        try
        {
            host.Tray.Dispose();
            host.SignatureRefresh?.Detach();
            host.UnhookServiceEvents();

            if (host.ViewModel != null && host.ViewModelPropertyChanged != null)
                host.ViewModel.PropertyChanged -= host.ViewModelPropertyChanged;

            host.NavRefresh?.Detach();
            host.SidebarSync?.Detach();
            host.ViewModel?.Dispose();
            host.Container.Shutdown();
        }
        catch (Exception ex)
        {
            AppLogger.Warn("MainWindowShutdown", "PerformCleanShutdown", ex);
        }
    }
}
