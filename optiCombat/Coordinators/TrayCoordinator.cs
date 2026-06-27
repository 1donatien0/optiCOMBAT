using optiCombat.Services;

namespace optiCombat.Coordinators;

/// <summary>
/// Vie du tray Windows : icône, menu contextuel, callbacks afficher / quitter.
/// </summary>
public sealed class TrayCoordinator : IDisposable
{
    private SystemTrayHost? _trayHost;
    private bool _disposed;

    public void Initialize(Action showMainWindow, Action exitApplication)
    {
        _trayHost ??= new SystemTrayHost();
        _trayHost.Initialize(showMainWindow, exitApplication);
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _trayHost?.Dispose();
        _trayHost = null;
    }
}
