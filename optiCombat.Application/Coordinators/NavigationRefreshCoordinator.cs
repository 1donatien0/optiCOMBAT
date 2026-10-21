using optiCombat.Services;

namespace optiCombat.Coordinators;

/// <summary>
/// Rafraîchit les données de la section affichée à chaque navigation : les pages sont gardées en cache,
/// sans ce rafraîchissement elles montreraient l'état du premier affichage.
/// </summary>
public static class NavigationRefreshCoordinator
{
    public sealed class Host
    {
        public Func<Task>? RefreshOverviewAsync { get; init; }
        public Func<Task>? RefreshAntivirusAsync { get; init; }
        public Action? RefreshHistory { get; init; }
    }

    public static async Task ApplyAsync(string? sectionTag, Host host)
    {
        switch (ShellSections.Normalize(sectionTag))
        {
            case ShellSections.Overview:
                await InvokeAsync(host.RefreshOverviewAsync).ConfigureAwait(true);
                break;
            case ShellSections.Antivirus:
                await InvokeAsync(host.RefreshAntivirusAsync).ConfigureAwait(true);
                break;
            case ShellSections.History:
                try { host.RefreshHistory?.Invoke(); }
                catch (Exception ex) { AppLogger.Warn("NavigationRefreshCoordinator", "history", ex); }
                break;
        }
    }

    private static async Task InvokeAsync(Func<Task>? refresh)
    {
        if (refresh == null)
            return;
        try
        {
            await refresh().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("NavigationRefreshCoordinator", "refresh", ex);
        }
    }
}
