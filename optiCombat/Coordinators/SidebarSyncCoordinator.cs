using optiCombat.Services;

namespace optiCombat.Coordinators;

/// <summary>
/// Synchronise la sélection des RadioButton de la sidebar quand la navigation change
/// (évite la boucle Navigated ↔ Checked).
/// </summary>
public sealed class SidebarSyncCoordinator
{
    private readonly INavigationService _navigation;
    private readonly Action<Action> _invokeOnUi;
    private readonly IReadOnlyDictionary<string, Action> _selectSidebarItem;
    private bool _isSyncing;

    public bool IsSyncing => _isSyncing;

    public SidebarSyncCoordinator(
        INavigationService navigation,
        Action<Action> invokeOnUi,
        IReadOnlyDictionary<string, Action> selectSidebarItem)
    {
        _navigation = navigation;
        _invokeOnUi = invokeOnUi;
        _selectSidebarItem = selectSidebarItem;
        _navigation.Navigated += OnNavigated;
    }

    public void Detach() => _navigation.Navigated -= OnNavigated;

    /// <summary>Exposé aux tests (sans Dispatcher).</summary>
    internal void ApplySync(string panelName) => Sync(panelName);

    private void OnNavigated(object? sender, string panelName) =>
        _invokeOnUi(() => Sync(panelName));

    private void Sync(string panelName)
    {
        if (!_selectSidebarItem.TryGetValue(panelName, out var select))
            return;

        _isSyncing = true;
        try
        {
            select();
        }
        finally
        {
            _isSyncing = false;
        }
    }
}
