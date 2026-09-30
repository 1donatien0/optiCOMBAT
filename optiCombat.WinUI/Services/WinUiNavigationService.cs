using optiCombat.Services;
using optiCombat.Strings;

namespace optiCombat.WinUI.Services;

/// <summary>Navigation WinUI mappée sur les IDs de panneaux partagés.</summary>
public sealed class WinUiNavigationService : INavigationService
{
    private static readonly Dictionary<string, string> TagByPanelId = new(StringComparer.OrdinalIgnoreCase)
    {
        [OpticombatStrings.PanelIds.Overview] = "overview",
        [OpticombatStrings.PanelIds.Clean] = "clean",
        [OpticombatStrings.PanelIds.Antivirus] = "antivirus",
        [OpticombatStrings.PanelIds.History] = "history",
        [OpticombatStrings.PanelIds.Options] = "options",
    };

    private readonly Action<string> _navigate;

    public WinUiNavigationService(Action<string> navigate) => _navigate = navigate;

    public string CurrentView { get; private set; } = OpticombatStrings.PanelIds.Overview;

    public event EventHandler<string>? Navigated;

    public void NavigateTo(string name)
    {
        var tag = TagByPanelId.TryGetValue(name, out var mapped) ? mapped : name.ToLowerInvariant();
        CurrentView = name;
        _navigate(tag);
        Navigated?.Invoke(this, name);
    }

    public bool HasPanel(string name) => TagByPanelId.ContainsKey(name);
}
