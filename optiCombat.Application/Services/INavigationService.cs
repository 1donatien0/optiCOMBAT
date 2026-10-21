namespace optiCombat.Services;

/// <summary>Navigation entre panneaux — contrat UI-agnostique (implémentation WinUI).</summary>
public interface INavigationService
{
    string CurrentView { get; }

    event EventHandler<string>? Navigated;

    void NavigateTo(string name);

    bool HasPanel(string name);
}
