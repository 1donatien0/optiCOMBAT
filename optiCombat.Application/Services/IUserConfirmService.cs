namespace optiCombat.Services;

/// <summary>
/// Confirmations et messages utilisateur, découplés de l'UI (boîte de dialogue native côté WinUI,
/// doublure dans les tests). Toute action destructive (suppression définitive) doit passer par
/// <see cref="ConfirmYesNo"/>.
/// </summary>
public interface IUserConfirmService
{
    bool ConfirmYesNo(string message, string title, bool warning = true);

    void Inform(string message, string title);

    void Warn(string message, string title);
}

/// <summary>Refuse toute confirmation (headless, ou shell pas encore initialisé) : aucune action destructive silencieuse.</summary>
public sealed class DeclineUserConfirmService : IUserConfirmService
{
    public static DeclineUserConfirmService Instance { get; } = new();

    public bool ConfirmYesNo(string message, string title, bool warning = true) => false;

    public void Inform(string message, string title) { }

    public void Warn(string message, string title) { }
}
