using System.ComponentModel;
using optiCombat.Strings;

namespace optiCombat.Coordinators;

/// <summary>Réduit la fenêtre au systray (minimize / fermeture) sans arrêter la protection.</summary>
public static class WindowTrayBehaviorCoordinator
{
    public sealed class Host
    {
        public required Action HideWindow { get; init; }
        public required Action<string> SetTrayStatus { get; init; }
    }

    public static void OnMinimized(Host host)
    {
        host.HideWindow();
        host.SetTrayStatus(OpticombatStrings.UiMessages.ProtectionReducedTray);
    }

    /// <returns><c>true</c> si la fermeture a été annulée (masquage systray).</returns>
    public static bool TryCancelClose(bool explicitExit, CancelEventArgs e, Host host)
    {
        if (explicitExit)
            return false;

        e.Cancel = true;
        host.HideWindow();
        host.SetTrayStatus(OpticombatStrings.UiMessages.ProtectionReducedTray);
        return true;
    }
}
