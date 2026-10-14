using optiCombat.Services;

namespace optiCombat.Coordinators;

/// <summary>
/// Après une action antivirus (quarantaine, restauration, suppression, ignorer) : statut, puis
/// rafraîchissement des vues qui affichent les mêmes données (quarantaine, historique, accueil).
/// </summary>
public static class AntivirusActionResultCoordinator
{
    public sealed class Host
    {
        public required Action<string, bool, bool> SetStatus { get; init; }
        public Action? RefreshQuarantineList { get; init; }
        public Action? RefreshHistory { get; init; }
        public Action? RefreshOverview { get; init; }
    }

    public static void Handle(ActionResult result, Host host)
    {
        host.SetStatus(result.Message, result.IsError, result.IsWarning);
        if (!result.Success)
            return;

        host.RefreshQuarantineList?.Invoke();
        host.RefreshHistory?.Invoke();
        host.RefreshOverview?.Invoke();
    }
}
