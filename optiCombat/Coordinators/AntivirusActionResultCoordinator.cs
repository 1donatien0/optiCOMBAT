using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Views;

namespace optiCombat.Coordinators;

/// <summary>Statut et rafraîchissements après une action antivirus (quarantaine, ignore, etc.).</summary>
public static class AntivirusActionResultCoordinator
{
    public sealed class Host
    {
        public required Action<string, bool, bool> SetStatus { get; init; }
        public required Action RefreshQuarantineList { get; init; }
        public required Action RefreshHistory { get; init; }
        public AntivirusView? AntivirusPanel { get; init; }
    }

    public static void Handle(ActionResult result, Host host)
    {
        host.SetStatus(result.Message, result.IsError, result.IsWarning);
        if (!result.Success)
            return;

        host.RefreshQuarantineList();
        host.RefreshHistory();
        host.AntivirusPanel?.RefreshAllData();
    }
}
