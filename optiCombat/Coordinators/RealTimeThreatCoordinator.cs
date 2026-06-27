using optiCombat.Models;
using optiCombat.ViewModels;

namespace optiCombat.Coordinators;

/// <summary>Menaces RTP / processus / USB remontées dans le ViewModel et l'accueil.</summary>
public static class RealTimeThreatCoordinator
{
    public sealed class Host
    {
        public ScanViewModel? ViewModel { get; init; }
        public required Action RefreshQuarantineList { get; init; }
        public required Action RefreshOverviewProtection { get; init; }
    }

    public static void Handle(ThreatInfo threat, Host host)
    {
        host.ViewModel?.AppendLiveThreat(threat);
        host.RefreshQuarantineList();
        host.RefreshOverviewProtection();
    }
}
