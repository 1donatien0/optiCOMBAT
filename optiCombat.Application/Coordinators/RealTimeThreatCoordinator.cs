using optiCombat.Localization;
using optiCombat.Models;

namespace optiCombat.Coordinators;

/// <summary>Menace remontée par la protection temps réel, la surveillance des processus ou l'analyse USB.</summary>
public static class RealTimeThreatCoordinator
{
    public sealed class Host
    {
        public required Action<string> SetStatus { get; init; }
        public Action? RefreshProtectionBadge { get; init; }
        public Action? RefreshQuarantineList { get; init; }
        public Action? RefreshOverview { get; init; }
    }

    public static void Handle(ThreatInfo threat, Host host)
    {
        host.RefreshProtectionBadge?.Invoke();
        host.SetStatus(LocalizationService.Format("Rtp_ThreatToastTitle", threat.VirusName));
        host.RefreshQuarantineList?.Invoke();
        host.RefreshOverview?.Invoke();
    }
}
