using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Views;

namespace optiCombat.Coordinators;

/// <summary>Synchronise historique, dernière analyse et statistiques d'accueil.</summary>
public static class HistoryRefreshCoordinator
{
    public sealed class Host
    {
        public required ScanLogManager Logger { get; init; }
        public HistoryControl? HistoryPanel { get; init; }
        public OverviewControl? OverviewPanel { get; init; }
        public AntivirusView? AntivirusPanel { get; init; }
        public required Action RefreshOverviewProtection { get; init; }
    }

    public static void Refresh(Host host)
    {
        var sessions = host.Logger.GetHistory();
        host.HistoryPanel?.RefreshTimeline();
        ApplyLastScanSummary(host, sessions);
        host.OverviewPanel?.UpdateProtectionStatistics(sessions);
        host.RefreshOverviewProtection();
    }

    private static void ApplyLastScanSummary(Host host, IReadOnlyList<ScanSession> sessions)
    {
        ScanSession? last = sessions.Count == 0
            ? null
            : sessions.OrderByDescending(s => s.StartedAt).First();
        host.OverviewPanel?.UpdateLastScanSummary(last);
        host.AntivirusPanel?.UpdateLastScanDisplay(last?.StartedAt);
    }
}
