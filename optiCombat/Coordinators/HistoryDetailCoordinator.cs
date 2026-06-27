using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.ViewModels;
using System.Windows;

namespace optiCombat.Coordinators;

/// <summary>Affichage des panneaux détail (scan, quarantaine, nettoyage) dans Historique.</summary>
public static class HistoryDetailCoordinator
{
    public static void HideDetailPanels(HistoryDetailView view)
    {
        if (view.ThreatsGrid != null)
        {
            view.ThreatsGrid.ItemsSource = null;
            view.ThreatsGrid.Visibility = Visibility.Collapsed;
        }

        if (view.CleanLogPanel != null)
            view.CleanLogPanel.Visibility = Visibility.Collapsed;
        if (view.QuarantineDetailPanel != null)
            view.QuarantineDetailPanel.Visibility = Visibility.Collapsed;
        if (view.NoThreatsState != null)
            view.NoThreatsState.Visibility = Visibility.Collapsed;
        if (view.ThreatsLegacyText != null)
            view.ThreatsLegacyText.Visibility = Visibility.Collapsed;
    }

    public static void ShowScanDetail(HistoryDetailView view, ScanSession? session, IReadOnlyList<HistoryThreatRow>? threatRows)
    {
        if (view.CleanLogPanel != null)
            view.CleanLogPanel.Visibility = Visibility.Collapsed;
        if (view.QuarantineDetailPanel != null)
            view.QuarantineDetailPanel.Visibility = Visibility.Collapsed;

        var hasStoredThreats = threatRows is { Count: > 0 };
        var sessionSelected = session != null;
        var legacyOnly = sessionSelected && session!.ThreatsFound > 0 && session.Threats.Count == 0;

        if (view.ThreatsGrid != null)
        {
            view.ThreatsGrid.ItemsSource = hasStoredThreats ? threatRows : null;
            view.ThreatsGrid.Visibility = hasStoredThreats ? Visibility.Visible : Visibility.Collapsed;
        }

        if (view.NoThreatsState != null)
        {
            view.NoThreatsState.Visibility = sessionSelected && !hasStoredThreats && !legacyOnly
                ? Visibility.Visible
                : Visibility.Collapsed;
        }

        if (view.ThreatsLegacyText != null)
            view.ThreatsLegacyText.Visibility = legacyOnly ? Visibility.Visible : Visibility.Collapsed;
    }

    public static void ShowQuarantineDetail(HistoryDetailView view, ActivityEntry entry)
    {
        if (view.ThreatsGrid != null)
            view.ThreatsGrid.Visibility = Visibility.Collapsed;
        if (view.CleanLogPanel != null)
            view.CleanLogPanel.Visibility = Visibility.Collapsed;
        if (view.NoThreatsState != null)
            view.NoThreatsState.Visibility = Visibility.Collapsed;
        if (view.ThreatsLegacyText != null)
            view.ThreatsLegacyText.Visibility = Visibility.Collapsed;

        if (view.QuarantineDetailPanel == null)
            return;

        view.QuarantineDetailPanel.Visibility = Visibility.Visible;
        var q = entry.QuarantineEntry;

        if (view.QuarTitle != null)
            view.QuarTitle.Text = q?.FileName ?? entry.TypeDisplay;
        if (view.QuarPath != null)
        {
            view.QuarPath.Text = q != null
                ? LocalizationService.Format("Hist_DetailQuarantinePath", q.OriginalPath)
                : entry.TargetDisplay;
        }
        if (view.QuarMeta != null && q != null)
            view.QuarMeta.Text = LocalizationService.Format("Hist_DetailQuarantineMeta", q.VirusName, q.SizeDisplay);
        if (view.QuarStatus != null)
        {
            view.QuarStatus.Text = entry.IsStillQuarantined
                ? LocalizationService.GetString("Hist_QuarantineStillActive")
                : LocalizationService.GetString("Hist_QuarantineHistorical");
        }
        if (view.BtnManageInAv != null)
            view.BtnManageInAv.IsEnabled = entry.IsStillQuarantined;
    }

    public static void ShowCleanDetail(HistoryDetailView view, CleanSession? session)
    {
        if (view.ThreatsGrid != null)
            view.ThreatsGrid.Visibility = Visibility.Collapsed;
        if (view.QuarantineDetailPanel != null)
            view.QuarantineDetailPanel.Visibility = Visibility.Collapsed;
        if (view.NoThreatsState != null)
            view.NoThreatsState.Visibility = Visibility.Collapsed;
        if (view.ThreatsLegacyText != null)
            view.ThreatsLegacyText.Visibility = Visibility.Collapsed;

        if (view.CleanLogPanel == null || view.CleanLogText == null)
            return;

        view.CleanLogPanel.Visibility = Visibility.Visible;
        if (session == null)
        {
            view.CleanLogText.Text = LocalizationService.GetString("Hist_DetailSelectClean");
            return;
        }

        view.CleanLogText.Text = !string.IsNullOrWhiteSpace(session.OperationLog)
            ? session.OperationLog
            : LocalizationService.Format(
                "Hist_DetailCleanSummary",
                session.TargetsSummary ?? string.Empty,
                session.BytesDisplay ?? string.Empty,
                session.DurationDisplay ?? string.Empty);
    }
}
