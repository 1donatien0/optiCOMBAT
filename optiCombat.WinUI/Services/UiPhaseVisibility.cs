using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace optiCombat.WinUI.Services;

/// <summary>Phases d'affichage Nettoyer et Antivirus (visibilité + ProgressRing).</summary>
public static class UiPhaseVisibility
{
    public static void ApplyCleanLogPhase(
        bool busy,
        bool empty,
        UIElement logScroll,
        UIElement emptyState,
        ProgressRing logProgress)
    {
        logScroll.Visibility = empty ? Visibility.Collapsed : Visibility.Visible;
        emptyState.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
        logProgress.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        logProgress.IsActive = busy;
    }

    public static void ApplyCleanActionPhase(bool busy, ProgressRing actionProgress)
    {
        actionProgress.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        actionProgress.IsActive = busy;
    }

    public static void ApplyAntivirusScanPhase(
        bool scanning,
        bool hasThreats,
        UIElement scanHubPanel,
        UIElement scanProgressPanel,
        UIElement threatsList,
        UIElement emptyThreatsState,
        UIElement quarantineAllButton,
        bool showScanLaunchers)
    {
        if (scanning)
        {
            scanHubPanel.Visibility = Visibility.Collapsed;
            scanProgressPanel.Visibility = Visibility.Visible;
            threatsList.Visibility = Visibility.Visible;
            emptyThreatsState.Visibility = Visibility.Collapsed;
            quarantineAllButton.Visibility = Visibility.Collapsed;
            return;
        }

        scanHubPanel.Visibility = showScanLaunchers ? Visibility.Visible : Visibility.Collapsed;
        scanProgressPanel.Visibility = Visibility.Collapsed;

        if (hasThreats)
        {
            threatsList.Visibility = Visibility.Visible;
            emptyThreatsState.Visibility = Visibility.Collapsed;
            quarantineAllButton.Visibility = Visibility.Visible;
        }
        else
        {
            threatsList.Visibility = Visibility.Collapsed;
            emptyThreatsState.Visibility = Visibility.Visible;
            quarantineAllButton.Visibility = Visibility.Collapsed;
        }
    }
}
