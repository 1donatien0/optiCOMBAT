using System.Windows;
using System.Windows.Controls;

namespace optiCombat.Coordinators;

/// <summary>Références UI des panneaux détail Historique (remplies par <see cref="optiCombat.Views.HistoryControl"/>).</summary>
public sealed class HistoryDetailView
{
    public DataGrid? ThreatsGrid { get; init; }
    public FrameworkElement? CleanLogPanel { get; init; }
    public TextBlock? CleanLogText { get; init; }
    public FrameworkElement? QuarantineDetailPanel { get; init; }
    public TextBlock? QuarTitle { get; init; }
    public TextBlock? QuarPath { get; init; }
    public TextBlock? QuarMeta { get; init; }
    public TextBlock? QuarStatus { get; init; }
    public System.Windows.Controls.Button? BtnManageInAv { get; init; }
    public FrameworkElement? NoThreatsState { get; init; }
    public FrameworkElement? ThreatsLegacyText { get; init; }
}
