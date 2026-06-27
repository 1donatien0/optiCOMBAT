using optiCombat.Coordinators;
using optiCombat.Localization;

namespace optiCombat.Tests;

[Collection("Localization")]
public sealed class HistoryDetailCoordinatorTests
{
    public HistoryDetailCoordinatorTests() => LocalizationService.ApplyCulture("fr-FR");

    [Fact]
    public void HideDetailPanels_with_empty_view_does_not_throw()
    {
        HistoryDetailCoordinator.HideDetailPanels(new HistoryDetailView());
    }

    [Fact]
    public void ShowCleanDetail_with_null_session_and_empty_view_does_not_throw()
    {
        HistoryDetailCoordinator.ShowCleanDetail(new HistoryDetailView(), session: null);
    }
}
