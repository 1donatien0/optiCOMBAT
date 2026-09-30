using Moq;
using optiCombat.Coordinators;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Strings;

namespace optiCombat.Tests;

public sealed class ToastActivationCoordinatorTests
{
    [Fact]
    public void Handle_history_navigates_to_history_panel()
    {
        string? navigated = null;
        var nav = new Mock<INavigationService>();
        nav.Setup(n => n.NavigateTo(It.IsAny<string>())).Callback<string>(id => navigated = id);

        var services = new Mock<IViewServices>();

        var host = new ToastActivationCoordinator.Host
        {
            Services = services.Object,
            Navigation = nav.Object,
            ShowWindow = () => { },
            SetStatus = (_, _, _) => { },
            RefreshQuarantineList = () => { },
            RefreshAntivirusView = () => { },
            SelectAntivirusScanTab = () => { },
            SelectAntivirusQuarantineTab = () => { },
            SelectAntivirusSignaturesTab = () => { },
            TriggerManualSignatureUpdate = () => { },
        };

        ToastActivationCoordinator.Handle(new ToastActivationEventArgs("history", null, null), host);
        Assert.Equal(OpticombatStrings.PanelIds.History, navigated);
    }
}
