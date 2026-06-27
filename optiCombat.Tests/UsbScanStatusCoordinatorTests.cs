using optiCombat.Coordinators;
using optiCombat.Localization;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class UsbScanStatusCoordinatorTests
{
    public UsbScanStatusCoordinatorTests() => LocalizationService.ApplyCulture("fr-FR");

    [Fact]
    public void Handle_started_sets_refresh_status()
    {
        string? text = null;
        string? icon = null;

        UsbScanStatusCoordinator.Handle(
            new RemovableDriveScanStatusEventArgs(RemovableDriveScanPhase.Started, @"E:\", "USB", 0, 0),
            new UsbScanStatusCoordinator.Host
            {
                SetStatus = (t, _, _, i) => { text = t; icon = i; },
            });

        Assert.NotNull(text);
        Assert.Contains("USB", text);
        Assert.Equal(UiIconKinds.Refresh, icon);
    }

    [Fact]
    public void Handle_complete_with_threats_sets_warning()
    {
        bool isWarning = false;

        UsbScanStatusCoordinator.Handle(
            new RemovableDriveScanStatusEventArgs(RemovableDriveScanPhase.Completed, @"F:\", "Stick", 2, 12),
            new UsbScanStatusCoordinator.Host
            {
                SetStatus = (_, _, w, _) => isWarning = w,
            });

        Assert.True(isWarning);
    }

    [Fact]
    public void Handle_failed_sets_error()
    {
        bool isError = false;

        UsbScanStatusCoordinator.Handle(
            new RemovableDriveScanStatusEventArgs(RemovableDriveScanPhase.Failed, @"G:\", "SD", 0, 0),
            new UsbScanStatusCoordinator.Host
            {
                SetStatus = (_, e, _, _) => isError = e,
            });

        Assert.True(isError);
    }
}
