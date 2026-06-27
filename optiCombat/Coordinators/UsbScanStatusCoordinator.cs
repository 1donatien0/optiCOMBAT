using optiCombat.Localization;
using optiCombat.Services;

namespace optiCombat.Coordinators;

/// <summary>Messages de statut pour les analyses de lecteurs amovibles (USB).</summary>
public static class UsbScanStatusCoordinator
{
    public sealed class Host
    {
        public required Action<string, bool, bool, string?> SetStatus { get; init; }
    }

    public static void Handle(RemovableDriveScanStatusEventArgs e, Host host)
    {
        if (e.Phase == RemovableDriveScanPhase.Started)
        {
            host.SetStatus(
                LocalizationService.Format("Status_UsbScanStarting", e.DriveLabel),
                false,
                false,
                UiIconKinds.Refresh);
            return;
        }

        if (e.Phase == RemovableDriveScanPhase.Failed)
        {
            host.SetStatus(
                LocalizationService.Format("Status_UsbScanFailed", e.DriveLabel),
                true,
                false,
                null);
            return;
        }

        host.SetStatus(
            LocalizationService.Format("Status_UsbScanComplete", e.DriveLabel, e.FilesScanned, e.ThreatsFound),
            false,
            e.ThreatsFound > 0,
            e.ThreatsFound > 0 ? null : UiIconKinds.Success);
    }
}
