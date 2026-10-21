using optiCombat.Localization;
using optiCombat.Services;

namespace optiCombat.Coordinators;

/// <summary>Message de statut pour l'analyse d'un lecteur amovible (USB / SD).</summary>
public static class UsbScanStatusCoordinator
{
    public readonly record struct StatusMessage(string Text, bool IsError, bool IsWarning);

    public static StatusMessage Describe(RemovableDriveScanStatusEventArgs e) => e.Phase switch
    {
        RemovableDriveScanPhase.Started =>
            new(LocalizationService.Format("Status_UsbScanStarting", e.DriveLabel), false, false),
        RemovableDriveScanPhase.Failed =>
            new(LocalizationService.Format("Status_UsbScanFailed", e.DriveLabel), true, false),
        _ => new(
            LocalizationService.Format("Status_UsbScanComplete", e.DriveLabel, e.FilesScanned, e.ThreatsFound),
            false,
            e.ThreatsFound > 0),
    };
}
