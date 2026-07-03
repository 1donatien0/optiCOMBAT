using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.ViewModels;

namespace optiCombat.Services;

public static class SignatureStatusSnapshotExtensions
{
    public static void ApplyToScanViewModel(this SignatureStatusSnapshot snapshot, ScanViewModel vm)
    {
        vm.DbVersion = snapshot.ClamDatabaseVersion;
        vm.RulesPackVersion = snapshot.YaraPackVersion;
        vm.LastUpdateDisplay = snapshot.ClamLastUpdateDisplay == "—"
            ? LocalizationService.GetString("Vm_Never")
            : snapshot.ClamLastUpdateDisplay;
        vm.RulesLastUpdateDisplay = snapshot.YaraLastUpdateDisplay == "—"
            ? LocalizationService.GetString("Vm_Never")
            : snapshot.YaraLastUpdateDisplay;
        vm.YaraRulesCount = snapshot.YaraRulesCount;
        vm.YaraStatus = snapshot.YaraIsAvailable
            ? LocalizationService.Format("Vm_YaraOperational", snapshot.YaraRulesCount)
            : LocalizationService.GetString("Vm_YaraUnavailable");
        vm.RefreshProtectionStatus();
    }
}
