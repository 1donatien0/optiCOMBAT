using optiCombat.Localization;
using optiCombat.Models;

namespace optiCombat.Strings
{
    /// <summary>
    /// Centralise les chaînes utilisées par l'UI (IDs de navigation, URLs, messages récurrents).
    /// Les libellés affichés passent par <see cref="LocalizationService"/> (fr-FR / en-US).
    /// </summary>
    public static class OpticombatStrings
    {
        public static class PanelIds
        {
            public const string Overview = "Overview";
            public const string Clean = "Clean";
            public const string Antivirus = "Antivirus";
            public const string History = "History";
            public const string Options = "Options";
        }

        public static class ActionIds
        {
            public const string Update = "Update";
        }

        public static class Urls
        {
            public const string OpticombatWebsite = "https://sourceforge.net/projects/opticombat/";
            public const string OpticombatSourceForge = "https://sourceforge.net/projects/opticombat/";
            public const string YaraForgeApiLatest = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest";
            public const string ClamAvRootCertRaw = "https://raw.githubusercontent.com/Cisco-Talos/clamav/main/certs/clamav.crt";
        }

        public static class Confirmations
        {
            public static string Title => LocalizationService.GetString("Common_Confirmation");

            public static string QuarantineAll(int count) =>
                LocalizationService.Format("Confirm_QuarantineAll", count);

            public static string PurgeQuarantine(int count) =>
                LocalizationService.Format("Confirm_PurgeQuarantine", count);
        }

        public static class UiMessages
        {
            public static string ProtectionActive => LocalizationService.GetString("Ui_ProtectionActive");
            public static string ProtectionReducedTray => LocalizationService.GetString("Ui_ProtectionTray");
            public static string AnalyseInterrompueSurDemande => LocalizationService.GetString("Ui_ScanInterrupted");
            public static string RestoreFromQuarantineSuccess => LocalizationService.GetString("Ui_RestoreOk");
            public static string RestoreFromQuarantineError => LocalizationService.GetString("Ui_RestoreError");
            public static string DeleteThreatPermanentlySuccess => LocalizationService.GetString("Ui_DeleteOk");
            public static string DeleteThreatPermanentlyError => LocalizationService.GetString("Ui_DeleteError");
        }

        public static class StatusUpdates
        {
            public static string SignaturesUpdateAlreadyRunning => LocalizationService.GetString("Status_SigUpdateRunning");
            public static string SignaturesUpdateInProgress => LocalizationService.GetString("Status_SigUpdateProgress");
            public static string RulesUpdateInProgress => LocalizationService.GetString("Status_RulesUpdateProgress");
            public static string FullSignaturesUpdateStarting => LocalizationService.GetString("Status_FullUpdateStart");
            public static string SignaturesUpdateFinishedSuccess => LocalizationService.GetString("Status_SigUpdateOk");
            public static string SignaturesUpdateFinishedError => LocalizationService.GetString("Status_SigUpdateFail");
            public static string FullSignaturesUpdateFinished => LocalizationService.GetString("Status_FullUpdateDone");
            public static string FullSignaturesUpdateFinishedWithErrors => LocalizationService.GetString("Status_FullUpdatePartial");
            public static string SignaturesUpdateStopping => LocalizationService.GetString("Status_SigUpdateStop");
        }
    }
}
