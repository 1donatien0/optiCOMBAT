using Microsoft.Win32;
using optiCombat.Localization;
using System.Runtime.Versioning;

namespace optiCombat.Services
{
    public enum PostureFixStatus { Done, NeedsRestart, Cancelled, Failed, NotSupported }

    public sealed record PostureFixResult(PostureFixStatus Status, string Message);

    /// <summary>
    /// Corrections en un clic des contrôles du score de sécurité (identifiants de
    /// <see cref="SecurityPostureService"/>). Au plus une invite UAC par correction, toujours précédée
    /// d'une confirmation pour les changements système. Les contrôles non corrigeables ici
    /// (Windows Update) gardent leur lien <c>FixUri</c> vers les Paramètres Windows.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class PostureFixService
    {
        public const string FirewallCommand = "netsh advfirewall set allprofiles state on";
        public const string UacCommand =
            @"reg add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"" /v EnableLUA /t REG_DWORD /d 1 /f";

        /// <summary>Vrai si le contrôle peut être corrigé directement par l'application.</summary>
        public static bool CanAutoFix(string? checkId) => checkId is
            "firewall" or "uac" or "shares" or "opticombat" or "scan" or "sigauto";

        /// <param name="confirm">(message, titre) → accord de l'utilisateur.</param>
        /// <param name="startQuickScan">Lance une analyse rapide (contrôle « scan »).</param>
        /// <param name="runElevated">Injection pour les tests ; par défaut <see cref="ElevatedCommandRunner"/>.</param>
        public static async Task<PostureFixResult> FixAsync(
            string checkId,
            ServiceContainer container,
            Func<string, string, bool> confirm,
            Func<Task>? startQuickScan = null,
            Func<IReadOnlyList<string>, bool>? runElevated = null)
        {
            runElevated ??= cmds => ElevatedCommandRunner.RunElevatedBatch(cmds, waitForExit: true);
            try
            {
                switch (checkId)
                {
                    case "firewall":
                        return await RunAdminAsync(confirm, runElevated,
                            LocalizationService.GetString("Posture_FixConfirmFirewall"), [FirewallCommand], false).ConfigureAwait(false);

                    case "uac":
                        return await RunAdminAsync(confirm, runElevated,
                            LocalizationService.GetString("Posture_FixConfirmUac"), [UacCommand], true).ConfigureAwait(false);

                    case "shares":
                    {
                        var commands = BuildShareDeleteCommands(ListUserShares(), out var names);
                        if (commands.Count == 0)
                            return new(PostureFixStatus.Done, LocalizationService.GetString("Posture_FixDone"));
                        return await RunAdminAsync(confirm, runElevated,
                            LocalizationService.Format("Posture_FixConfirmShares", string.Join(", ", names)), commands, false).ConfigureAwait(false);
                    }

                    case "opticombat":
                        container.ApplyRealtimeProtection(true);
                        return new(PostureFixStatus.Done, LocalizationService.GetString("Posture_FixDone"));

                    case "sigauto":
                        container.ApplySignatureAutoUpdate(true);
                        return new(PostureFixStatus.Done, LocalizationService.GetString("Posture_FixDone"));

                    case "scan":
                        if (startQuickScan == null)
                            return new(PostureFixStatus.NotSupported, string.Empty);
                        _ = startQuickScan();
                        return new(PostureFixStatus.Done, LocalizationService.GetString("Posture_FixScanStarted"));

                    default:
                        return new(PostureFixStatus.NotSupported, string.Empty);
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("PostureFixService", $"Correction {checkId}", ex);
                return new(PostureFixStatus.Failed, LocalizationService.Format("Posture_FixFailed", ex.Message));
            }
        }

        /// <summary>
        /// Commandes <c>net share … /delete</c> ; les noms contenant des métacaractères cmd.exe sont ignorés
        /// (jamais injectés dans la ligne de commande élevée).
        /// </summary>
        public static List<string> BuildShareDeleteCommands(IEnumerable<string> shareNames, out List<string> acceptedNames)
        {
            acceptedNames = new List<string>();
            var commands = new List<string>();
            foreach (var name in shareNames)
            {
                if (name.EndsWith('$') || !ElevatedCommandRunner.IsSafeArgument(name))
                    continue;
                acceptedNames.Add(name);
                commands.Add($"net share \"{name}\" /delete /y");
            }
            return commands;
        }

        private static async Task<PostureFixResult> RunAdminAsync(
            Func<string, string, bool> confirm,
            Func<IReadOnlyList<string>, bool> runElevated,
            string message,
            IReadOnlyList<string> commands,
            bool needsRestart)
        {
            if (!confirm(message, LocalizationService.GetString("Posture_Title")))
                return new(PostureFixStatus.Cancelled, LocalizationService.GetString("Posture_FixCancelled"));

            var ok = await Task.Run(() => runElevated(commands)).ConfigureAwait(false);
            if (!ok)
                return new(PostureFixStatus.Cancelled, LocalizationService.GetString("Posture_FixCancelled"));

            return needsRestart
                ? new(PostureFixStatus.NeedsRestart, LocalizationService.GetString("Posture_FixNeedsRestart"))
                : new(PostureFixStatus.Done, LocalizationService.GetString("Posture_FixDone"));
        }

        /// <summary>Partages réseau créés par l'utilisateur (hors partages administratifs <c>$</c>).</summary>
        internal static List<string> ListUserShares()
        {
            var result = new List<string>();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\lanmanserver\Shares");
                if (key == null)
                    return result;
                foreach (var name in key.GetValueNames())
                {
                    if (!name.EndsWith('$') && SecurityPostureService.ShareRegistryValueIndicatesUserPath(key.GetValue(name)))
                        result.Add(name);
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("PostureFixService", "ListUserShares", ex);
            }
            return result;
        }
    }
}
