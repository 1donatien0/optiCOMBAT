using System.IO;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace optiCombat.Services
{
    /// <summary>
    /// Restreint l'ACL des dossiers de données optiCombat : propriétaire courant, SYSTEM et
    /// Administrateurs uniquement, héritage rompu (retire le groupe Users hérité).
    /// <para>
    /// La quarantaine et, si l'utilisateur ajoute les exclusions Windows Defender,
    /// <c>%LocalAppData%\optiCombat</c> ne sont plus analysés par Defender : sans ce durcissement,
    /// un autre compte local pourrait y déposer une charge utile hors de portée de l'analyse.
    /// </para>
    /// Best-effort : une erreur est journalisée sans interrompre l'application ; si le
    /// propriétaire n'est pas identifiable, aucune ACL n'est posée (pour ne pas se verrouiller dehors).
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class DirectoryHardening
    {
        /// <summary>Applique l'ACL restrictive. Idempotent, sûr à chaque démarrage. Retourne vrai si appliquée.</summary>
        public static bool HardenDataDirectory(string directory)
        {
            if (!OperatingSystem.IsWindows())
                return false;
            if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
                return false;

            try
            {
                var owner = WindowsIdentity.GetCurrent().User;
                if (owner == null)
                {
                    AppLogger.Warn("DirectoryHardening", $"Propriétaire introuvable, durcissement ignoré : {PathRedaction.RedactPath(directory)}");
                    return false;
                }

                var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

                var security = new DirectorySecurity();
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                foreach (var sid in new[] { owner, system, admins })
                {
                    security.AddAccessRule(new FileSystemAccessRule(
                        sid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
                }

                new DirectoryInfo(directory).SetAccessControl(security);
                AppLogger.Debug("DirectoryHardening", $"ACL restreinte appliquée : {PathRedaction.RedactPath(directory)}");
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("DirectoryHardening", $"Durcissement ACL ignoré : {PathRedaction.RedactPath(directory)}", ex);
                return false;
            }
        }
    }
}
