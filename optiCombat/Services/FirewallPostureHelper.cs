using Microsoft.Win32;
using System.Runtime.Versioning;

namespace optiCombat.Services
{
    /// <summary>
    /// Vérifie le pare-feu Windows sur les trois profils GPO (domaine, privé, public).
    /// Ne se limite pas à <c>StandardProfile</c>, ce qui évite un faux positif sur poste joint au domaine.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class FirewallPostureHelper
    {
        private const string FirewallPolicyBase =
            @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

        private static readonly string[] ProfileSubKeys =
        {
            "DomainProfile",
            "StandardProfile",
            "PublicProfile",
        };

        /// <summary>
        /// <c>true</c> si chaque profil présent dans le registre a <c>EnableFirewall</c> actif.
        /// </summary>
        public static bool IsFirewallEnabledOnAllProfiles()
        {
            bool anyProfile = false;

            foreach (var profile in ProfileSubKeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey($"{FirewallPolicyBase}\\{profile}");
                    if (key == null)
                        continue;

                    anyProfile = true;
                    if (key.GetValue("EnableFirewall") is not int enabled || enabled == 0)
                        return false;
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("FirewallPosture", profile, ex);
                    return false;
                }
            }

            return anyProfile;
        }
    }
}
