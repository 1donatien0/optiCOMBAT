using optiCombat.Localization;
using optiCombat.Models;
using System.IO;

namespace optiCombat.Services
{
    /// <summary>
    /// Sauvegarde optionnelle avant quarantaine et conseils de remédiation (ClamAV = détection, pas réparation binaire).
    /// </summary>
    public static class ThreatRemediationService
    {
        /// <summary>%LOCALAPPDATA%\optiCombat\SafetyBackups (redirigé en test par <see cref="OpticombatDataRoots"/>).</summary>
        internal static string BackupRoot => OpticombatDataRoots.LocalFile("SafetyBackups");

        /// <summary>Extension des copies de sécurité neutralisées.</summary>
        internal const string SafetyCopyExtension = ".ocsafe";

        /// <summary>Masque appliqué octet par octet aux copies (même valeur que l'ancien format de quarantaine).</summary>
        internal const byte SafetyCopyMask = 0x5A;

        /// <summary>
        /// Copie de sécurité d'un fichier avant quarantaine, <b>neutralisée</b> : contenu masqué
        /// (XOR <see cref="SafetyCopyMask"/>) et extension <see cref="SafetyCopyExtension"/>.
        /// </summary>
        /// <remarks>
        /// Le dossier SafetyBackups est sous la racine de données optiCombat, exclue des scans de
        /// l'application et, si l'utilisateur les a ajoutées, des exclusions Defender. Une copie en
        /// clair avec son extension d'origine restait donc un exécutable actif que rien ne scannait.
        /// Pour récupérer l'original : appliquer le même XOR (voir <see cref="DecodeSafetyCopy"/>).
        /// </remarks>
        public static bool TryCreateSafetyCopy(ThreatInfo threat)
        {
            if (string.IsNullOrWhiteSpace(threat.FilePath) || !File.Exists(threat.FilePath))
                return false;

            try
            {
                var info = new FileInfo(threat.FilePath);
                if (info.Length > 32L * 1024 * 1024)
                    return false;

                Directory.CreateDirectory(BackupRoot);
                var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss", System.Globalization.CultureInfo.InvariantCulture);
                var safeName = Path.GetFileName(threat.FilePath);
                var dest = Path.Combine(BackupRoot, $"{stamp}_{Guid.NewGuid():N}_{safeName}{SafetyCopyExtension}");
                var bytes = File.ReadAllBytes(threat.FilePath);
                for (var i = 0; i < bytes.Length; i++)
                    bytes[i] ^= SafetyCopyMask;
                using (var fs = new FileStream(dest, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    fs.Write(bytes, 0, bytes.Length);
                AppLogger.Info("ThreatRemediation", $"Copie de sécurité (neutralisée) : {PathRedaction.RedactPath(dest)}");
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ThreatRemediation", "TryCreateSafetyCopy", ex);
                return false;
            }
        }

        /// <summary>Contenu d'origine d'une copie de sécurité neutralisée.</summary>
        public static byte[] DecodeSafetyCopy(string safetyCopyPath)
        {
            var bytes = File.ReadAllBytes(safetyCopyPath);
            for (var i = 0; i < bytes.Length; i++)
                bytes[i] ^= SafetyCopyMask;
            return bytes;
        }

        public static IReadOnlyList<string> GetRemediationSteps(ThreatInfo threat)
        {
            var steps = new List<string>
            {
                LocalizationService.GetString("Remed_Step_Quarantine"),
            };

            if (RiskyFileExtensions.IsExecutable(threat.FilePath))
                steps.Add(LocalizationService.GetString("Remed_Step_NoRun"));

            if (string.Equals(threat.DetectedBy, "YARA", StringComparison.OrdinalIgnoreCase))
                steps.Add(LocalizationService.GetString("Remed_Step_YaraReview"));

            steps.Add(LocalizationService.GetString("Remed_Step_Restore"));
            steps.Add(LocalizationService.GetString("Remed_Step_NoRepairNote"));
            return steps;
        }
    }
}
