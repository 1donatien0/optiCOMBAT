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
        private static readonly string BackupRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiCombat", "SafetyBackups");

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
                var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
                var safeName = Path.GetFileName(threat.FilePath);
                var dest = Path.Combine(BackupRoot, $"{stamp}_{Guid.NewGuid():N}_{safeName}");
                File.Copy(threat.FilePath, dest, overwrite: false);
                AppLogger.Info("ThreatRemediation", $"Copie de sécurité : {PathRedaction.RedactPath(dest)}");
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ThreatRemediation", "TryCreateSafetyCopy", ex);
                return false;
            }
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
