using System.IO;
using System.Text.RegularExpressions;
using optiCombat.Localization;
using optiCombat.Models;

namespace optiCombat.Services
{
    /// <summary>
    /// Textes visibles pendant un scan : une seule « analyse optiCombat », sans exposer
    /// les moteurs internes (ClamAV, YARA, etc.) — comme les suites grand public multi-moteurs.
    /// </summary>
    internal static class ScanUserDisplay
    {
        private static readonly Regex FileCountInMessageRegex = new(
            @"(\d[\d\s]*\s*fichiers?\s*analys|\d[\d\s]*\s*files?\s*scann)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);

        public static string ScanStarting(ScanType type, string? path = null) => type switch
        {
            ScanType.QuickScan => LocalizationService.GetString("Scan_QuickStarting"),
            ScanType.FullScan => LocalizationService.GetString("Scan_FullStarting"),
            ScanType.Folder => LocalizationService.Format("Scan_FolderStarting", path ?? ""),
            ScanType.File => LocalizationService.Format("Scan_FileStarting", Path.GetFileName(path ?? "")),
            _ => LocalizationService.GetString("Scan_DefaultStarting"),
        };

        public static string Preparation => LocalizationService.GetString("Scan_Preparation");
        public static string Ready => LocalizationService.GetString("Scan_Ready");
        public static string ReadyDegraded => LocalizationService.GetString("Scan_ReadyDegraded");

        /// <summary>Convertit un message technique de progression en libellé utilisateur.</summary>
        public static string ForProgressMessage(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return LocalizationService.GetString("Scan_InProgress");

            var m = StripEnginePrefixes(raw.Trim());

            if (m.StartsWith("Cible ", StringComparison.OrdinalIgnoreCase))
                m = LocalizationService.GetString("Scan_ZonePrefix") + m["Cible ".Length..];
            else if (m.StartsWith("Target ", StringComparison.OrdinalIgnoreCase))
                m = LocalizationService.GetString("Scan_ZonePrefix") + m["Target ".Length..];

            if (m.StartsWith("scan récursif de", StringComparison.OrdinalIgnoreCase)
                || m.StartsWith("démarrage", StringComparison.OrdinalIgnoreCase)
                || m.StartsWith("règle ", StringComparison.OrdinalIgnoreCase)
                || m.StartsWith("recursive scan", StringComparison.OrdinalIgnoreCase)
                || m.StartsWith("starting", StringComparison.OrdinalIgnoreCase)
                || m.StartsWith("rule ", StringComparison.OrdinalIgnoreCase))
                return LocalizationService.GetString("Scan_InProgress");

            if (FileCountInMessageRegex.IsMatch(m))
                return m;

            return m;
        }

        /// <summary>
        /// Remplace un compteur local dans le message (ex. fin de zone ClamAV) par le cumul session.
        /// </summary>
        public static string SyncFileCountInMessage(string? raw, int cumulativeFilesScanned)
        {
            var m = ForProgressMessage(raw);
            if (cumulativeFilesScanned <= 0)
                return m;

            if (FileCountInMessageRegex.IsMatch(m))
                return LocalizationService.Format("Scan_FilesProgress", cumulativeFilesScanned);

            return m;
        }

        private static string StripEnginePrefixes(string message)
        {
            var m = message;
            if (m.Length > 0 && m[0] == '[')
            {
                var close = m.IndexOf(']');
                if (close > 0)
                    m = m[(close + 1)..].Trim();
            }

            foreach (var prefix in new[] { "ClamAV — ", "ClamAV : ", "YARA — ", "YARA : " })
            {
                if (m.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    m = m[prefix.Length..].Trim();
                    break;
                }
            }

            return m;
        }
    }
}
