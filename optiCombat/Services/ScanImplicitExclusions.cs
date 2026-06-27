using System.IO;
using System.Text.RegularExpressions;

namespace optiCombat.Services
{
    /// <summary>
    /// Exclusions implicites (non saisies par l'utilisateur) : signatures AV/IDE et scripts temporaires.
    /// Centralise la logique pour scans, RTP et surveillance processus via <see cref="ExclusionSettings.IsFileExcluded"/>.
    /// </summary>
    internal static class ScanImplicitExclusions
    {
        private static readonly Regex CursorTempPs1 = new(
            @"^ps-script-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.ps1$",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly HashSet<string> SignatureDbExtensions = new(
            new[] { ".yar", ".yara", ".yarc", ".cvd", ".cld", ".cdb", ".ycf" },
            StringComparer.OrdinalIgnoreCase);

        public static bool IsImplicitlyExcluded(string? filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                return false;

            if (IsIdeTempPowerShell(filePath))
                return true;

            if (IsSignatureDatabaseFile(filePath))
                return true;

            return false;
        }

        /// <summary>Sous-dossiers optiCombat a lister dans Options (deja couverts par la racine AppData).</summary>
        public static IEnumerable<string> GetSignatureDataSubfolders()
        {
            var appData = OpticombatProtectedPaths.GetLocalAppDataRoot();
            foreach (var name in new[] { "clamav", "rules", "yara", "quarantine", "Logs", "staging" })
            {
                var path = Path.Combine(appData, name);
                if (Directory.Exists(path))
                    yield return path;
            }
        }

        private static bool IsIdeTempPowerShell(string filePath)
        {
            if (!filePath.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase))
                return false;

            if (!IsUnderAnyTempRoot(filePath))
                return false;

            var name = Path.GetFileName(filePath);
            if (CursorTempPs1.IsMatch(name))
                return true;

            if (name.StartsWith("ps-state-out-", StringComparison.OrdinalIgnoreCase))
                return true;

            if (name.StartsWith("__PSScriptPolicyTest_", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        private static bool IsSignatureDatabaseFile(string filePath)
        {
            if (!SignatureDbExtensions.Contains(Path.GetExtension(filePath)))
                return false;

            if (OpticombatProtectedPaths.IsUnderProtectedPath(filePath))
                return true;

            var parent = Path.GetFileName(Path.GetDirectoryName(filePath) ?? string.Empty);
            return parent.Equals("rules", StringComparison.OrdinalIgnoreCase)
                || parent.Equals("database", StringComparison.OrdinalIgnoreCase)
                || parent.Equals("clamav", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsUnderAnyTempRoot(string filePath)
        {
            foreach (var root in GetTempRoots())
            {
                if (IsUnderRoot(filePath, root))
                    return true;
            }

            return false;
        }

        private static IEnumerable<string> GetTempRoots()
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            void Add(string? path)
            {
                if (string.IsNullOrWhiteSpace(path))
                    return;
                try
                {
                    var full = Path.GetFullPath(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                    seen.Add(full);
                }
                catch
                {
                    /* ignore */
                }
            }

            Add(Path.GetTempPath());
            Add(Environment.GetEnvironmentVariable("TEMP"));
            Add(Environment.GetEnvironmentVariable("TMP"));
            Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Temp"));

            return seen;
        }

        private static bool IsUnderRoot(string filePath, string root)
        {
            try
            {
                var full = Path.GetFullPath(filePath);
                if (full.Equals(root, StringComparison.OrdinalIgnoreCase))
                    return true;

                return full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                    || full.StartsWith(root + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }
    }
}
