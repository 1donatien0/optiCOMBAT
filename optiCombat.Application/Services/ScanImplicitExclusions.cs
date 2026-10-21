using System.IO;

namespace optiCombat.Services
{
    /// <summary>
    /// Exclusions implicites (non saisies par l'utilisateur) : signatures AV/IDE et scripts temporaires.
    /// Centralise la logique pour scans, RTP et surveillance processus via <see cref="ExclusionSettings.IsFileExcluded"/>.
    /// </summary>
    internal static class ScanImplicitExclusions
    {
        /// <summary>
        /// Taille max d'un fichier <c>__PSScriptPolicyTest_*.ps1</c> légitime : PowerShell y écrit une
        /// seule ligne de commentaire pour tester AppLocker.
        /// </summary>
        internal const long MaxPolicyTestFileBytes = 128;

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

            // Audit 360 : les exclusions par NOM seul (« ps-script-<guid>.ps1 », « ps-state-out-* »)
            // permettaient à un dropper déposé dans %TEMP% d'échapper à la protection temps réel en
            // adoptant ce nom. Elles sont retirées (les faux positifs qui les motivaient venaient des
            // règles YARA corrigées). Seul le fichier-témoin AppLocker de PowerShell reste exclu, et
            // uniquement s'il a la taille d'un témoin (une ligne de commentaire).
            var name = Path.GetFileName(filePath);
            if (name.StartsWith("__PSScriptPolicyTest_", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var info = new FileInfo(filePath);
                    return info.Exists && info.Length <= MaxPolicyTestFileBytes;
                }
                catch (IOException) { return false; }
                catch (UnauthorizedAccessException) { return false; }
            }

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
