using Microsoft.Win32;
using System.IO;
using System.Text.RegularExpressions;

namespace optiCombat.Services
{
    /// <summary>
    /// Périmètres optiCombat jamais analysés (scans, RTP, quarantaine auto) pour éviter
    /// l'auto-détection sur binaires, règles YARA, bases ClamAV et artefacts de MAJ.
    /// </summary>
    internal static class OpticombatProtectedPaths
    {
        private const string InnoUninstallGuid = @"F3A2C1D0-5B6E-4F7A-8C9D-0E1F2A3B4C5D";

        private static readonly Lazy<IReadOnlyList<string>> CachedRoots = new(
            ResolveDistinctRoots,
            LazyThreadSafetyMode.ExecutionAndPublication);

        /// <summary>%LOCALAPPDATA%\optiCombat — signatures ClamAV, quarantaine, logs, staging MAJ.</summary>
        public static string GetLocalAppDataRoot()
        {
            return Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiCombat"));
        }

        /// <summary>Racines protégées (installation + données applicatives).</summary>
        public static IReadOnlyList<string> GetProtectedRoots() => CachedRoots.Value;

        public static bool IsUnderProtectedPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;

            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            }
            catch
            {
                return false;
            }

            foreach (var root in CachedRoots.Value)
            {
                if (IsUnderRoot(fullPath, root))
                    return true;
            }

            return false;
        }

        /// <summary>Vrai si le dossier fait partie des exclusions obligatoires (non supprimables dans Options).</summary>
        public static bool IsMandatoryExcludedFolder(string? folderPath)
        {
            if (string.IsNullOrWhiteSpace(folderPath))
                return false;

            string norm;
            try
            {
                norm = Path.GetFullPath(folderPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            }
            catch
            {
                return false;
            }

            foreach (var root in CachedRoots.Value)
            {
                if (string.Equals(norm, root, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        public static IEnumerable<string> GetClamScanExcludePatterns()
        {
            foreach (var root in CachedRoots.Value)
            {
                var trimmed = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                yield return "^" + Regex.Escape(trimmed) + @"([\\/]|$)";
            }
        }

        private static IReadOnlyList<string> ResolveDistinctRoots()
        {
            var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            TryAddRoot(roots, AppInstallPaths.GetInstallRootUncached());
            TryAddRoot(roots, GetLocalAppDataRoot());

            TryAddProgramFilesInstall(roots);
            TryAddFromInnoUninstallRegistry(roots);
            TryAddDevWorkspaceRoot(roots);

            return roots.OrderBy(r => r, StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>Depot source en debug : rules/, scripts/, bin/ du projet exclus des scans.</summary>
        private static void TryAddDevWorkspaceRoot(HashSet<string> roots)
        {
            var install = AppInstallPaths.GetInstallRootUncached();
            if (install.IndexOf(@"\bin\", StringComparison.OrdinalIgnoreCase) < 0)
                return;

            try
            {
                var dir = new DirectoryInfo(install);
                for (var depth = 0; depth < 12 && dir != null; depth++, dir = dir.Parent)
                {
                    if (File.Exists(Path.Combine(dir.FullName, "optiCombat.sln")))
                    {
                        TryAddRoot(roots, dir.FullName);
                        break;
                    }
                }
            }
            catch
            {
                /* chemin invalide */
            }
        }

        private static void TryAddProgramFilesInstall(HashSet<string> roots)
        {
            foreach (var pf in new[]
                     {
                         Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                         Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                     })
            {
                if (string.IsNullOrWhiteSpace(pf))
                    continue;

                var candidate = Path.Combine(pf, "optiCombat");
                if (File.Exists(Path.Combine(candidate, "optiCombat.exe")))
                    TryAddRoot(roots, candidate);
            }
        }

        private static void TryAddFromInnoUninstallRegistry(HashSet<string> roots)
        {
            var subkeys = new[]
            {
                $@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{InnoUninstallGuid}_is1",
                $@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{InnoUninstallGuid}_is1",
            };

            foreach (var subkey in subkeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(subkey);
                    if (key?.GetValue("InstallLocation") is string location)
                        TryAddRoot(roots, location);
                }
                catch
                {
                    /* registre inaccessible */
                }
            }
        }

        private static void TryAddRoot(HashSet<string> roots, string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return;

            try
            {
                roots.Add(Path.GetFullPath(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)));
            }
            catch
            {
                /* chemin invalide */
            }
        }

        private static bool IsUnderRoot(string fullPath, string root)
        {
            if (fullPath.Equals(root, StringComparison.OrdinalIgnoreCase))
                return true;

            return fullPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || fullPath.StartsWith(root + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
    }
}
