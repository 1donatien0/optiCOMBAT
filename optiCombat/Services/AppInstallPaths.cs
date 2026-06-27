using System.IO;
using System.Text.RegularExpressions;

namespace optiCombat.Services
{
    /// <summary>
    /// Répertoire racine du processus optiCombat en cours (publish / install / debug).
    /// Sert à exclure implicitement ce périmètre des scans et de la RTP pour éviter
    /// les auto-détections (règles YARA, binaires YARA, bases ClamAV embarquées).
    /// </summary>
    internal static class AppInstallPaths
    {
        private static readonly Lazy<string> CachedRoot = new(ResolveRoot, LazyThreadSafetyMode.ExecutionAndPublication);

        /// <summary>Racine normalisée sans slash final (Path.GetFullPath).</summary>
        public static string GetInstallRoot() => CachedRoot.Value;

        /// <summary>Résolution directe sans cache (découverte des autres racines protégées).</summary>
        internal static string GetInstallRootUncached() => ResolveRoot();

        private static string ResolveRoot()
        {
            var baseDir = AppContext.BaseDirectory;
            if (string.IsNullOrWhiteSpace(baseDir))
                baseDir = AppDomain.CurrentDomain.BaseDirectory;

            try
            {
                return Path.GetFullPath(baseDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            }
            catch
            {
                return baseDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            }
        }

        /// <summary>Vrai si <paramref name="path"/> est sous l'installation ou les données optiCombat (MAJ, quarantaine).</summary>
        public static bool IsUnderInstallRoot(string? path)
            => OpticombatProtectedPaths.IsUnderProtectedPath(path);

        /// <summary>Motifs PCRE pour <c>clamscan --exclude</c> et <c>clamd.conf ExcludePath</c>.</summary>
        public static IEnumerable<string> GetClamScanExcludePatterns()
            => OpticombatProtectedPaths.GetClamScanExcludePatterns();
    }
}
