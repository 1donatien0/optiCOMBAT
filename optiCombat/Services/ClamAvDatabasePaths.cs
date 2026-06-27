using System.IO;

namespace optiCombat.Services
{
    /// <summary>
    /// Répertoire des signatures ClamAV : doit être inscriptible (freshclam crée
    /// des sous-dossiers <c>tmp.*</c>). Les installs sous Program Files échouent
    /// souvent au 2e lancement même si la 1re MAJ a réussi.
    /// </summary>
    internal static class ClamAvDatabasePaths
    {
        private const string SeedMarker = ".opticombat-db-seeded";

        /// <summary>
        /// Résout le dossier contenant les binaires ClamAV (<c>clamscan.exe</c> /
        /// <c>freshclam.exe</c>) en cherchant dans cet ordre :
        /// <list type="number">
        ///   <item><c>&lt;baseDir&gt;\clamav\&lt;arch&gt;\</c> (binaires embarqués x64/x86)</item>
        ///   <item><c>&lt;baseDir&gt;\clamav\</c> (layout plat)</item>
        ///   <item><c>%ProgramFiles%\ClamAV\</c></item>
        ///   <item><c>%ProgramFiles(x86)%\ClamAV\</c></item>
        /// </list>
        /// Retourne le layout plat comme repli si aucun n'est trouvé (l'erreur
        /// sera levée à l'utilisation par le moteur concerné).
        /// </summary>
        /// <param name="executableName">
        /// Nom de l'exécutable à chercher dans chaque candidat
        /// (ex. <c>"clamscan.exe"</c> ou <c>"freshclam.exe"</c>).
        /// </param>
        /// <param name="baseDir">
        /// Répertoire racine de recherche. <c>null</c> (valeur par défaut) utilise
        /// <see cref="AppDomain.CurrentDomain.BaseDirectory"/> — comportement de production.
        /// Passer une valeur explicite en test pour isoler la logique de découverte.
        /// </param>
        public static string ResolveClamAvBinDir(
            string executableName = "clamscan.exe",
            string? baseDir = null)
        {
            baseDir ??= AppDomain.CurrentDomain.BaseDirectory;
            var arch = Environment.Is64BitProcess ? "x64" : "x86";

            var candidates = new[]
            {
                Path.Combine(baseDir, "clamav", arch),
                Path.Combine(baseDir, "clamav"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClamAV"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "ClamAV"),
            };

            foreach (var candidate in candidates)
                if (File.Exists(Path.Combine(candidate, executableName)))
                    return candidate;

            // Repli : layout plat (l'erreur sera levée à l'utilisation)
            return Path.Combine(baseDir, "clamav");
        }

        /// <summary>Résout le dossier <c>database</c> à côté des binaires (ou parent).</summary>
        public static string ResolvePreferredDatabaseDir(string clamavBinDir)
        {
            clamavBinDir = Path.GetFullPath(clamavBinDir);
            var local = Path.Combine(clamavBinDir, "database");
            if (Directory.Exists(local))
                return Path.GetFullPath(local);

            var parent = Path.GetDirectoryName(clamavBinDir);
            if (parent != null)
            {
                var parentDb = Path.Combine(parent, "database");
                if (Directory.Exists(parentDb))
                    return Path.GetFullPath(parentDb);
            }

            return Path.GetFullPath(local);
        }

        /// <summary>
        /// Répertoire effectif pour freshclam / clamscan / clamd : préféré si sain,
        /// sinon <c>%LocalAppData%\optiCombat\clamav\database</c> avec copie initiale
        /// des bases depuis le chemin en lecture seule.
        /// </summary>
        public static string ResolveWritableDatabaseDir(string clamavBinDir)
        {
            var preferred = ResolvePreferredDatabaseDir(clamavBinDir);

            if (!IsUnderProgramFilesOrProgramFilesX86(preferred)
                && IsUsableWritableDatabaseRoot(preferred))
                return preferred;

            var fallback = Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiCombat", "clamav", "database"));

            Directory.CreateDirectory(fallback);
            TrySeedSignatureFiles(preferred, fallback);
            return fallback;
        }

        private static bool IsUnderProgramFilesOrProgramFilesX86(string fullPath)
        {
            fullPath = Path.GetFullPath(fullPath);
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var pfx86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            if (!string.IsNullOrEmpty(pf))
            {
                var sep = Path.DirectorySeparatorChar;
                var p = Path.GetFullPath(pf.TrimEnd(sep));
                if (fullPath.StartsWith(p + sep, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            if (!string.IsNullOrEmpty(pfx86))
            {
                var sep = Path.DirectorySeparatorChar;
                var p = Path.GetFullPath(pfx86.TrimEnd(sep));
                if (fullPath.StartsWith(p + sep, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static bool IsUsableWritableDatabaseRoot(string dir)
        {
            try
            {
                Directory.CreateDirectory(dir);
                var probeDir = Path.Combine(dir, ".opticombat-write-probe-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(probeDir);
                var probeFile = Path.Combine(probeDir, "t.tmp");
                File.WriteAllText(probeFile, "x");
                File.Delete(probeFile);
                Directory.Delete(probeDir, recursive: false);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static void TrySeedSignatureFiles(string readOnlySourceDir, string writableDestDir)
        {
            try
            {
                if (File.Exists(Path.Combine(writableDestDir, SeedMarker)))
                    return;

                var destHasDb = Directory.Exists(writableDestDir)
                    && (Directory.GetFiles(writableDestDir, "*.cvd").Length > 0
                        || Directory.GetFiles(writableDestDir, "*.cld").Length > 0);

                if (destHasDb)
                {
                    File.WriteAllText(Path.Combine(writableDestDir, SeedMarker), "1");
                    return;
                }

                if (!Directory.Exists(readOnlySourceDir))
                {
                    File.WriteAllText(Path.Combine(writableDestDir, SeedMarker), "1");
                    return;
                }

                foreach (var path in Directory.EnumerateFiles(readOnlySourceDir))
                {
                    var ext = Path.GetExtension(path).ToUpperInvariant();
                    if (ext is not (".CVD" or ".CLD"))
                        continue;
                    var destFile = Path.Combine(writableDestDir, Path.GetFileName(path));
                    if (!File.Exists(destFile))
                        File.Copy(path, destFile, overwrite: false);
                }

                File.WriteAllText(Path.Combine(writableDestDir, SeedMarker), "1");
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ClamAvDatabasePaths", "TrySeedSignatureFiles", ex);
            }
        }
    }
}
