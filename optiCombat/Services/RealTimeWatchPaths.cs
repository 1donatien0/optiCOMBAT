using System.IO;

namespace optiCombat.Services
{
    /// <summary>
    /// Dossiers surveillés par la protection temps réel — alignés sur le scan rapide Defender-like.
    /// </summary>
    internal static class RealTimeWatchPaths
    {
        private static readonly string[] SystemFolders =
        {
            @"C:\ProgramData",
            @"C:\Windows\Downloaded Program Files",
        };

        public static IReadOnlyList<string> GetWatchFolders(IExclusionSettingsAccessor? exclusions = null)
        {
            var folders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var path in SystemFolders)
                TryAdd(folders, path);

            foreach (var path in ScanTargets.QuickScanTargets())
                TryAdd(folders, path);

            var excl = (exclusions ?? new DefaultExclusionSettingsAccessor()).Current;
            return folders
                .Where(p => !excl.IsFolderExcluded(p))
                .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static void TryAdd(HashSet<string> folders, string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return;
            try
            {
                if (Directory.Exists(path))
                    folders.Add(Path.GetFullPath(path));
            }
            catch
            {
                /* chemin invalide */
            }
        }
    }
}
