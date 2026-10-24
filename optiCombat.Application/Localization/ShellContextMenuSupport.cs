using Microsoft.Win32;
using optiCombat.Services;

namespace optiCombat.Localization
{
    /// <summary>Menu contextuel Explorateur « Scanner avec optiCombat » / « Scan with optiCombat » (fichiers et dossiers).</summary>
    internal static class ShellContextMenuSupport
    {
        private static readonly string[] ShellKeys =
        {
            @"Software\Classes\*\shell",
            @"Software\Classes\Directory\shell",
        };

        private const string LegacyFrenchName = "Scanner avec optiCombat";
        private const string LegacyEnglishName = "Scan with optiCombat";

        /// <summary>Tests uniquement : exécutable inscrit dans le menu.</summary>
        internal static string? ExecutablePathOverride { get; set; }

        public static void ApplyForCurrentCulture()
        {
            var menuName = LocalizationService.GetString("Shell_ScanWith");
            var exe = ExecutablePathOverride ?? Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(exe))
                exe = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(exe))
                return;

            var shellApi = SystemShell.Current;
            try
            {
                foreach (var shellKey in ShellKeys)
                {
                    RemoveMenu(shellApi, shellKey, LegacyFrenchName);
                    RemoveMenu(shellApi, shellKey, LegacyEnglishName);

                    var menu = shellKey + "\\" + menuName;
                    shellApi.SetCurrentUserValue(menu, "Icon", $"{exe},0", RegistryValueKind.String);
                    shellApi.SetCurrentUserValue(menu + "\\command", string.Empty, $"\"{exe}\" --scan \"%1\"", RegistryValueKind.String);
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ShellContextMenu", "ApplyForCurrentCulture", ex);
            }
        }

        private static void RemoveMenu(ISystemShell shellApi, string shellKey, string name)
        {
            try
            {
                shellApi.DeleteCurrentUserSubKeyTree(shellKey + "\\" + name);
            }
            catch
            {
                /* menu absent */
            }
        }
    }
}
