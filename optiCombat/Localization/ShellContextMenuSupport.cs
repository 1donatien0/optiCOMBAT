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

        public static void ApplyForCurrentCulture()
        {
            var menuName = LocalizationService.GetString("Shell_ScanWith");
            var exe = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(exe))
                exe = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(exe))
                return;

            try
            {
                foreach (var shellKey in ShellKeys)
                {
                    RemoveMenu(shellKey, LegacyFrenchName);
                    RemoveMenu(shellKey, LegacyEnglishName);

                    using var shell = Registry.CurrentUser.CreateSubKey(shellKey);
                    if (shell == null)
                        continue;

                    using var menu = shell.CreateSubKey(menuName);
                    menu?.SetValue("Icon", $"{exe},0");
                    using var command = menu?.CreateSubKey("command");
                    command?.SetValue("", $"\"{exe}\" --scan \"%1\"");
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ShellContextMenu", "ApplyForCurrentCulture", ex);
            }
        }

        private static void RemoveMenu(string shellKey, string name)
        {
            try
            {
                using var shell = Registry.CurrentUser.OpenSubKey(shellKey, writable: true);
                shell?.DeleteSubKeyTree(name, throwOnMissingSubKey: false);
            }
            catch
            {
                /* menu absent */
            }
        }
    }
}
