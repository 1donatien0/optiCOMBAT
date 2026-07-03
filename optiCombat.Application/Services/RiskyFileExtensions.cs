using System.IO;

namespace optiCombat.Services
{
    /// <summary>Extensions de fichiers à risque (exécutables, scripts, macros Office, archives suspectes).</summary>
    internal static class RiskyFileExtensions
    {
        public static readonly HashSet<string> All = new(
            new[]
            {
                ".exe", ".dll", ".scr", ".com", ".msi", ".msc", ".jar", ".apk",
                ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".hta",
                ".py", ".pyw", ".reg",
                ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
                ".iso", ".img", ".vhd", ".vhdx",
            },
            StringComparer.OrdinalIgnoreCase);

        public static readonly HashSet<string> ScriptHosts = new(
            new[] { "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe", "msbuild.exe" },
            StringComparer.OrdinalIgnoreCase);

        public static bool IsRisky(string filePath) =>
            All.Contains(Path.GetExtension(filePath));

        public static bool IsExecutable(string filePath)
        {
            var ext = Path.GetExtension(filePath);
            return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".scr", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".com", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".msi", StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsScriptHostProcess(string? processName) =>
            !string.IsNullOrWhiteSpace(processName)
            && ScriptHosts.Contains(Path.GetFileName(processName));
    }
}
