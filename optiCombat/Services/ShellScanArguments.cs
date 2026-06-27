using optiCombat.Models;
using System.IO;

namespace optiCombat.Services;

/// <summary>Arguments du menu contextuel Explorateur (<c>--scan "chemin"</c>).</summary>
public static class ShellScanArguments
{
    public const string Scan = "--scan";

    public static bool TryGetScanPath(IReadOnlyList<string> args, out string path)
    {
        path = string.Empty;
        for (var i = 0; i < args.Count; i++)
        {
            if (!string.Equals(args[i], Scan, StringComparison.OrdinalIgnoreCase))
                continue;

            if (i + 1 >= args.Count || string.IsNullOrWhiteSpace(args[i + 1]))
                return false;

            path = args[i + 1].Trim().Trim('"');
            return path.Length > 0;
        }

        return false;
    }

    public static bool IsValidScanTarget(string path) =>
        !string.IsNullOrWhiteSpace(path) && (File.Exists(path) || Directory.Exists(path));

    public static ScanType ResolveScanType(string path) =>
        Directory.Exists(path) ? ScanType.Folder : ScanType.File;
}
