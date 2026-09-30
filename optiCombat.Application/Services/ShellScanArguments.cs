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
            if (!ScanPathValidation.IsSyntacticallyAcceptable(path))
            {
                path = string.Empty;
                return false;
            }

            return path.Length > 0;
        }

        return false;
    }

    /// <summary>
    /// Cible shell acceptable : existe, syntaxe OK, et n'est pas une racine trop large
    /// (lecteur, profil utilisateur, zones système — un scan shell = fichier/dossier choisi).
    /// </summary>
    public static bool IsValidScanTarget(string path) =>
        TryNormalizeShellScanTarget(path, out _);

    /// <summary>Normalise et valide une cible de scan menu contextuel.</summary>
    public static bool TryNormalizeShellScanTarget(string? path, out string fullPath)
    {
        fullPath = string.Empty;
        if (!ScanPathValidation.TryNormalizeScanTarget(path, out var normalized, allowSensitive: true))
            return false;

        if (!IsAcceptableShellScope(normalized))
            return false;

        fullPath = normalized;
        return true;
    }

    /// <summary>
    /// Refuse les racines de lecteur et les arbres trop larges pour un scan shell
    /// (profil utilisateur entier, Windows, Program Files, ProgramData, etc.).
    /// </summary>
    public static bool IsAcceptableShellScope(string fullPath)
    {
        if (string.IsNullOrWhiteSpace(fullPath))
            return false;

        string trimmed;
        try { trimmed = Path.TrimEndingDirectorySeparator(Path.GetFullPath(fullPath)); }
        catch { return false; }

        var root = Path.GetPathRoot(trimmed);
        if (!string.IsNullOrEmpty(root)
            && string.Equals(
                trimmed,
                Path.TrimEndingDirectorySeparator(root),
                StringComparison.OrdinalIgnoreCase))
            return false;

        foreach (var broad in EnumerateBroadRoots())
        {
            if (string.IsNullOrEmpty(broad))
                continue;
            var normalizedBroad = Path.TrimEndingDirectorySeparator(Path.GetFullPath(broad));
            if (string.Equals(trimmed, normalizedBroad, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        // Zones système (et sous-arbres) : pas via le canal shell / IPC fichier pending.
        if (QuarantineManager.IsSensitivePath(trimmed))
            return false;

        return true;
    }

    private static IEnumerable<string> EnumerateBroadRoots()
    {
        yield return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var publicDesktop = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
        if (!string.IsNullOrEmpty(publicDesktop))
        {
            var publicProfile = Path.GetDirectoryName(publicDesktop);
            if (!string.IsNullOrEmpty(publicProfile))
                yield return publicProfile;
        }
    }

    public static ScanType ResolveScanType(string path) =>
        Directory.Exists(path) ? ScanType.Folder : ScanType.File;
}
