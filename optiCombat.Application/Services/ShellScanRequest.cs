using System.IO;

namespace optiCombat.Services;

/// <summary>Transfert du chemin de scan entre instances (menu contextuel Explorateur).</summary>
public static class ShellScanRequest
{
    private static string PendingFilePath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiCombat",
            "shell_scan_pending.txt");

    public static void Publish(string path)
    {
        var dir = Path.GetDirectoryName(PendingFilePath)!;
        Directory.CreateDirectory(dir);
        File.WriteAllText(PendingFilePath, path);
    }

    public static string? TryConsume()
    {
        try
        {
            if (!File.Exists(PendingFilePath))
                return null;

            var path = File.ReadAllText(PendingFilePath).Trim();
            File.Delete(PendingFilePath);
            return string.IsNullOrWhiteSpace(path) ? null : path;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ShellScanRequest", "TryConsume", ex);
            return null;
        }
    }
}
