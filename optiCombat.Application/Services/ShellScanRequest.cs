using System.Globalization;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace optiCombat.Services;

/// <summary>
/// Transfert du chemin de scan entre instances (menu contextuel Explorateur).
/// Fichier court sous LocalAppData, ACL restreinte, validation à l'écriture et à la lecture,
/// expiration courte — réduit le DoS / détournement via <c>WmShellScan</c>.
/// </summary>
public static class ShellScanRequest
{
    /// <summary>Une demande plus ancienne est ignorée (anti-rejeu / fichier planté).</summary>
    public static readonly TimeSpan MaxPendingAge = TimeSpan.FromMinutes(2);

    private const int MaxPathChars = 4096;

    /// <summary>Horloge injectable pour les tests d'expiration.</summary>
    internal static Func<DateTime> UtcNow { get; set; } = static () => DateTime.UtcNow;

    private static string AppDataDirectory =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiCombat");

    private static string PendingFilePath =>
        Path.Combine(AppDataDirectory, "shell_scan_pending.txt");

    /// <summary>
    /// Publie un chemin à scanner. No-op (retourne faux) si la cible est invalide ou trop large.
    /// </summary>
    public static bool Publish(string path)
    {
        if (!ShellScanArguments.TryNormalizeShellScanTarget(path, out var normalized))
            return false;

        try
        {
            var dir = AppDataDirectory;
            Directory.CreateDirectory(dir);
            DirectoryHardening.HardenDataDirectory(dir);

            var payload = string.Create(
                CultureInfo.InvariantCulture,
                $"{UtcNow().Ticks}\n{normalized}");

            var bytes = Encoding.UTF8.GetBytes(payload);
            using (var fs = new FileStream(
                       PendingFilePath,
                       FileMode.Create,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 4096,
                       FileOptions.None))
            {
                TryRestrictPendingFileAcl(PendingFilePath);
                fs.Write(bytes, 0, bytes.Length);
                fs.Flush(flushToDisk: true);
            }

            TryRestrictPendingFileAcl(PendingFilePath);
            return true;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ShellScanRequest", "Publish", ex);
            return false;
        }
    }

    /// <summary>Consomme une demande récente et valide ; ignore sinon.</summary>
    public static string? TryConsume()
    {
        try
        {
            if (!File.Exists(PendingFilePath))
                return null;

            string raw;
            using (var fs = new FileStream(
                       PendingFilePath,
                       FileMode.Open,
                       FileAccess.Read,
                       FileShare.Read,
                       bufferSize: 4096,
                       FileOptions.DeleteOnClose))
            {
                using var reader = new StreamReader(fs, Encoding.UTF8);
                raw = reader.ReadToEnd();
            }

            if (!TryParsePending(raw, out var path, out var stampedUtc))
                return null;

            if (UtcNow() - stampedUtc > MaxPendingAge || stampedUtc > UtcNow() + TimeSpan.FromMinutes(1))
                return null;

            if (!ShellScanArguments.TryNormalizeShellScanTarget(path, out var normalized))
                return null;

            return normalized;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ShellScanRequest", "TryConsume", ex);
            try { if (File.Exists(PendingFilePath)) File.Delete(PendingFilePath); } catch { /* best effort */ }
            return null;
        }
    }

    private static bool TryParsePending(string raw, out string path, out DateTime stampedUtc)
    {
        path = string.Empty;
        stampedUtc = default;
        if (string.IsNullOrWhiteSpace(raw))
            return false;

        var lines = raw.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        if (lines.Length < 2)
            return false;

        if (!long.TryParse(lines[0].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var ticks))
            return false;

        try { stampedUtc = new DateTime(ticks, DateTimeKind.Utc); }
        catch { return false; }

        path = string.Join("\n", lines.Skip(1)).Trim();
        if (path.Length == 0 || path.Length > MaxPathChars)
            return false;

        return true;
    }

    private static void TryRestrictPendingFileAcl(string path)
    {
        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            var owner = WindowsIdentity.GetCurrent().User;
            if (owner is null || !File.Exists(path))
                return;

            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var sid in new[] { owner, system, admins })
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    sid, FileSystemRights.FullControl, AccessControlType.Allow));
            }

            new FileInfo(path).SetAccessControl(security);
        }
        catch (Exception ex)
        {
            AppLogger.Debug("ShellScanRequest", $"ACL fichier pending ignorée : {ex.Message}");
        }
    }
}
