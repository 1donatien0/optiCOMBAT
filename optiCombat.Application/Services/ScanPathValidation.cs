using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace optiCombat.Services;

/// <summary>
/// Validation des chemins proposés pour analyse depuis l'extérieur de l'application
/// (menu contextuel <c>--scan</c>, ligne de commande, pipe IPC).
/// Refuse les chemins de périphérique (<c>\\.\</c>, <c>\\?\</c>), les caractères de contrôle
/// et les chemins inexistants ; normalise le chemin (<see cref="Path.GetFullPath(string)"/>)
/// et, si <c>allowSensitive</c> est faux, résout les jonctions/symlinks avant le contrôle
/// de sensibilité (évite le contournement via point de réparse).
/// </summary>
public static class ScanPathValidation
{
    /// <summary>Contrôle syntaxique seul (sans accès disque) : vide, caractères de contrôle, préfixes de périphérique.</summary>
    public static bool IsSyntacticallyAcceptable(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        var trimmed = path.Trim().Trim('"');
        if (trimmed.Length == 0)
            return false;

        foreach (var c in trimmed)
        {
            if (char.IsControl(c))
                return false;
        }

        return !trimmed.StartsWith(@"\\.\", StringComparison.Ordinal)
            && !trimmed.StartsWith(@"\\?\", StringComparison.Ordinal)
            && !trimmed.StartsWith("//./", StringComparison.Ordinal)
            && !trimmed.StartsWith("//?/", StringComparison.Ordinal);
    }

    /// <summary>
    /// Normalise et valide un chemin à analyser.
    /// </summary>
    /// <param name="path">Chemin brut (guillemets tolérés).</param>
    /// <param name="fullPath">Chemin absolu normalisé si valide.</param>
    /// <param name="allowSensitive">
    /// <c>false</c> pour refuser les dossiers système (<see cref="QuarantineManager.IsSensitivePath"/>) —
    /// utilisé par le pipe IPC, accessible aux autres processus. Les analyses demandées par l'utilisateur
    /// (menu contextuel, UI) restent autorisées sur ces dossiers (lecture seule, avec élévation si besoin).
    /// </param>
    public static bool TryNormalizeScanTarget(string? path, out string fullPath, bool allowSensitive = true)
    {
        fullPath = string.Empty;
        if (!IsSyntacticallyAcceptable(path))
            return false;

        string normalized;
        try
        {
            normalized = Path.GetFullPath(path!.Trim().Trim('"'));
        }
        catch (Exception)
        {
            return false;
        }

        if (!File.Exists(normalized) && !Directory.Exists(normalized))
            return false;

        if (!allowSensitive)
        {
            // Juger la sensibilité sur la cible finale (jonction / symlink), pas seulement
            // sur le chemin lexical — pattern ReparsePoint de RemovableDriveScanService (optiSCAN).
            if (!TryResolveFinalPath(normalized, out var finalPath))
                return false;
            if (QuarantineManager.IsSensitivePath(normalized)
                || QuarantineManager.IsSensitivePath(finalPath))
                return false;
        }

        fullPath = normalized;
        return true;
    }

    /// <summary>
    /// Résout la cible finale d'un fichier ou dossier (suit jonctions / liens symboliques).
    /// Échec fermé si le chemin n'est pas ouvrable.
    /// </summary>
    internal static bool TryResolveFinalPath(string fullPath, out string finalPath)
    {
        finalPath = fullPath;
        if (!OperatingSystem.IsWindows())
            return true;

        return TryResolveFinalPathWindows(fullPath, out finalPath);
    }

    [SupportedOSPlatform("windows")]
    private static bool TryResolveFinalPathWindows(string fullPath, out string finalPath)
    {
        finalPath = fullPath;
        // dwDesiredAccess = 0 : métadonnées seulement ; BACKUP_SEMANTICS pour ouvrir un dossier.
        using var handle = CreateFileW(
            fullPath,
            dwDesiredAccess: 0,
            dwShareMode: FileShare.ReadWrite | FileShare.Delete,
            lpSecurityAttributes: IntPtr.Zero,
            dwCreationDisposition: FileMode.Open,
            dwFlagsAndAttributes: FILE_FLAG_BACKUP_SEMANTICS,
            hTemplateFile: IntPtr.Zero);

        if (handle.IsInvalid)
            return false;

        var buffer = new StringBuilder(1024);
        var needed = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, FILE_NAME_NORMALIZED);
        if (needed == 0)
            return false;

        if (needed > buffer.Capacity)
        {
            buffer.EnsureCapacity((int)needed);
            needed = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, FILE_NAME_NORMALIZED);
            if (needed == 0)
                return false;
        }

        var resolved = buffer.ToString();
        if (resolved.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            resolved = @"\\" + resolved[8..];
        else if (resolved.StartsWith(@"\\?\", StringComparison.Ordinal))
            resolved = resolved[4..];

        try
        {
            finalPath = Path.GetFullPath(resolved);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_NAME_NORMALIZED = 0x0;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        FileShare dwShareMode,
        IntPtr lpSecurityAttributes,
        FileMode dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle hFile,
        StringBuilder lpszFilePath,
        uint cchFilePath,
        uint dwFlags);
}
