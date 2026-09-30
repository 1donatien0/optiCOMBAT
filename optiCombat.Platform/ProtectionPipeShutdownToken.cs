using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace optiCombat.Platform;

/// <summary>Jeton d'authentification pour l'opération IPC <c>shutdown</c> (fichier ProgramData).</summary>
public static class ProtectionPipeShutdownToken
{
    /// <summary>Chemin du fichier jeton (surchargeable en tests).</summary>
    public static string TokenFilePath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "optiCombat",
        "ipc_shutdown.token");

    public static string Generate() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    public static bool Validate(string? expected, string? provided)
    {
        if (string.IsNullOrEmpty(expected) || string.IsNullOrEmpty(provided))
            return false;

        var a = Encoding.UTF8.GetBytes(expected);
        var b = Encoding.UTF8.GetBytes(provided);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>
    /// Persiste le jeton sous verrou exclusif (<see cref="FileShare.None"/>) : le secret est
    /// écrit pendant que personne d'autre ne peut ouvrir le fichier, puis l'ACL admins est
    /// posée avant la fermeture du handle. Pas de WriteAllText suivi d'ACL sur un fichier partageable.
    /// </summary>
    public static void Persist(string token)
    {
        var dir = Path.GetDirectoryName(TokenFilePath)!;
        Directory.CreateDirectory(dir);

        var bytes = Encoding.UTF8.GetBytes(token);
        using (var fs = new FileStream(
                   TokenFilePath,
                   FileMode.Create,
                   FileAccess.Write,
                   FileShare.None,
                   bufferSize: 4096,
                   FileOptions.None))
        {
            fs.Write(bytes, 0, bytes.Length);
            fs.Flush(flushToDisk: true);
            // ACL pendant le verrou exclusif : aucun autre processus ne lit le secret
            // avec l'ACL héritée par défaut.
            TryRestrictToAdministrators(TokenFilePath);
        }

        TryRestrictToAdministrators(TokenFilePath);
        TryRestrictToAdministrators(dir);
    }

    public static bool TryRead(out string? token)
    {
        token = null;
        try
        {
            if (!File.Exists(TokenFilePath))
                return false;
            token = File.ReadAllText(TokenFilePath, Encoding.UTF8).Trim();
            return !string.IsNullOrEmpty(token);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Limite la lecture du jeton aux administrateurs (évite l'arrêt IPC par un utilisateur standard).</summary>
    private static void TryRestrictToAdministrators(string path)
    {
        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            if (Directory.Exists(path))
            {
                var dirSecurity = new DirectorySecurity();
                dirSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                dirSecurity.AddAccessRule(new FileSystemAccessRule(
                    system, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
                dirSecurity.AddAccessRule(new FileSystemAccessRule(
                    admins, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
                new DirectoryInfo(path).SetAccessControl(dirSecurity);
                return;
            }

            if (!File.Exists(path))
                return;

            var fileSecurity = new FileSecurity();
            fileSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            fileSecurity.AddAccessRule(new FileSystemAccessRule(
                system, FileSystemRights.FullControl, AccessControlType.Allow));
            fileSecurity.AddAccessRule(new FileSystemAccessRule(
                admins, FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(fileSecurity);
        }
        catch
        {
            // Best effort : l'écriture du jeton ne doit pas faire échouer le démarrage IPC.
        }
    }
}
