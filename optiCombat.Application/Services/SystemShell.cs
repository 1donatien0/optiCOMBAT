using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace optiCombat.Services;

/// <summary>Résultat d'un processus lancé par <see cref="ISystemShell.Run"/>.</summary>
/// <param name="Started">Le processus a démarré.</param>
/// <param name="ExitCode">Code de sortie (-1 s'il n'a pas démarré ou n'a pas fini à temps).</param>
/// <param name="Output">Sortie standard (et erreur) si redirigée, sinon vide.</param>
/// <param name="Cancelled">L'utilisateur a refusé l'invite UAC (verbe <c>runas</c>).</param>
/// <param name="TimedOut">Le délai est écoulé avant la fin du processus.</param>
internal sealed record ProcessOutcome(bool Started, int ExitCode, string Output, bool Cancelled = false, bool TimedOut = false)
{
    public static ProcessOutcome NotStarted { get; } = new(false, -1, string.Empty);

    public static ProcessOutcome UserCancelled { get; } = new(false, -1, string.Empty, Cancelled: true);

    public bool Succeeded => Started && !TimedOut && ExitCode == 0;
}

/// <summary>
/// Accès aux processus et au registre de l'utilisateur, en un seul point remplaçable en test.
/// Les actions système (tweaks, exclusions Defender, service Windows, élévation, langue,
/// démarrage automatique) passent par ici : un test vérifie la commande ou la clé exacte
/// sans jamais modifier le poste.
/// </summary>
internal interface ISystemShell
{
    /// <summary>Lance et attend (<paramref name="timeoutMs"/> ; <c>null</c> = ne pas attendre).</summary>
    ProcessOutcome Run(ProcessStartInfo startInfo, int? timeoutMs);

    /// <summary>Nombre de processus portant ce nom (sans extension).</summary>
    int CountProcesses(string name);

    /// <summary>Termine les processus portant ce nom ; renvoie le nombre terminé.</summary>
    int KillProcesses(string name);

    void SetCurrentUserValue(string subKey, string name, object value, RegistryValueKind kind);

    object? GetCurrentUserValue(string subKey, string name);

    void DeleteCurrentUserValue(string subKey, string name);

    /// <summary>Supprime une clé HKCU et ses sous-clés (absente : sans effet).</summary>
    void DeleteCurrentUserSubKeyTree(string subKey);

    /// <summary>Écrit sous HKLM (installation élevée : fournisseur AMSI).</summary>
    void SetLocalMachineValue(string subKey, string name, object value, RegistryValueKind kind);

    /// <summary>Termine l'application (relance après changement de langue).</summary>
    void ExitProcess(int exitCode);
}

/// <summary>
/// Point d'accès. En production, <see cref="Current"/> est toujours <see cref="Real"/>.
/// Les tests posent un shell inerte global (<see cref="Default"/>) et, au besoin, un enregistreur
/// propre à leur flux d'exécution (<see cref="Current"/>, porté par <see cref="AsyncLocal{T}"/> :
/// il suit les <c>await</c> et <c>Task.Run</c> du test sans gêner les tests parallèles).
/// </summary>
internal static class SystemShell
{
    private static readonly AsyncLocal<ISystemShell?> Scoped = new();

    public static ISystemShell Real { get; } = new WindowsSystemShell();

    /// <summary>Shell utilisé hors portée explicite (tests : shell inerte pour toute l'exécution).</summary>
    public static ISystemShell Default { get; set; } = Real;

    /// <summary>Shell effectif ; l'affectation ne vaut que pour le flux d'exécution courant.</summary>
    public static ISystemShell Current
    {
        get => Scoped.Value ?? Default;
        set => Scoped.Value = value;
    }
}

/// <remarks>
/// Fine enveloppe des API Windows (Process, Registry) : exclue de la couverture car la tester
/// reviendrait à lancer de vrais processus élevés et à écrire dans le registre du poste. Toute la
/// logique de décision est dans les appelants, couverts via un <see cref="ISystemShell"/> factice.
/// </remarks>
[SupportedOSPlatform("windows")]
[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "Enveloppe Process/Registry sans logique ; appelants testés via ISystemShell factice.")]
internal sealed class WindowsSystemShell : ISystemShell
{
    private const int ErrorCancelled = 1223;

    public ProcessOutcome Run(ProcessStartInfo startInfo, int? timeoutMs)
    {
        Process? proc;
        try
        {
            proc = Process.Start(startInfo);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            return ProcessOutcome.UserCancelled;
        }

        if (proc == null)
            return ProcessOutcome.NotStarted;

        using (proc)
        {
            if (timeoutMs is not { } timeout)
                return new ProcessOutcome(true, -1, string.Empty);

            var output = string.Empty;
            Task<string>? stdout = startInfo.RedirectStandardOutput ? proc.StandardOutput.ReadToEndAsync() : null;
            Task<string>? stderr = startInfo.RedirectStandardError ? proc.StandardError.ReadToEndAsync() : null;
            if (!proc.WaitForExit(timeout))
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* déjà terminé */ }
                return new ProcessOutcome(true, -1, string.Empty, TimedOut: true);
            }
            proc.WaitForExit();
            if (stdout != null)
                output = stdout.GetAwaiter().GetResult();
            if (stderr != null)
            {
                var err = stderr.GetAwaiter().GetResult();
                if (!string.IsNullOrWhiteSpace(err))
                    output = string.IsNullOrEmpty(output) ? err : output + Environment.NewLine + err;
            }
            return new ProcessOutcome(true, proc.ExitCode, output.Trim());
        }
    }

    public int CountProcesses(string name)
    {
        var all = Process.GetProcessesByName(name);
        foreach (var p in all)
            p.Dispose();
        return all.Length;
    }

    public int KillProcesses(string name)
    {
        var killed = 0;
        foreach (var p in Process.GetProcessesByName(name))
        {
            try
            {
                p.Kill();
                killed++;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemShell", $"Kill {name}", ex);
            }
            finally
            {
                p.Dispose();
            }
        }
        return killed;
    }

    public void SetCurrentUserValue(string subKey, string name, object value, RegistryValueKind kind)
    {
        using var key = Registry.CurrentUser.CreateSubKey(subKey, writable: true);
        key.SetValue(name, value, kind);
    }

    public object? GetCurrentUserValue(string subKey, string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(subKey, writable: false);
        return key?.GetValue(name);
    }

    public void DeleteCurrentUserValue(string subKey, string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(subKey, writable: true);
        key?.DeleteValue(name, throwOnMissingValue: false);
    }

    public void DeleteCurrentUserSubKeyTree(string subKey) =>
        Registry.CurrentUser.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);

    public void SetLocalMachineValue(string subKey, string name, object value, RegistryValueKind kind)
    {
        using var key = Registry.LocalMachine.CreateSubKey(subKey, writable: true);
        key.SetValue(name, value, kind);
    }

    public void ExitProcess(int exitCode) => Environment.Exit(exitCode);
}
