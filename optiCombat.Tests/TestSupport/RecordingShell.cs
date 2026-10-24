using System.Diagnostics;
using Microsoft.Win32;
using optiCombat.Services;

namespace optiCombat.Tests.TestSupport;

/// <summary>
/// <see cref="ISystemShell"/> factice : enregistre chaque processus et écriture de registre,
/// ne lance rien et ne touche jamais le registre réel. Sert aussi de shell inerte par défaut
/// pour toute l'exécution des tests (voir <see cref="TestDataRoot"/>).
/// </summary>
internal sealed class RecordingShell : ISystemShell, IDisposable
{
    private readonly object _gate = new();
    private readonly ISystemShell? _previous;

    public RecordingShell() { }

    private RecordingShell(ISystemShell previous) => _previous = previous;

    /// <summary>Installe un enregistreur pour le flux d'exécution du test courant.</summary>
    public static RecordingShell Install()
    {
        var shell = new RecordingShell(SystemShell.Current);
        SystemShell.Current = shell;
        return shell;
    }

    public List<ProcessStartInfo> Runs { get; } = new();

    public List<int?> Timeouts { get; } = new();

    /// <summary>Réponse à chaque lancement (par défaut : non démarré, comme un poste sans l'outil).</summary>
    public Func<ProcessStartInfo, ProcessOutcome> Respond { get; set; } = _ => ProcessOutcome.NotStarted;

    public Dictionary<string, object> CurrentUser { get; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, object> LocalMachine { get; } = new(StringComparer.OrdinalIgnoreCase);

    public List<string> DeletedTrees { get; } = new();

    public Dictionary<string, int> Processes { get; } = new(StringComparer.OrdinalIgnoreCase);

    public List<string> Killed { get; } = new();

    public int? ExitCode { get; private set; }

    public static string Key(string subKey, string name) => subKey + "|" + name;

    /// <summary>Ligne de commande lisible d'un lancement (fichier + arguments).</summary>
    public static string CommandLine(ProcessStartInfo psi) =>
        psi.FileName + " " + (psi.ArgumentList.Count > 0 ? string.Join(" ", psi.ArgumentList) : psi.Arguments);

    public IReadOnlyList<string> CommandLines
    {
        get { lock (_gate) return Runs.Select(CommandLine).ToList(); }
    }

    public ProcessOutcome Run(ProcessStartInfo startInfo, int? timeoutMs)
    {
        lock (_gate)
        {
            Runs.Add(startInfo);
            Timeouts.Add(timeoutMs);
        }
        return Respond(startInfo);
    }

    public int CountProcesses(string name)
    {
        lock (_gate) return Processes.TryGetValue(name, out var n) ? n : 0;
    }

    public int KillProcesses(string name)
    {
        lock (_gate)
        {
            Killed.Add(name);
            var n = Processes.TryGetValue(name, out var c) ? c : 0;
            Processes[name] = 0;
            return n;
        }
    }

    public void SetCurrentUserValue(string subKey, string name, object value, RegistryValueKind kind)
    {
        lock (_gate) CurrentUser[Key(subKey, name)] = value;
    }

    public object? GetCurrentUserValue(string subKey, string name)
    {
        lock (_gate) return CurrentUser.TryGetValue(Key(subKey, name), out var v) ? v : null;
    }

    public void DeleteCurrentUserValue(string subKey, string name)
    {
        lock (_gate) CurrentUser.Remove(Key(subKey, name));
    }

    public void DeleteCurrentUserSubKeyTree(string subKey)
    {
        lock (_gate)
        {
            DeletedTrees.Add(subKey);
            foreach (var k in CurrentUser.Keys.Where(k => k.StartsWith(subKey + "\\", StringComparison.OrdinalIgnoreCase)
                                                         || k.StartsWith(subKey + "|", StringComparison.OrdinalIgnoreCase)).ToList())
                CurrentUser.Remove(k);
        }
    }

    public void SetLocalMachineValue(string subKey, string name, object value, RegistryValueKind kind)
    {
        lock (_gate) LocalMachine[Key(subKey, name)] = value;
    }

    public void ExitProcess(int exitCode)
    {
        lock (_gate) ExitCode = exitCode;
    }

    public void Dispose()
    {
        if (_previous != null)
            SystemShell.Current = _previous;
    }
}
