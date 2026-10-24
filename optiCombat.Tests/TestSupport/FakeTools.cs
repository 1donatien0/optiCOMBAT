using System.Runtime.InteropServices;
using System.Text;

namespace optiCombat.Tests.TestSupport;

/// <summary>
/// Installe l'outil factice <c>FakeTool</c> (projet optiCombat.TestFakes) sous le nom d'un outil
/// externe et écrit son scénario. Fonctionne sous Windows (apphost .exe) comme sous Linux.
/// </summary>
internal static class FakeTools
{
    private static readonly UTF8Encoding Utf8 = new(false);

    private static string HostName => RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "FakeTool.exe" : "FakeTool";

    /// <summary>Copie l'outil factice dans <paramref name="dir"/> sous le nom <paramref name="exeName"/>.</summary>
    public static string Install(string dir, string exeName)
    {
        Directory.CreateDirectory(dir);
        var baseDir = AppContext.BaseDirectory;
        var target = Path.Combine(dir, exeName);
        File.Copy(Path.Combine(baseDir, HostName), target, overwrite: true);
        foreach (var f in new[] { "FakeTool.dll", "FakeTool.runtimeconfig.json", "FakeTool.deps.json" })
            File.Copy(Path.Combine(baseDir, f), Path.Combine(dir, f), overwrite: true);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(target,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                | UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
        }
        return target;
    }

    /// <summary>
    /// Écrit le scénario de l'outil installé en <paramref name="exePath"/>. <paramref name="when"/> :
    /// <c>null</c> = tous les appels, « 2 » = deuxième appel, « list » = appels dont le premier
    /// argument est <c>list</c> (ou <c>--list</c>, <c>/list</c>).
    /// </summary>
    public static void Script(
        string exePath,
        string? when = null,
        int exit = 0,
        string stdout = "",
        string stderr = "",
        int delayMs = 0,
        bool readStdin = false,
        params (string Path, string Content)[] writes)
    {
        var sb = new StringBuilder();
        sb.Append("exit=").Append(exit).Append('\n');
        if (readStdin)
            sb.Append("stdin=read\n");
        if (delayMs > 0)
            sb.Append("delay=").Append(delayMs).Append('\n');
        foreach (var (path, content) in writes)
            sb.Append("write=").Append(path).Append('|').Append(content).Append('\n');
        sb.Append("---stdout---\n").Append(stdout.Replace("\r\n", "\n", StringComparison.Ordinal));
        if (stdout.Length > 0 && !stdout.EndsWith('\n'))
            sb.Append('\n');
        sb.Append("---stderr---\n").Append(stderr.Replace("\r\n", "\n", StringComparison.Ordinal));
        File.WriteAllText(when is null ? exePath + ".fake" : $"{exePath}.fake.{when}", sb.ToString(), Utf8);
    }

    /// <summary>Appels reçus (un tableau d'arguments par appel).</summary>
    public static IReadOnlyList<string[]> Calls(string exePath)
    {
        var log = exePath + ".args";
        if (!File.Exists(log))
            return Array.Empty<string[]>();
        return File.ReadAllLines(log, Utf8)
            .Where(l => l.Length > 0)
            .Select(l => l.Split('\t'))
            .ToArray();
    }

    /// <summary>Entrée standard reçue (concaténée), ou chaîne vide.</summary>
    public static string Stdin(string exePath) =>
        File.Exists(exePath + ".stdin") ? File.ReadAllText(exePath + ".stdin", Utf8) : string.Empty;
}
