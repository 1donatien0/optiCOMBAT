// FakeTool — outil externe factice pour les tests (voir optiCombat.Tests/TestSupport/FakeTools.cs).
//
// Scénario lu dans le premier fichier existant parmi « <exe>.fake.<n> » (n-ième appel, à partir
// de 1), « <exe>.fake.<premier argument> » et « <exe>.fake » (lignes clé=valeur, puis blocs) :
//   exit=<code>             code de sortie (défaut 0)
//   delay=<ms>              attente avant de répondre (annulation / délais)
//   stdin=read              lit l'entrée standard et l'ajoute à « <exe>.stdin »
//   write=<chemin>|<texte>  crée un fichier (simule un outil qui écrit sur disque)
//   ---stdout---            les lignes suivantes vont sur la sortie standard
//   ---stderr---            les lignes suivantes vont sur la sortie d'erreur
// Les arguments reçus sont ajoutés à « <chemin de l'exécutable>.args » (une ligne par appel,
// arguments séparés par une tabulation).
using System.Text;

namespace optiCombat.TestFakes;

internal static class Program
{
    private static readonly UTF8Encoding Utf8 = new(false);

    private static int Main(string[] args)
    {
        var self = Environment.ProcessPath ?? string.Empty;
        var argsLog = self + ".args";
        File.AppendAllText(argsLog, string.Join('\t', args) + "\n", Utf8);
        var callNumber = File.ReadAllLines(argsLog, Utf8).Length;

        var candidates = new List<string> { $"{self}.fake.{callNumber}" };
        // Premier argument sans préfixe d'option (« --version » → version, « /Run » → Run).
        var verb = args.Length > 0 ? args[0].TrimStart('-', '/') : string.Empty;
        if (verb.Length > 0 && verb.IndexOfAny(Path.GetInvalidFileNameChars()) < 0)
            candidates.Add($"{self}.fake.{verb}");
        candidates.Add(self + ".fake");
        var scenarioPath = candidates.FirstOrDefault(File.Exists);
        if (scenarioPath == null)
            return 0;

        var exit = 0;
        var delay = 0;
        var readStdin = false;
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        StringBuilder? block = null;
        foreach (var raw in File.ReadAllLines(scenarioPath, Encoding.UTF8))
        {
            if (raw == "---stdout---")
            {
                block = stdout;
                continue;
            }
            if (raw == "---stderr---")
            {
                block = stderr;
                continue;
            }
            if (block != null)
            {
                block.Append(raw).Append('\n');
                continue;
            }
            var eq = raw.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0)
                continue;
            var key = raw[..eq];
            var value = raw[(eq + 1)..];
            switch (key)
            {
                case "exit":
                    exit = int.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
                    break;
                case "stdin":
                    readStdin = value == "read";
                    break;
                case "delay":
                    delay = int.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
                    break;
                case "write":
                    var bar = value.IndexOf('|', StringComparison.Ordinal);
                    var path = bar < 0 ? value : value[..bar];
                    var content = bar < 0 ? string.Empty : value[(bar + 1)..];
                    var dir = Path.GetDirectoryName(path);
                    if (!string.IsNullOrEmpty(dir))
                        Directory.CreateDirectory(dir);
                    File.WriteAllText(path, content, Utf8);
                    break;
            }
        }

        // Lecture opt-in : une entrée standard héritée (non redirigée) ne se ferme jamais.
        if (readStdin)
        {
            var stdin = Console.In.ReadToEnd();
            if (stdin.Length > 0)
                File.AppendAllText(self + ".stdin", stdin, Utf8);
        }

        if (delay > 0)
            Thread.Sleep(delay);

        using (var o = new StreamWriter(Console.OpenStandardOutput(), Utf8))
            o.Write(stdout.ToString());
        using (var e = new StreamWriter(Console.OpenStandardError(), Utf8))
            e.Write(stderr.ToString());
        return exit;
    }
}
