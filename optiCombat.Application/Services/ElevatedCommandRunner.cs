using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;

namespace optiCombat.Services
{
    /// <summary>
    /// Exécute un lot de commandes système en administrateur, avec UNE seule invite UAC
    /// (<c>cmd.exe /d /c cmd1 &amp;&amp; cmd2 …</c>, verbe <c>runas</c>, fenêtre masquée).
    /// Les commandes doivent être construites par l'application : aucune donnée utilisateur brute
    /// (voir <see cref="IsSafeArgument"/>).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class ElevatedCommandRunner
    {
        /// <summary>Ligne de commande passée à <c>cmd.exe</c> (testable).</summary>
        public static string BuildArguments(IReadOnlyList<string> commands) =>
            "/d /c " + string.Join(" && ", commands);

        /// <summary>Refuse les métacaractères cmd.exe dans une valeur insérée dans une commande.</summary>
        public static bool IsSafeArgument(string value) =>
            !string.IsNullOrWhiteSpace(value)
            && value.IndexOfAny(['&', '|', '<', '>', '^', '%', '"', '\r', '\n', '!', '(', ')']) < 0;

        /// <summary>Vrai si le lot a été accepté (UAC) et, si attendu, s'est terminé avec le code 0.</summary>
        public static bool RunElevatedBatch(IReadOnlyList<string> commands, bool waitForExit, int timeoutMs = 120_000)
        {
            if (commands.Count == 0)
                return true;

            try
            {
                var outcome = SystemShell.Current.Run(new ProcessStartInfo
                {
                    FileName = Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                    Arguments = BuildArguments(commands),
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden,
                }, waitForExit ? timeoutMs : null);
                if (outcome.Cancelled)
                {
                    AppLogger.Info("ElevatedCommandRunner", "Élévation refusée par l'utilisateur");
                    return false;
                }
                if (!waitForExit)
                    return outcome.Started;
                return outcome.Succeeded;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ElevatedCommandRunner", "RunElevatedBatch", ex);
                return false;
            }
        }
    }
}
