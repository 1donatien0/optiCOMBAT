using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Xml.Linq;

namespace optiCombat.Services
{
    /// <summary>
    /// Gère la création et la suppression d'une tâche planifiée Windows
    /// pour un scan quotidien automatique, via schtasks.exe (outil natif Windows).
    /// Aucune dépendance NuGet requise.
    /// </summary>
    public class ScheduledScanService : IScheduledScanService
    {
        private const string TaskName = "optiCombat_DailyScan";
        private readonly string _exePath;
        private TimeSpan _scheduledTime = TimeSpan.FromHours(2);

        public ScheduledScanService()
        {
            _exePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "optiCombat.exe");
        }

        /// <summary>
        /// Crée la tâche planifiée pour un scan quotidien.
        /// Par défaut à 02h00 du matin.
        /// </summary>
        public bool CreateDailyScan(TimeSpan? time = null)
        {
            try
            {
                _scheduledTime = time ?? TimeSpan.FromHours(2);
                var startTime = $"{_scheduledTime.Hours:D2}:{_scheduledTime.Minutes:D2}";

                DeleteTask();

                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                psi.ArgumentList.Add("/Create");
                psi.ArgumentList.Add("/TN");
                psi.ArgumentList.Add(TaskName);
                psi.ArgumentList.Add("/TR");
                // Ne pas entourer manuellement de guillemets : ArgumentList échappe correctement pour schtasks.
                psi.ArgumentList.Add($"{_exePath} --fullscan --quiet");
                psi.ArgumentList.Add("/SC");
                psi.ArgumentList.Add("DAILY");
                psi.ArgumentList.Add("/ST");
                psi.ArgumentList.Add(startTime);
                // Moindre privilège : /RL LIMITED évite d'exécuter la tâche
                // avec le niveau « le plus élevé » du compte utilisateur (HIGHEST).
                // Si un scan planifié doit accéder à des chemins protégés, préférer
                // une élévation ponctuelle (ElevationHelper) plutôt qu'une tâche HIGHEST.
                psi.ArgumentList.Add("/RL");
                psi.ArgumentList.Add("LIMITED");
                psi.ArgumentList.Add("/F");

                return RunSchtasksCapture(psi).ExitCode == 0;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScheduledScanService", "Erreur création tâche planifiée", ex);
                return false;
            }
        }

        /// <summary>
        /// Supprime la tâche planifiée.
        /// </summary>
        public bool DeleteTask()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                psi.ArgumentList.Add("/Delete");
                psi.ArgumentList.Add("/TN");
                psi.ArgumentList.Add(TaskName);
                psi.ArgumentList.Add("/F");
                RunSchtasksCapture(psi);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScheduledScanService", "DeleteTask", ex);
                return false;
            }
        }

        /// <summary>
        /// Vérifie si la tâche existe.
        /// </summary>
        public bool IsTaskExists()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                psi.ArgumentList.Add("/Query");
                psi.ArgumentList.Add("/TN");
                psi.ArgumentList.Add(TaskName);
                return RunSchtasksCapture(psi).ExitCode == 0;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScheduledScanService", "IsTaskExists", ex);
                return false;
            }
        }

        /// <summary>
        /// Prochaine exécution : lue depuis la tâche Windows (XML / LIST) si possible,
        /// sinon dérivée de <see cref="_scheduledTime"/> (mémoire processus).
        /// </summary>
        public DateTime? GetNextRunTime()
        {
            try
            {
                if (!IsTaskExists())
                    return FallbackFromScheduledMemory();

                // 1) XML — indépendant de la locale pour l'heure du trigger
                var xmlPsi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                xmlPsi.ArgumentList.Add("/Query");
                xmlPsi.ArgumentList.Add("/TN");
                xmlPsi.ArgumentList.Add(TaskName);
                xmlPsi.ArgumentList.Add("/XML");

                var xmlRes = RunSchtasksCapture(xmlPsi);
                if (xmlRes.ExitCode == 0 && TryParseNextRunFromTaskXml(xmlRes.CombinedOutput, out var fromXml))
                    return fromXml;

                // 2) LIST /V — « Next Run Time » / « Prochaine exécution » (locale Windows)
                var listPsi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                listPsi.ArgumentList.Add("/Query");
                listPsi.ArgumentList.Add("/TN");
                listPsi.ArgumentList.Add(TaskName);
                listPsi.ArgumentList.Add("/FO");
                listPsi.ArgumentList.Add("LIST");
                listPsi.ArgumentList.Add("/V");

                var listRes = RunSchtasksCapture(listPsi);
                if (listRes.ExitCode == 0 && TryParseNextRunFromListOutput(listRes.CombinedOutput, out var fromList))
                    return fromList;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScheduledScanService", "GetNextRunTime — repli sur heure mémoire", ex);
            }

            return FallbackFromScheduledMemory();
        }

        /// <summary>
        /// Exécute la tâche immédiatement.
        /// </summary>
        public bool RunNow()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                psi.ArgumentList.Add("/Run");
                psi.ArgumentList.Add("/TN");
                psi.ArgumentList.Add(TaskName);
                return RunSchtasksCapture(psi).ExitCode == 0;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScheduledScanService", "RunNow", ex);
                return false;
            }
        }

        private DateTime? FallbackFromScheduledMemory()
        {
            var next = DateTime.Today + _scheduledTime;
            if (next <= DateTime.Now)
                next = next.AddDays(1);
            return next;
        }

        internal static bool TryParseNextRunFromTaskXml(string xml, out DateTime next)
        {
            next = default;
            try
            {
                var doc = XDocument.Parse(xml);
                foreach (var el in doc.Descendants())
                {
                    if (!string.Equals(el.Name.LocalName, "StartBoundary", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var text = el.Value.Trim();
                    if (string.IsNullOrEmpty(text)) continue;

                    if (!DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var anchor)
                        && !DateTime.TryParse(text, CultureInfo.CurrentCulture, DateTimeStyles.None, out anchor))
                        continue;

                    var timeOfDay = anchor.TimeOfDay;
                    var candidate = DateTime.Today + timeOfDay;
                    if (candidate <= DateTime.Now)
                        candidate = candidate.AddDays(1);
                    next = candidate;
                    return true;
                }
            }
            catch
            {
                return false;
            }

            return false;
        }

        internal static bool TryParseNextRunFromListOutput(string text, out DateTime next)
        {
            next = default;
            foreach (var raw in text.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None))
            {
                var line = raw.Trim();
                string? val = null;

                if (line.StartsWith("Next Run Time:", StringComparison.OrdinalIgnoreCase))
                    val = line["Next Run Time:".Length..].Trim();
                else if (line.StartsWith("Prochaine exécution", StringComparison.OrdinalIgnoreCase))
                {
                    var idx = line.IndexOf(':');
                    if (idx >= 0 && idx + 1 < line.Length)
                        val = line[(idx + 1)..].Trim();
                }
                else if (line.StartsWith("Heure de début suivante", StringComparison.OrdinalIgnoreCase))
                {
                    var idx = line.IndexOf(':');
                    if (idx >= 0 && idx + 1 < line.Length)
                        val = line[(idx + 1)..].Trim();
                }

                if (string.IsNullOrEmpty(val) || val.Equals("N/A", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (DateTime.TryParse(val, CultureInfo.CurrentCulture, DateTimeStyles.None, out next))
                    return true;
                if (DateTime.TryParse(val, CultureInfo.InvariantCulture, DateTimeStyles.None, out next))
                    return true;
            }

            return false;
        }

        private readonly record struct SchtasksResult(int ExitCode, string StdOut, string StdErr)
        {
            public string CombinedOutput
            {
                get
                {
                    var sb = new StringBuilder();
                    if (!string.IsNullOrEmpty(StdOut)) sb.AppendLine(StdOut);
                    if (!string.IsNullOrEmpty(StdErr)) sb.AppendLine(StdErr);
                    return sb.ToString();
                }
            }
        }

        private static SchtasksResult RunSchtasksCapture(ProcessStartInfo psi)
        {
            using var p = Process.Start(psi)
                ?? throw new InvalidOperationException("Impossible de démarrer schtasks.exe");

            // Lecture CONCURRENTE stdout + stderr : la lecture séquentielle
            // (ReadToEnd puis ReadToEnd) peut bloquer indéfiniment si le process
            // remplit le buffer interne stderr pendant qu'on attend la fin de
            // stdout, et vice-versa (deadlock documenté par Microsoft).
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();

            bool finished = Task.WhenAll(stdoutTask, stderrTask)
                .Wait(TimeSpan.FromSeconds(15));
            if (!finished)
            {
                try { p.Kill(entireProcessTree: true); }
                catch (Exception ex)
                {
                    AppLogger.Warn("ScheduledScanService", "schtasks timeout — Kill", ex);
                }
            }

            p.WaitForExit(1_000);

            return new SchtasksResult(
                p.ExitCode,
                stdoutTask.IsCompletedSuccessfully ? stdoutTask.Result : string.Empty,
                stderrTask.IsCompletedSuccessfully ? stderrTask.Result : string.Empty);
        }
    }
}
