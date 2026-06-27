using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;

namespace optiCombat
{
    /// <summary>
    /// Capteur de crash de tout premier niveau. S'arme via [ModuleInitializer],
    /// donc AVANT la méthode Main générée et avant App.InitializeComponent() :
    /// il capture les exceptions de démarrage que le filet de App.xaml.cs
    /// (installé seulement dans OnStartup) ne peut pas voir.
    ///
    /// Écrit la trace complète dans deux emplacements pour fiabilité :
    ///   %LOCALAPPDATA%\optiCombat\Logs\startup-crash.log
    ///   &lt;dossier de l'exe&gt;\startup-crash.log   (repli)
    ///
    /// Diagnostic uniquement : n'altère pas le comportement de l'application.
    /// </summary>
    internal static class StartupDiagnostics
    {
        [ModuleInitializer]
        internal static void Arm()
        {
            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            {
                if (e.ExceptionObject is Exception ex)
                {
                    TryWrite("UnhandledException (terminating=" + e.IsTerminating + ")", ex);
                }
            };
        }

        private static void TryWrite(string context, Exception ex)
        {
            var sb = new StringBuilder();
            sb.AppendLine("══════════════════════════════════════════════════════");
            sb.AppendLine($"[{DateTime.Now:O}] optiCombat — crash de démarrage");
            sb.AppendLine($"Contexte : {context}");
            sb.AppendLine($"Process  : {Environment.ProcessPath}");
            sb.AppendLine($"OS       : {Environment.OSVersion} / .NET {Environment.Version}");
            sb.AppendLine("──────────────────────────────────────────────────────");
            sb.AppendLine(ex.ToString()); // type + message + stack + inner exceptions
            sb.AppendLine();

            foreach (var path in CandidatePaths())
            {
                try
                {
                    var dir = Path.GetDirectoryName(path);
                    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                    File.AppendAllText(path, sb.ToString());
                }
                catch { /* un emplacement peut échouer ; on tente le suivant */ }
            }
        }

        private static string[] CandidatePaths()
        {
            string local;
            try
            {
                local = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "optiCombat", "Logs", "startup-crash.log");
            }
            catch { local = string.Empty; }

            string nextToExe;
            try { nextToExe = Path.Combine(AppContext.BaseDirectory, "startup-crash.log"); }
            catch { nextToExe = string.Empty; }

            return new[] { local, nextToExe };
        }
    }
}
