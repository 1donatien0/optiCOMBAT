using System.Diagnostics;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace optiCombat.Services
{
    /// <summary>
    /// Helpers pour une élévation UAC ponctuelle lorsque l'opération le requiert.
    ///
    /// Avant cette session, optiCombat tournait en administrateur en permanence
    /// (manifest requireAdministrator). Toute faille → escalade SYSTEM directe.
    /// Maintenant, l'app tourne en asInvoker (utilisateur normal) et ne demande
    /// l'élévation que ponctuellement, pour les opérations qui en ont vraiment
    /// besoin (scan C:\Windows, suppression dans Program Files).
    ///
    /// Pattern d'usage :
    ///   if (ElevationHelper.NeedsElevation(path))
    ///   {
    ///       if (!ElevationHelper.IsRunningElevated())
    ///       {
    ///           var ok = ElevationHelper.RelaunchElevated("--scan", path);
    ///           if (ok) Application.Current.Shutdown();
    ///           return;
    ///       }
    ///   }
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class ElevationHelper
    {
        /// <summary>
        /// Vérifie si le process courant tourne avec les droits administrateur.
        /// </summary>
        public static bool IsRunningElevated()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ElevationHelper", "IsRunningElevated", ex);
                return false;
            }
        }

        /// <summary>
        /// Indique si un chemin nécessite typiquement les droits admin pour
        /// être scanné/modifié. Liste blanche conservatrice : System32,
        /// SysWOW64, Windows, Program Files.
        /// </summary>
        public static bool NeedsElevation(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            try
            {
                var full = System.IO.Path.GetFullPath(path);
                string[] roots =
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                };
                static string Normalize(string p) =>
                    System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(p));

                var target = Normalize(full);
                foreach (var r in roots)
                {
                    if (string.IsNullOrEmpty(r)) continue;
                    var root = Normalize(r);
                    if (target.Equals(root, StringComparison.OrdinalIgnoreCase)
                        || target.StartsWith(root + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// Relance optiCombat en mode administrateur avec les arguments donnés.
        /// Affiche le dialogue UAC à l'utilisateur. Retourne true si lancement
        /// confirmé, false si l'utilisateur a refusé (ou erreur).
        ///
        /// IMPORTANT : après un relaunch réussi, le caller doit fermer l'instance
        /// courante (Application.Current.Shutdown). On laisse cette décision au
        /// code appelant pour permettre un éventuel "lance + attends + récupère
        /// résultat" si jamais on en a besoin plus tard.
        /// </summary>
        public static bool RelaunchElevated(params string[] args)
        {
            try
            {
                var exe = Environment.ProcessPath
                    ?? Assembly.GetEntryAssembly()?.Location
                    ?? throw new InvalidOperationException("Chemin exécutable indéterminable");

                var psi = new ProcessStartInfo
                {
                    FileName = exe,
                    UseShellExecute = true,   // requis pour Verb=runas
                    Verb = "runas",           // déclenche l'invite UAC
                };
                foreach (var a in args) psi.ArgumentList.Add(a);

                var p = Process.Start(psi);
                AppLogger.Info("ElevationHelper", $"Relaunch élevé : pid={p?.Id}");
                return p != null;
            }
            catch (System.ComponentModel.Win32Exception wex)
                when (wex.NativeErrorCode == 1223) // ERROR_CANCELLED
            {
                AppLogger.Info("ElevationHelper", "Élévation refusée par l'utilisateur");
                return false;
            }
            catch (Exception ex)
            {
                AppLogger.Error("ElevationHelper", "RelaunchElevated", ex);
                return false;
            }
        }
    }
}
