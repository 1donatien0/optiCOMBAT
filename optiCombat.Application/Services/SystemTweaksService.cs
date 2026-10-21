using Microsoft.Win32;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace optiCombat.Services
{
    /// <summary>
    /// Tweaks système du panneau Optimiser (port C# de l'utilitaire OptiWin —
    /// GUI/OptiWin-GUI.ps1) : performance, confidentialité, interface,
    /// maintenance. L'application tourne en asInvoker : les actions HKCU sont
    /// appliquées directement, les actions nécessitant l'admin (HKLM, services,
    /// DISM, cache Windows Update) sont regroupées dans UN script cmd exécuté
    /// avec une seule invite UAC (<see cref="RunElevatedBatch"/>).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class SystemTweaksService
    {
        // GUID du plan d'alimentation « Performances élevées » (constante Windows).
        private const string HighPerformancePlanGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";

        // ── Helpers registre (HKCU uniquement — pas d'élévation requise) ─────
        private static void SetHkcuValue(string subKey, string name, int value)
        {
            using var key = Registry.CurrentUser.CreateSubKey(subKey, writable: true);
            key.SetValue(name, value, RegistryValueKind.DWord);
        }

        // ── Performance ──────────────────────────────────────────────────────

        /// <summary>Active le plan d'alimentation « Performances élevées ».</summary>
        public static bool EnableHighPerformancePowerPlan()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powercfg.exe",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                psi.ArgumentList.Add("/setactive");
                psi.ArgumentList.Add(HighPerformancePlanGuid);
                using var p = Process.Start(psi);
                p?.WaitForExit(15000);
                return p is { ExitCode: 0 };
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "powercfg /setactive", ex);
                return false;
            }
        }

        /// <summary>Effets visuels sur « Meilleures performances » (effet à la reconnexion).</summary>
        public static bool SetVisualEffectsBestPerformance()
        {
            try
            {
                SetHkcuValue(@"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects",
                    "VisualFXSetting", 2);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "VisualFXSetting", ex);
                return false;
            }
        }

        /// <summary>Ouvre le Gestionnaire des tâches sur l'onglet Démarrage.</summary>
        public static bool OpenStartupAppsManager()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "taskmgr.exe",
                    Arguments = "/0 /startup",
                    UseShellExecute = true,
                });
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "taskmgr /startup", ex);
                return false;
            }
        }

        // ── Confidentialité (HKCU — sans élévation) ──────────────────────────

        /// <summary>Désactive l'identifiant publicitaire.</summary>
        public static bool DisableAdvertisingId()
        {
            try
            {
                SetHkcuValue(@"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                    "Enabled", 0);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "AdvertisingInfo", ex);
                return false;
            }
        }

        /// <summary>Désactive suggestions et publicités (menu Démarrer, écran de verrouillage).</summary>
        public static bool DisableSuggestions()
        {
            const string cdm = @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";
            string[] names =
            {
                "SubscribedContent-338387Enabled", "SubscribedContent-338388Enabled",
                "SubscribedContent-338389Enabled", "SubscribedContent-353694Enabled",
                "SubscribedContent-353696Enabled", "SystemPaneSuggestionsEnabled",
                "SilentInstalledAppsEnabled", "SoftLandingEnabled",
            };
            try
            {
                foreach (var n in names)
                    SetHkcuValue(cdm, n, 0);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "ContentDeliveryManager", ex);
                return false;
            }
        }

        /// <summary>Désactive les expériences personnalisées.</summary>
        public static bool DisableTailoredExperiences()
        {
            try
            {
                SetHkcuValue(@"Software\Microsoft\Windows\CurrentVersion\Privacy",
                    "TailoredExperiencesWithDiagnosticDataEnabled", 0);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "TailoredExperiences", ex);
                return false;
            }
        }

        // ── Interface (HKCU — sans élévation) ────────────────────────────────

        public static bool ShowFileExtensions() => TrySetAdvanced("HideFileExt", 0);
        public static bool ShowHiddenFiles() => TrySetAdvanced("Hidden", 1);
        public static bool AlignTaskbarLeft() => TrySetAdvanced("TaskbarAl", 0);
        public static bool HideTaskbarWidgets() => TrySetAdvanced("TaskbarDa", 0);
        public static bool ExplorerOpensThisPc() => TrySetAdvanced("LaunchTo", 1);

        /// <summary>Réduit la zone de recherche de la barre des tâches à une icône.</summary>
        public static bool SearchBoxAsIcon()
        {
            try
            {
                SetHkcuValue(@"Software\Microsoft\Windows\CurrentVersion\Search",
                    "SearchboxTaskbarMode", 1);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "SearchboxTaskbarMode", ex);
                return false;
            }
        }

        private static bool TrySetAdvanced(string name, int value)
        {
            try
            {
                SetHkcuValue(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                    name, value);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", $"Explorer\\Advanced {name}", ex);
                return false;
            }
        }

        /// <summary>
        /// Redémarre l'Explorateur pour appliquer les tweaks d'interface.
        /// Windows relance explorer.exe automatiquement ; on le relance
        /// nous-mêmes par sécurité si ce n'est pas le cas après 3 s.
        /// </summary>
        public static void RestartExplorer()
        {
            try
            {
                foreach (var p in Process.GetProcessesByName("explorer"))
                {
                    try { p.Kill(); }
                    catch (Exception ex) { AppLogger.Warn("SystemTweaksService", "Kill explorer", ex); }
                    finally { p.Dispose(); }
                }

                _ = Task.Run(async () =>
                {
                    await Task.Delay(3000).ConfigureAwait(false);
                    if (Process.GetProcessesByName("explorer").Length == 0)
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = "explorer.exe",
                            UseShellExecute = true,
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "RestartExplorer", ex);
            }
        }

        // ── Réseau ───────────────────────────────────────────────────────────

        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache", SetLastError = false)]
        private static extern uint DnsFlushResolverCache();

        /// <summary>Vide le cache DNS (sans élévation, via dnsapi.dll).</summary>
        public static bool FlushDnsCache()
        {
            try
            {
                DnsFlushResolverCache();
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "DnsFlushResolverCache", ex);
                return false;
            }
        }

        // ── Actions nécessitant l'élévation (regroupées, une seule invite UAC) ─

        /// <summary>Ligne cmd : télémétrie au minimum + service DiagTrack désactivé.</summary>
        public static IEnumerable<string> ElevatedTelemetryCommands()
        {
            yield return @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"" /v AllowTelemetry /t REG_DWORD /d 0 /f";
            yield return "sc stop DiagTrack";
            yield return "sc config DiagTrack start= disabled";
        }

        /// <summary>Lignes cmd : vidage du cache Windows Update.</summary>
        public static IEnumerable<string> ElevatedWindowsUpdateCacheCommands()
        {
            yield return "net stop wuauserv";
            // Commandes valides sur la ligne de commande (pas de syntaxe batch %%d) : le lot
            // élevé n'est plus écrit dans un script temporaire (voir RunElevatedBatch).
            yield return @"rd /s /q ""%SystemRoot%\SoftwareDistribution\Download""";
            yield return @"mkdir ""%SystemRoot%\SoftwareDistribution\Download""";
            yield return "net start wuauserv";
        }

        /// <summary>Ligne cmd : nettoyage des composants Windows (DISM — lent).</summary>
        public static IEnumerable<string> ElevatedDismCleanupCommands()
        {
            yield return "Dism.exe /Online /Cleanup-Image /StartComponentCleanup";
        }

        /// <summary>Longueur maximale d'une ligne de commande cmd.exe (8191) moins une marge.</summary>
        private const int MaxCmdLineLength = 8000;

        /// <summary>
        /// Construit les arguments de <c>cmd.exe</c> exécutant toutes les commandes à la suite
        /// (<c>&amp;</c> : on continue même si l'une échoue, comme l'ancien script).
        /// <c>/s</c> : cmd retire seulement le premier et le dernier guillemet, le reste est
        /// transmis tel quel.
        /// </summary>
        public static string BuildElevatedCommandLine(IEnumerable<string> commandLines)
        {
            var list = commandLines.Where(l => !string.IsNullOrWhiteSpace(l)).ToList();
            if (list.Any(l => l.IndexOfAny(['\r', '\n']) >= 0))
                throw new ArgumentException("Saut de ligne interdit dans une commande élevée.", nameof(commandLines));
            var args = "/d /s /c \"" + string.Join(" & ", list) + "\"";
            if (args.Length > MaxCmdLineLength)
                throw new ArgumentException("Lot de commandes élevées trop long pour cmd.exe.", nameof(commandLines));
            return args;
        }

        /// <summary>
        /// Exécute les commandes en administrateur (une seule invite UAC pour tout le lot).
        /// <para>
        /// Audit 360 : les commandes étaient écrites dans un script .cmd de <c>%TEMP%</c> puis
        /// exécutées élevées — pendant l'affichage de l'invite UAC, n'importe quel processus de
        /// l'utilisateur pouvait réécrire le script (élévation de privilèges). Elles sont
        /// désormais passées directement sur la ligne de commande, figée au moment de la demande.
        /// </para>
        /// Renvoie false si l'utilisateur refuse l'invite UAC ou en cas d'erreur.
        /// </summary>
        public static bool RunElevatedBatch(IEnumerable<string> commandLines, bool waitForExit)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                    Arguments = BuildElevatedCommandLine(commandLines),
                    UseShellExecute = true,   // requis pour Verb=runas
                    Verb = "runas",           // invite UAC
                    WindowStyle = ProcessWindowStyle.Minimized,
                };

                using var p = Process.Start(psi);
                if (p == null)
                    return false;
                if (waitForExit)
                    p.WaitForExit();
                return true;
            }
            catch (System.ComponentModel.Win32Exception wex)
                when (wex.NativeErrorCode == 1223) // ERROR_CANCELLED : UAC refusé
            {
                AppLogger.Info("SystemTweaksService", "Élévation refusée par l'utilisateur");
                return false;
            }
            catch (Exception ex)
            {
                AppLogger.Error("SystemTweaksService", "RunElevatedBatch", ex);
                return false;
            }
        }

        /// <summary>Ouvre les paramètres Windows Update.</summary>
        public static bool OpenWindowsUpdateSettings()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "ms-settings:windowsupdate",
                    UseShellExecute = true,
                });
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SystemTweaksService", "ms-settings:windowsupdate", ex);
                return false;
            }
        }
    }
}
