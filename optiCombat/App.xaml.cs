using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using System.Windows;
using WinApplication = System.Windows.Application;

namespace optiCombat
{
    /// <summary>
    /// Point d'entrée de l'application WPF optiCombat.
    /// Gère l'instance unique (mutex), le mode headless (scans planifiés sans UI)
    /// et l'initialisation du thème au démarrage.
    /// </summary>
    public partial class App : WinApplication
    {
        private static Mutex? _instanceMutex;
        private const string MutexName = "Global\\optiCombat_UniqueInstance";

        /// <summary>Session garde : RTP active, fenêtre masquée (systray).</summary>
        public static bool GuardSession { get; private set; }

        /// <summary>Chemin en attente depuis le menu contextuel Explorateur (<c>--scan</c>).</summary>
        public static string? PendingShellScanPath { get; internal set; }

        /// <summary>
        /// Appelé au démarrage de l'application. Gère dans l'ordre :
        /// le mode headless (scan sans UI), puis le contrôle d'instance unique,
        /// et enfin l'initialisation du thème pour le mode normal.
        /// </summary>
        protected override async void OnStartup(StartupEventArgs e)
        {
            // Avant TOUT : capter les exceptions non gérées. Sans cela, une exception
            // au démarrage tue le process silencieusement (« l'app disparaît du
            // gestionnaire des tâches sans message »). Désormais elles sont
            // journalisées (%LOCALAPPDATA%\optiCombat\Logs) et affichées à l'écran.
            InstallGlobalCrashHandlers();

            // Rendu : sur certains environnements (session distante/RDP, VM, pilote GPU
            // partiel), l'accélération matérielle WPF peint la fenêtre en NOIR alors que
            // la barre de titre s'affiche. On bascule en rendu logiciel dans ces cas pour
            // garantir l'affichage (app peu gourmande en graphismes — impact négligeable).
            ConfigureSafeRendering();

            LocalizationService.Initialize();

            if (ShellScanArguments.TryGetScanPath(e.Args, out var shellPath)
                && ElevationHelper.NeedsElevation(shellPath)
                && !ElevationHelper.IsRunningElevated())
            {
                if (ElevationHelper.RelaunchElevated(ShellScanArguments.Scan, shellPath))
                {
                    Shutdown();
                    return;
                }
            }

            // ── Mode headless ────────────────────────────────────────────────
            // Détecté en premier pour éviter d'afficher la fenêtre principale.
            // ScheduledScanService crée la tâche schtasks avec --fullscan --quiet ;
            // sans ce parsing, l'app se lançait simplement avec son UI.
            var headlessMode = HeadlessScanArguments.ParseMode(e.Args);
            if (headlessMode == HeadlessScanArguments.Mode.Watchdog)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                base.OnStartup(e);
                TamperProtectionService.RunWatchdogCheck();
                Shutdown();
                return;
            }

            if (headlessMode == HeadlessScanArguments.Mode.DefenderExclusions)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                base.OnStartup(e);
                WindowsDefenderExclusionService.EnsureOpticombatExclusions();
                Shutdown();
                return;
            }

            if (headlessMode == HeadlessScanArguments.Mode.ServiceHost)
            {
                bool createdService;
                _instanceMutex = new Mutex(true, "Global\\optiCombat_ServiceHost", out createdService);
                if (!createdService)
                {
                    Shutdown();
                    return;
                }

                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                await RunServiceHostAsync();
                Shutdown();
                return;
            }

            if (headlessMode is HeadlessScanArguments.Mode.FullScan or HeadlessScanArguments.Mode.QuickScan)
            {
                bool createdHeadless;
                _instanceMutex = new Mutex(true, MutexName, out createdHeadless);
                if (!createdHeadless)
                {
                    try { new ScanLogManager().WriteToLog("[Headless] Instance déjà active — scan ignoré."); }
                    catch { /* ignore */ }
                    _instanceMutex.Close();
                    _instanceMutex = null;
                    Shutdown();
                    return;
                }

                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                base.OnStartup(e);
                await RunHeadlessAsync(headlessMode, HeadlessScanArguments.IsQuiet(e.Args));
                Shutdown();
                return;
            }

            // ── Single-instance ──────────────────────────────────────────────
            bool createdNew;
            _instanceMutex = new Mutex(true, MutexName, out createdNew);

            if (!createdNew)
            {
                if (ShellScanArguments.TryGetScanPath(e.Args, out var existingScanPath)
                    && ShellScanArguments.IsValidScanTarget(existingScanPath))
                {
                    ShellScanRequest.Publish(existingScanPath);
                    Services.IpcManager.NotifyShellScanRequest();
                }

                // Une autre instance tourne : on lui demande de remonter sa fenêtre
                // via le message broadcast géré par IpcManager.
                Services.IpcManager.NotifyShowExistingInstance();
                _instanceMutex.Close();
                _instanceMutex = null;
                Shutdown();
                return;
            }

            if (ShellScanArguments.TryGetScanPath(e.Args, out var pendingShellPath)
                && ShellScanArguments.IsValidScanTarget(pendingShellPath))
            {
                PendingShellScanPath = pendingShellPath;
            }

            GuardSession = headlessMode == HeadlessScanArguments.Mode.Guard
                || headlessMode == HeadlessScanArguments.Mode.ServiceHost;

            base.OnStartup(e);
            // Thème : ThemeManager.Initialize() dans MainWindow (avant InitializeComponent).
        }

        // ── Gestion globale des exceptions non gérées ────────────────────────────

        /// <summary>
        /// Branche les trois sources d'exceptions non gérées d'une app WPF :
        /// le thread UI (Dispatcher), les autres threads (AppDomain) et les
        /// tâches non observées (TaskScheduler). Garantit qu'aucun crash ne
        /// reste invisible : tout est journalisé et présenté à l'utilisateur.
        /// </summary>
        private void InstallGlobalCrashHandlers()
        {
            DispatcherUnhandledException += (_, args) =>
            {
                LogFatal("Dispatcher", args.Exception);
                var recoverable = IsRecoverableDispatcherException(args.Exception);
                ShowCrashDialog(args.Exception, CrashDialogKind.Dispatcher, terminating: !recoverable);
                args.Handled = recoverable;
            };

            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            {
                if (args.ExceptionObject is Exception ex)
                {
                    LogFatal("AppDomain", ex);
                    ShowCrashDialog(ex, CrashDialogKind.AppDomain, terminating: args.IsTerminating);
                }
            };

            System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, args) =>
            {
                LogFatal("UnobservedTask", args.Exception);
                args.SetObserved();
                ShowCrashDialog(
                    args.Exception.GetBaseException(),
                    CrashDialogKind.BackgroundTask);
            };
        }

        private enum CrashDialogKind
        {
            Dispatcher,
            AppDomain,
            BackgroundTask,
        }

        /// <summary>
        /// Exceptions UI récupérables : l'utilisateur peut lire le message et continuer.
        /// Les autres provoquent un arrêt propre après fermeture du dialogue.
        /// </summary>
        private static bool IsRecoverableDispatcherException(Exception ex) =>
            ex is not (StackOverflowException or OutOfMemoryException or AccessViolationException);

        private static void LogFatal(string source, Exception ex)
        {
            try { Services.AppLogger.Fatal("UnhandledException", source, ex); }
            catch { /* le logging ne doit jamais aggraver un crash */ }
        }

        private static void ShowCrashDialog(
            Exception ex,
            CrashDialogKind kind,
            bool terminating = false)
        {
            try
            {
                var title = kind switch
                {
                    CrashDialogKind.BackgroundTask => "optiCombat — Erreur en arrière-plan",
                    _ when Current?.MainWindow == null => "optiCombat — Erreur au démarrage",
                    _ => "optiCombat — Erreur inattendue",
                };

                var message =
                    "optiCombat a rencontré une erreur non gérée :\n\n" +
                    ex.GetType().Name + " : " + ex.Message + "\n\n" +
                    "Détails complets (stack trace) enregistrés dans :\n" +
                    "%LOCALAPPDATA%\\optiCombat\\Logs";

                if (terminating)
                    message += "\n\nL'application va se fermer.";

                void Show()
                {
                    System.Windows.MessageBox.Show(
                        message,
                        title,
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Error);

                    if (terminating && Current != null)
                        Current.Shutdown(-1);
                }

                var dispatcher = Current?.Dispatcher;
                if (dispatcher != null && !dispatcher.CheckAccess())
                    dispatcher.Invoke(Show);
                else
                    Show();
            }
            catch { /* pas d'UI disponible (mode headless) → log seul */ }
        }

        /// <summary>
        /// Force le rendu logiciel WPF. Sur les environnements sans accélération
        /// matérielle fiable (RDP/VM/pilote GPU partiel), le rendu matériel peint la
        /// fenêtre en NOIR (barre de titre visible, contenu noir). Le rendu logiciel
        /// rend exactement la même chose côté CPU ; impact négligeable pour cette UI.
        /// </summary>
        private static void ConfigureSafeRendering()
        {
            try
            {
                System.Windows.Media.RenderOptions.ProcessRenderMode =
                    System.Windows.Interop.RenderMode.SoftwareOnly;
            }
            catch (Exception ex)
            {
                Services.AppLogger.Warn("App", "ConfigureSafeRendering", ex);
            }
        }

        // ── Headless ────────────────────────────────────────────────────────────

        /// <summary>
        /// Exécute un scan en mode headless (sans fenêtre WPF), persiste le résultat
        /// dans l'historique et déclenche la quarantaine automatique si configurée.
        /// </summary>
        private static async Task RunHeadlessAsync(HeadlessScanArguments.Mode mode, bool quiet)
        {
            try
            {
                var container = ServiceContainer.Default;
                var orchestrator = container.Orchestrator;
                var quarantine = container.Quarantine;
                var logger = container.Logger;

                logger.WriteToLog($"[Headless] Démarrage — mode {mode}, quiet={quiet}");

                DistractionFreeMonitor.Start();
                if (container.UserPreferencesAccessor.Current.GameModeAutoEnabled
                    && DistractionFreeMonitor.ShouldSuppressNotifications())
                {
                    logger.WriteToLog("[Headless] Scan reporté — mode jeu / plein écran actif.");
                    return;
                }

                if (mode == HeadlessScanArguments.Mode.FullScan && !ElevationHelper.IsRunningElevated())
                    logger.WriteToLog("[Headless] Analyse complète sans élévation — dossiers système partiels.");

                ScanResult result = mode switch
                {
                    HeadlessScanArguments.Mode.FullScan => await orchestrator.FullScanAsync(),
                    HeadlessScanArguments.Mode.QuickScan => await orchestrator.QuickScanAsync(),
                    _ => throw new InvalidOperationException("Mode headless non supporté")
                };

                logger.SaveScanResult(result);
                logger.WriteToLog(
                    $"[Headless] Terminé — {result.FilesScanned} fichier(s), " +
                    $"{result.ThreatsFound} menace(s), statut {result.Status}");

                // Quarantaine automatique en mode headless si l'utilisateur l'a
                // configurée — sinon les menaces sont simplement journalisées.
                if (container.ExclusionSettingsAccessor.Current.AutoQuarantineEnabled)
                {
                    int q = quarantine.QuarantineAll(result.Threats, result.SessionId);
                    logger.WriteToLog($"[Headless] Quarantaine automatique : {q} fichier(s)");
                }

                // Notification optionnelle de fin (sauf si --quiet)
                if (!quiet && result.ThreatsFound > 0)
                {
                    try
                    {
                        container.Notifications.ShowScanCompleted(result.ThreatsFound, result.FilesScanned);
                    }
                    catch (Exception ex)
                    {
                        logger.WriteToLog($"[Headless] Notification: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                // En mode headless, pas d'UI pour afficher l'erreur — log only.
                try { new ScanLogManager().WriteToLog($"[Headless] FATAL: {ex}"); }
                catch { /* dernier recours */ }
            }
        }

        private static async Task RunServiceHostAsync()
        {
            try
            {
                ProtectionScanGateway.IsServiceHostProcess = true;
                using var host = new ProtectionServiceHost(ServiceContainer.Default);
                host.Start();
                new ScanLogManager().WriteToLog("[ServiceHost] Protection système active (IPC + RTP + processus)");

                var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                AppDomain.CurrentDomain.ProcessExit += (_, _) => tcs.TrySetResult();
                Console.CancelKeyPress += (_, e) =>
                {
                    e.Cancel = true;
                    tcs.TrySetResult();
                };
                await tcs.Task.ConfigureAwait(false);
                await host.StopAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                try { new ScanLogManager().WriteToLog($"[ServiceHost] FATAL: {ex}"); }
                catch { /* ignore */ }
            }
        }

        /// <summary>
        /// Appelé à la fermeture de l'application. Libère le mutex d'instance unique
        /// et délègue à <see cref="ServiceContainer.Shutdown"/> pour disposer les services.
        /// </summary>
        protected override void OnExit(ExitEventArgs e)
        {
            // ReleaseMutex doit être appelé sur le même thread que celui qui a
            // appelé WaitOne/Constructor. WPF garantit OnStartup et OnExit sur
            // le thread UI, donc c'est OK ici. On enrobe quand même en try
            // pour le cas où la mutex serait déjà libérée (ApplicationException).
            if (_instanceMutex != null)
            {
                try { _instanceMutex.ReleaseMutex(); }
                catch (ApplicationException ex)
                {
                    // Mutex non détenue par le thread courant — incohérence.
                    Services.AppLogger.Warn("App", "ReleaseMutex sur mauvais thread", ex);
                }
                catch (Exception ex)
                {
                    Services.AppLogger.Warn("App", "ReleaseMutex", ex);
                }
                try { _instanceMutex.Dispose(); } catch { }
                _instanceMutex = null;
            }
            base.OnExit(e);
            try { Services.ServiceContainer.Default.Shutdown(); }
            catch (Exception ex) { Services.AppLogger.Warn("App", "ServiceContainer.Shutdown", ex); }
        }
    }

    // NativeMethods retiré : la logique IPC est désormais dans
    // Logique IPC : Services.IpcManager.
}