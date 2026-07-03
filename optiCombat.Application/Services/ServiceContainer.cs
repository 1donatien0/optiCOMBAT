using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using optiCombat.Localization;

namespace optiCombat.Services
{
    /// <summary>
    /// Regroupe les services à longue durée de vie (singleton <see cref="Default"/>).
    /// Construction via <see cref="Microsoft.Extensions.DependencyInjection"/>.
    /// Points d'entrée légitimes pour <see cref="Default"/> : <see cref="App"/> (bootstrap),
    /// <see cref="ProtectionServiceHost"/>, et <see cref="ViewModels.ScanViewModel"/> sans paramètre (designer).
    /// Les vues reçoivent <see cref="IViewServices"/> / <see cref="IOptionsServices"/> via <c>Bind()</c>.
    /// Le bus UI est implémenté par <see cref="UiEventBus"/> (singleton DI partagé).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class ServiceContainer : IViewServices, IHistoryServices, IOptionsServices, IProtectionServiceHostDependencies
    {
        private static readonly Lazy<ServiceContainer> _default =
            new(() => new ServiceContainer(), LazyThreadSafetyMode.ExecutionAndPublication);

        public static ServiceContainer Default => _default.Value;

        /// <summary>Bus UI (événements inter-panneaux) — même instance que <see cref="Default"/>.</summary>
        public static IUiEventBus UiEvents => Default._uiEventBus;

        /// <summary>Façade vues (bus + services) — même instance que <see cref="Default"/>.</summary>
        public static IViewServices Views => Default;

        private readonly IServiceProvider _services;
        private readonly UiEventBus _uiEventBus;
        private readonly IUserPreferencesAccessor _userPreferences;
        private readonly IExclusionSettingsAccessor _exclusionSettings;
        private bool _shutdownDone;

        // ── Services singleton ───────────────────────────────────────────────────
        public ClamAvEngine ClamAv { get; }

        /// <summary>Moteur Clam effectif (clamd avec repli clamscan).</summary>
        internal CompositeClamAvBackend ClamAvBackend { get; }

        /// <summary><c>clamd</c> ou <c>clamscan</c> selon le dernier scan.</summary>
        public string ClamActiveEngine => ClamAvBackend.ActiveEngine;
        public YaraEngine Yara { get; }
        public ScanOrchestrator Orchestrator { get; }
        public FreshclamUpdater FreshclamUpdater { get; }
        public YaraForgeUpdater RulesUpdater { get; }
        public QuarantineManager Quarantine { get; }
        public ScanLogManager Logger { get; }
        public ActivityLogService ActivityLog { get; }
        public NotificationService Notifications { get; }
        /// <summary>Protection temps réel (désactivable via Options / exclusions).</summary>
        public RealTimeProtection RealTimeProtection { get; }

        /// <summary>Surveillance WMI des lancements de processus.</summary>
        public ProcessStartMonitor ProcessStartMonitor { get; }

        /// <summary>Watchdog planifié contre l'arrêt non autorisé de la protection.</summary>
        public TamperProtectionService TamperProtection { get; }

        /// <summary>Scan automatique des lecteurs amovibles à l'insertion.</summary>
        public RemovableDriveScanService RemovableDriveScan { get; }

        /// <summary>Tâche planifiée Windows (schtasks) — instance partagée pour Options et diagnostics.</summary>
        public ScheduledScanService ScheduledScan { get; }

        // Adapters interfaces — à utiliser pour les futurs tests ou substitutions
        public IScanEngine ScanEngine { get; }

        /// <summary>Actions UI antivirus (quarantaine, suppression, stop updates).</summary>
        public AntivirusActions Actions { get; }

        public ThreatReputationService ThreatReputation { get; }

        public CloudThreatIntelService CloudThreatIntel { get; }

        public ISecurityPostureService SecurityPosture { get; }

        /// <summary>Versions signatures ClamAV/YARA avec cache TTL (accueil, onglet Signatures).</summary>
        public SignatureStatusService SignatureStatus { get; }

        // Navigation entre panneaux. Initialisé par MainWindow.OnLoaded une fois
        // que tous les UserControls sont créés (RegisterPanel a besoin de leur
        // référence). Les vues peuvent alors appeler Navigation.NavigateTo("...")
        // sans connaître MainWindow.
        public INavigationService? Navigation { get; set; }

        /// <summary>Résout une menace connue par chemin (liste live du ViewModel, enregistrée par MainWindow).</summary>
        public Func<string, Models.ThreatInfo?>? ThreatLookup { get; set; }

        public Models.ThreatInfo? FindKnownThreat(string filePath) =>
            string.IsNullOrEmpty(filePath) ? null : ThreatLookup?.Invoke(filePath);

        public IUserPreferencesAccessor UserPreferencesAccessor => _userPreferences;

        public IExclusionSettingsAccessor ExclusionSettingsAccessor => _exclusionSettings;

        /// <summary>
        /// Émis par une vue qui veut déclencher une mise à jour manuelle des
        /// signatures (ex. carte « Mise à jour » de l’accueil). Écouté par MainWindow.
        /// Évite que les vues appellent directement BtnManualUpdateSignatures_Click.
        /// </summary>
        public event EventHandler? RequestSignatureUpdate
        {
            add => _uiEventBus.RequestSignatureUpdate += value;
            remove => _uiEventBus.RequestSignatureUpdate -= value;
        }

        public void TriggerSignatureUpdate() => _uiEventBus.TriggerSignatureUpdate();

        /// <summary>Active ou arrête la protection temps réel et persiste dans <see cref="ExclusionSettings"/>.</summary>
        public void ApplyRealtimeProtection(bool enabled)
        {
            _exclusionSettings.Current.RealTimeEnabled = enabled;
            _exclusionSettings.Current.Save();

            if (_userPreferences.Current.UsePlatformProtectionService
                && PlatformProtectionBootstrap.IsRemoteProtectionActive())
            {
                if (enabled)
                {
                    PlatformProtectionBootstrap.EnsurePlatformProtectionRunning();
                    if (_userPreferences.Current.TamperProtectionEnabled)
                        TamperProtection.EnsureWatchdogTask();
                }
                RequestProtectionStateRefresh();
                return;
            }

            if (enabled)
            {
                RealTimeProtection.Start();
                if (_userPreferences.Current.ProcessMonitorEnabled)
                    ProcessStartMonitor.Start();
                if (_userPreferences.Current.TamperProtectionEnabled)
                    TamperProtection.EnsureWatchdogTask();
            }
            else
            {
                RealTimeProtection.Stop();
                ProcessStartMonitor.Stop();
            }

            RequestProtectionStateRefresh();
        }

        /// <summary>Active le service Windows de protection système avancée.</summary>
        public void ApplyPlatformProtectionService(bool enabled)
        {
            if (enabled && !PlatformProtectionFeatureGate.IsUserActivatable)
            {
                AppLogger.Info(
                    "ServiceContainer",
                    "Mode plateforme avancé non activable (pilote signé requis — prévu dans 3 à 5 ans)");
                enabled = false;
            }

            _userPreferences.Current.UsePlatformProtectionService = enabled;
            _userPreferences.Current.Save();

            if (enabled)
            {
                PlatformProtectionBootstrap.TryInstallWindowsService();
                PlatformProtectionBootstrap.EnsurePlatformProtectionRunning();
                if (PlatformProtectionBootstrap.IsRemoteProtectionActive())
                {
                    RealTimeProtection.Stop();
                    ProcessStartMonitor.Stop();
                }
            }
            else
            {
                PlatformProtectionBootstrap.TryStopWindowsService();
                if (_exclusionSettings.Current.RealTimeEnabled)
                {
                    RealTimeProtection.Start();
                    if (_userPreferences.Current.ProcessMonitorEnabled)
                        ProcessStartMonitor.Start();
                }
            }

            RequestProtectionStateRefresh();
        }

        /// <summary>Active ou arrête la surveillance des lecteurs amovibles.</summary>
        public void ApplyRemovableDriveScan(bool enabled)
        {
            _userPreferences.Current.RemovableDriveScanEnabled = enabled;
            _userPreferences.Current.Save();
            if (enabled) RemovableDriveScan.Start();
            else RemovableDriveScan.Stop();
            RequestProtectionStateRefresh();
        }

        /// <summary>Persiste la quarantaine automatique (RTP + mode headless).</summary>
        public void ApplyAutoQuarantine(bool enabled)
        {
            _exclusionSettings.Current.AutoQuarantineEnabled = enabled;
            _exclusionSettings.Current.Save();
        }

        /// <summary>Active ou coupe les timers freshclam / règles YARA.</summary>
        public void ApplySignatureAutoUpdate(bool enabled)
        {
            SignatureUpdatePolicy.ApplyAutoUpdateTimers(FreshclamUpdater, RulesUpdater, enabled, _userPreferences);
            _userPreferences.Current.SignatureAutoUpdateEnabled = enabled;
            _userPreferences.Current.Save();
            RequestProtectionStateRefresh();
        }

        /// <summary>Active ou arrête la surveillance des créations de processus.</summary>
        public void ApplyProcessMonitor(bool enabled)
        {
            _userPreferences.Current.ProcessMonitorEnabled = enabled;
            _userPreferences.Current.Save();
            if (enabled && _exclusionSettings.Current.RealTimeEnabled)
                ProcessStartMonitor.Start();
            else
                ProcessStartMonitor.Stop();
            RequestProtectionStateRefresh();
        }

        /// <summary>Enregistre ou supprime la tâche watchdog anti-manipulation.</summary>
        public void ApplyTamperProtection(bool enabled)
        {
            _userPreferences.Current.TamperProtectionEnabled = enabled;
            _userPreferences.Current.Save();
            if (enabled)
                TamperProtection.EnsureWatchdogTask();
            else
                TamperProtection.DeleteWatchdogTask();
        }

        public event EventHandler? ProtectionStateRefreshRequested
        {
            add => _uiEventBus.ProtectionStateRefreshRequested += value;
            remove => _uiEventBus.ProtectionStateRefreshRequested -= value;
        }

        public void RequestProtectionStateRefresh() => _uiEventBus.RequestProtectionStateRefresh();

        /// <summary>Restaure RTP et MAJ auto selon les préférences persistées (appel au démarrage UI).</summary>
        public void ApplyPreferencesOnStartup()
        {
            ApplySignatureAutoUpdate(_userPreferences.Current.SignatureAutoUpdateEnabled);
            SignatureUpdatePolicy.ScheduleStartupRefreshIfStale(this, _userPreferences);

            if (_userPreferences.Current.UsePlatformProtectionService)
            {
                PlatformProtectionBootstrap.EnsurePlatformProtectionRunning();
                if (PlatformProtectionBootstrap.IsRemoteProtectionActive())
                {
                    if (_userPreferences.Current.TamperProtectionEnabled)
                        TamperProtection.EnsureWatchdogTask();
                    ApplyRemovableDriveAndEnginePrefs();
                    return;
                }

                AppLogger.Warn("ServiceContainer", "Service plateforme injoignable — repli RTP locale");
            }

            if (_exclusionSettings.Current.RealTimeEnabled)
            {
                RealTimeProtection.Start();
                if (_userPreferences.Current.ProcessMonitorEnabled)
                    ProcessStartMonitor.Start();
            }
            else
            {
                RealTimeProtection.Stop();
                ProcessStartMonitor.Stop();
            }

            if (_userPreferences.Current.TamperProtectionEnabled)
                TamperProtection.EnsureWatchdogTask();
            else
                TamperProtection.DeleteWatchdogTask();

            ApplyRemovableDriveAndEnginePrefs();
            WindowsDefenderExclusionService.EnsureOpticombatExclusionsAsync();
        }

        private void ApplyRemovableDriveAndEnginePrefs()
        {
            if (_userPreferences.Current.GameModeAutoEnabled)
                DistractionFreeMonitor.Start();
            else
                DistractionFreeMonitor.Stop();

            if (_userPreferences.Current.UseClamdEngine)
            {
                _ = Task.Run(async () =>
                {
                    try { await ClamdHost.Shared.EnsureRunningAsync().ConfigureAwait(false); }
                    catch (Exception ex) { AppLogger.Warn("ServiceContainer", "Préchauffage clamd", ex); }
                });
            }

            if (_userPreferences.Current.RemovableDriveScanEnabled)
                RemovableDriveScan.Start();
            else
                RemovableDriveScan.Stop();
        }

        // Demandes UI (export, onglet Signatures, etc.) : déléguées à <see cref="UiEventBus"/>.

        public event EventHandler? FocusAntivirusSignaturesRequested
        {
            add => _uiEventBus.FocusAntivirusSignaturesRequested += value;
            remove => _uiEventBus.FocusAntivirusSignaturesRequested -= value;
        }

        public void RequestFocusAntivirusSignaturesTab() =>
            _uiEventBus.RequestFocusAntivirusSignaturesTab();

        public event EventHandler? ScanHistoryViewsRefreshRequested
        {
            add => _uiEventBus.ScanHistoryViewsRefreshRequested += value;
            remove => _uiEventBus.ScanHistoryViewsRefreshRequested -= value;
        }

        public void RequestScanHistoryViewsRefresh() =>
            _uiEventBus.RequestScanHistoryViewsRefresh();

        public event EventHandler? ExportScanHistoryHtmlRequested
        {
            add => _uiEventBus.ExportScanHistoryHtmlRequested += value;
            remove => _uiEventBus.ExportScanHistoryHtmlRequested -= value;
        }

        public void RequestExportScanHistoryHtml() =>
            _uiEventBus.RequestExportScanHistoryHtml();

        public event EventHandler<Models.ScanSession>? ExportScanSessionPdfRequested
        {
            add => _uiEventBus.ExportScanSessionPdfRequested += value;
            remove => _uiEventBus.ExportScanSessionPdfRequested -= value;
        }

        public void RequestExportScanSessionPdf(Models.ScanSession session) =>
            _uiEventBus.RequestExportScanSessionPdf(session);

        public event EventHandler<Models.ScanSession>? ReviewHistorySessionRequested
        {
            add => _uiEventBus.ReviewHistorySessionRequested += value;
            remove => _uiEventBus.ReviewHistorySessionRequested -= value;
        }

        public void RequestReviewHistorySession(Models.ScanSession session) =>
            _uiEventBus.RequestReviewHistorySession(session);

        public event EventHandler? OpenQuarantineTabRequested
        {
            add => _uiEventBus.OpenQuarantineTabRequested += value;
            remove => _uiEventBus.OpenQuarantineTabRequested -= value;
        }

        public void RequestOpenQuarantineTab() =>
            _uiEventBus.RequestOpenQuarantineTab();

        private ServiceContainer()
        {
            var collection = new ServiceCollection();
            DependencyInjection.ServiceRegistration.AddOpticombatCoreServices(collection);
            _services = collection.BuildServiceProvider();

            _uiEventBus = _services.GetRequiredService<UiEventBus>();
            _userPreferences = _services.GetRequiredService<IUserPreferencesAccessor>();
            _exclusionSettings = _services.GetRequiredService<IExclusionSettingsAccessor>();

            DistractionFreeMonitor.Initialize(_userPreferences);
            PlatformProtectionBootstrap.Initialize(_userPreferences);
            LocalizationService.ConfigurePreferencesAccessor(_userPreferences);

            ClamAv = _services.GetRequiredService<ClamAvEngine>();
            ClamAvBackend = _services.GetRequiredService<CompositeClamAvBackend>();
            Yara = _services.GetRequiredService<YaraEngine>();
            FreshclamUpdater = _services.GetRequiredService<FreshclamUpdater>();
            RulesUpdater = _services.GetRequiredService<YaraForgeUpdater>();
            Quarantine = _services.GetRequiredService<QuarantineManager>();
            Logger = _services.GetRequiredService<ScanLogManager>();
            ActivityLog = _services.GetRequiredService<ActivityLogService>();
            Notifications = _services.GetRequiredService<NotificationService>();
            Orchestrator = _services.GetRequiredService<ScanOrchestrator>();
            ScanEngine = _services.GetRequiredService<IScanEngine>();
            ThreatReputation = _services.GetRequiredService<ThreatReputationService>();
            CloudThreatIntel = _services.GetRequiredService<CloudThreatIntelService>();
            SecurityPosture = _services.GetRequiredService<ISecurityPostureService>();
            SignatureStatus = _services.GetRequiredService<SignatureStatusService>();
            RealTimeProtection = _services.GetRequiredService<RealTimeProtection>();
            ProcessStartMonitor = _services.GetRequiredService<ProcessStartMonitor>();
            TamperProtection = _services.GetRequiredService<TamperProtectionService>();
            RemovableDriveScan = _services.GetRequiredService<RemovableDriveScanService>();
            ScheduledScan = _services.GetRequiredService<ScheduledScanService>();

            Logger.BindActivityLog(ActivityLog);
            Quarantine.BindActivityLog(ActivityLog);
            ActivityLog.EnsureMigrated(Quarantine);
            Actions = new AntivirusActions(this);

            AppLogger.Info("ServiceContainer", "Services initialisés (DI)");

            var yara = Yara;
            _ = Task.Run(async () =>
            {
                try
                {
                    if (!await yara.CompileRulesAsync().ConfigureAwait(false) && yara.IsAvailable)
                    {
                        AppLogger.Warn("ServiceContainer",
                            "Précompilation YARA (.yarc) absente ou échouée au démarrage — sera retentée au premier scan.");
                    }
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("ServiceContainer", "Précompilation YARA au démarrage", ex);
                }
            });
        }

        IScheduledScanService IViewServices.ScheduledScan => ScheduledScan;

        IExclusionSettingsAccessor IProtectionServiceHostDependencies.ExclusionSettingsAccessor => _exclusionSettings;

        IUserPreferencesAccessor IProtectionServiceHostDependencies.UserPreferencesAccessor => _userPreferences;

        /// <summary>
        /// Libère proprement tous les services disposables.
/// Appelé depuis App.OnExit.
        /// </summary>
        public void Shutdown()
        {
            if (_shutdownDone)
                return;
            _shutdownDone = true;
            _uiEventBus.ClearHandlers();
            try { RealTimeProtection.Dispose(); }
            catch (Exception ex) { AppLogger.Warn("ServiceContainer", "RealTimeProtection.Dispose", ex); }
            try { ProcessStartMonitor.Dispose(); }
            catch (Exception ex) { AppLogger.Warn("ServiceContainer", "ProcessStartMonitor.Dispose", ex); }
            try { RemovableDriveScan.Dispose(); }
            catch (Exception ex) { AppLogger.Warn("ServiceContainer", "RemovableDriveScan.Dispose", ex); }
            try { FreshclamUpdater.DisableAutoUpdate(); }
            catch (Exception ex) { AppLogger.Warn("ServiceContainer", "FreshclamUpdater.DisableAutoUpdate", ex); }
            try { RulesUpdater.DisableAutoUpdate(); }
            catch (Exception ex) { AppLogger.Warn("ServiceContainer", "RulesUpdater.DisableAutoUpdate", ex); }
            try { ClamdHost.Shared.Stop(); }
            catch (Exception ex) { AppLogger.Warn("ServiceContainer", "ClamdHost.Stop", ex); }
            try { DistractionFreeMonitor.Stop(); }
            catch (Exception ex) { AppLogger.Warn("ServiceContainer", "DistractionFreeMonitor.Stop", ex); }
            (ClamAv as IDisposable)?.Dispose();
            (Yara as IDisposable)?.Dispose();
            if (_services is IDisposable disposable)
                disposable.Dispose();
            AppLogger.Info("ServiceContainer", "Services fermés");
        }
    }
}
