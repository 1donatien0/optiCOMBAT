using MaterialDesignThemes.Wpf;
using optiCombat.Coordinators;
using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Strings;
using optiCombat.ViewModels;
using optiCombat.Views;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Windows.Forms;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using System.Windows.Input;
using System.Windows.Media.Animation;
using Button = System.Windows.Controls.Button;
using MediaColor = System.Windows.Media.Color;

namespace optiCombat
{
    /// <summary>
    /// Fenêtre principale d'optiCombat. Orchestre la navigation entre les 5 panneaux,
    /// coordonne les mises à jour de signatures, les exports et la protection temps réel
    /// en s'appuyant sur <see cref="Services.ServiceContainer"/> et <see cref="ViewModels.ScanViewModel"/>.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public partial class MainWindow : Window
    {
        // ── Services & ViewModel ─────────────────────────────────────────────────
        /// <summary>ViewModel partagé (scan, quarantaine, progression). DataContext de la fenêtre.</summary>
        public ScanViewModel? ViewModel { get; private set; }

        private readonly TrayCoordinator _trayCoordinator = new();
        private ShellScanCoordinator? _shellScanCoordinator;

        private readonly ServiceContainer _container = ServiceContainer.Default;
        private readonly ExportCoordinator _exportCoordinator = new(
            new HistoryExportService(ServiceContainer.Default.UserPreferencesAccessor));
        private readonly MainWindowServiceEventCoordinator _serviceEvents = new();
        private SidebarSyncCoordinator? _sidebarSync;
        private SignatureRefreshCoordinator? _signatureRefresh;
        private readonly Services.NavigationService _navigationService = new();
        private Services.NavigationRefreshCoordinator? _navRefreshCoordinator;
        private readonly SignatureUpdateUiRunner _signatureUpdateRunner = new();
        private readonly StatusFooterCoordinator _statusFooter = new();
        private bool _isClosing;
        private bool _wasScanning;

        private IUiEventBus UiBus => _container;

        // Après InitializeComponent / RegisterPanels, le constructeur assigne
        // IViewServices.Navigation : les vues naviguent sans référencer MainWindow.

        public MainWindow()
        {
            // Avant OptionsControl (LoadPreferences) : thème Windows + prefs déjà appliqués.
            ThemeManager.Initialize();
            InitializeComponent();
            // Branche les vues avant tout IsChecked / handler XAML qui accède aux services.
            RegisterPanels();
            BindAllViewPanels(_container);
            if (navOverview != null)
                navOverview.IsChecked = true;
            else
                _navigationService.NavigateTo(OpticombatStrings.PanelIds.Overview);

            ApplyVersionLabels();

            try
            {
                _trayCoordinator.Initialize(
                    ShowWindow,
                    () =>
                    {
                        _isClosing = true;
                        Close();
                    });

                // Services partagés via le singleton applicatif (mêmes instances que ScanViewModel).
                var c = _container;

                _signatureRefresh = new SignatureRefreshCoordinator(
                    c.FreshclamUpdater,
                    c.RulesUpdater,
                    c.SignatureStatus,
                    SurSortieFreshclam,
                    SurSortieMisesAJourRegles,
                    forceRefresh => RefreshSignaturesDisplayAsync(forceRefresh),
                    RefreshLiveFooter,
                    work => Dispatcher.InvokeAsync(work));
                _signatureRefresh.Attach();

                // ViewModel partage le même container : pas de re-instanciation.
                ViewModel = new ScanViewModel(c);
                ViewModel.PropertyChanged -= SurChangementProprieteScanViewModel;
                ViewModel.PropertyChanged += SurChangementProprieteScanViewModel;
                _wasScanning = ViewModel.IsScanning;
                Dispatcher.InvokeAsync(RefreshLiveFooter);
                c.ThreatLookup = path => ViewModel?.Threats.FirstOrDefault(t =>
                    string.Equals(t.FilePath, path, StringComparison.OrdinalIgnoreCase));
                this.DataContext = ViewModel;

                // Les vues utilisent ServiceContainer.Navigation (INavigationService) sans référencer MainWindow.
                c.Navigation = _navigationService;

                _serviceEvents.Attach(
                    c,
                    UiBus,
                    SurDemandeMiseAJourSignatures,
                    SurDemandeRafraichissementHistorique,
                    SurDemandeExportHistoriqueHtml,
                    SurDemandeExportSessionScanPdf,
                    SurDemandeRevueSessionHistorique,
                    SurDemandeOngletQuarantaine,
                    SurMenaceTempsReelDetectee,
                    SurStatutAnalyseUsb,
                    SurActivationToast,
                    SurActionAntivirusTerminee);

                _shellScanCoordinator = new ShellScanCoordinator(
                    Dispatcher,
                    _navigationService,
                    () => ViewModel,
                    ShowWindow);
                _shellScanCoordinator.Hook(this);

                // Abonnement aux événements
                this.Loaded += async (s, e) => await SurChargementFenetrePrincipale();
                this.Closing += SurFermetureFenetre;
                this.StateChanged += SurChangementEtatFenetre;

                // IPC : une seconde instance envoie un message Windows pour réafficher cette fenêtre (IpcManager).
                IpcManager.HookShowMessage(this, ShowWindow);

                ThemeManager.ThemeChanged += SurChangementTheme;
                UpdateThemeToggleTooltip(ThemeManager.IsDarkTheme);

                // Raccourcis Ctrl+1..Ctrl+5 : une seule RoutedCommand, le paramètre est le nom du panneau.
                KeyboardShortcuts.Register(this,
                    new[] { OpticombatStrings.PanelIds.Overview, OpticombatStrings.PanelIds.Clean, OpticombatStrings.PanelIds.Antivirus, OpticombatStrings.PanelIds.History, OpticombatStrings.PanelIds.Options },
                    SwitchPanel);
            }
            catch (Exception ex)
            {
                AppLogger.Error("MainWindow", "Initialisation fenêtre principale", ex);
                SetStatus(LocalizationService.Format("Status_Error", ex.Message), isError: true);
            }
        }

        // ── Initialisation ───────────────────────────────────────────────────────
        /// <summary>
        /// Orchestration principale au chargement de la fenêtre.
        /// Initialise les panneaux, évalue la disponibilité des moteurs (ClamAV/YARA),
        /// rafraîchit l'état de l'UI et branche les protections temps réel.
        /// </summary>
        /// <remarks>
        /// Cette méthode est appelée une seule fois dans l'exécution normale, mais la logique
        /// reste idempotente côté navigation (panneaux enregistrés sans duplication).
        /// En cas d'exception, l'UI affiche un statut d'erreur et continue sans crasher.
        /// </remarks>
        private async Task SurChargementFenetrePrincipale()
        {
            try
            {
                await MainWindowStartupCoordinator.RunAsync(new MainWindowStartupCoordinator.Host
                {
                    Container = _container,
                    Navigation = _navigationService,
                    ViewModel = ViewModel,
                    Window = this,
                    RegisterPanels = RegisterPanels,
                    RefreshAntivirusStatus = RefreshAntivirusStatus,
                    RefreshQuarantineList = RefreshQuarantineList,
                    RefreshHistory = RefreshHistory,
                    RefreshSignaturesDisplayAsync = () => RefreshSignaturesDisplayAsync(),
                    RefreshOverviewProtection = RefreshOverviewProtectionAndRecommendations,
                    ApplyElevationBanner = () => (panelOverview as Views.OverviewControl)?.ApplyElevationBanner(),
                    SetStatus = (msg, err, warn) => SetStatus(msg, isError: err, isWarning: warn),
                    WarmUpYaraRulesAsync = WarmUpYaraRulesAsync,
                    ShowWindow = ShowWindow,
                    ShellScan = _shellScanCoordinator,
                    GuardSession = App.GuardSession,
                    PendingShellScanPath = App.PendingShellScanPath,
                    ShowOnboardingIfNeeded = OnboardingService.ShowIfNeeded,
                }).ConfigureAwait(true);
                App.PendingShellScanPath = null;
            }
            catch (Exception ex)
            {
                AppLogger.Error("MainWindow", "SurChargementFenetrePrincipale", ex);
                SetStatus(LocalizationService.Format("Status_Error", ex.Message), isError: true);
            }
        }

        /// <summary>Compile les règles YARA en arrière-plan pour éviter le blocage au premier scan.</summary>
        private async Task WarmUpYaraRulesAsync()
        {
            try
            {
                var yara = _container.Yara;
                if (yara == null || !yara.IsAvailable || yara.HasCompiled)
                    return;
                await yara.CompileRulesAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("MainWindow", "WarmUpYaraRulesAsync", ex);
            }
        }

        private void BindAllViewPanels(ServiceContainer c)
        {
            if (panelHistory is HistoryControl historyPanel)
                historyPanel.Bind(c);
            BindViewPanels(c);
        }

        private void BindViewPanels(ServiceContainer c)
        {
            if (panelOverview is OverviewControl overview)
                overview.Bind(c);
            if (panelAntivirus is AntivirusView antivirus)
                antivirus.Bind(c);
            if (panelClean is CleanControl clean)
                clean.Bind(c);
            if (panelOptions is OptionsControl options)
                options.Bind(c);
        }

        /// <summary>
        /// Enregistre les 5 panneaux auprès du NavigationService.
        /// Appelé juste après <see cref="InitializeComponent"/> (avant tout <c>Checked</c> de la sidebar)
        /// et à nouveau dans <see cref="SurChargementFenetrePrincipale"/> (idempotent).
        /// </summary>
        private void RegisterPanels()
        {
            // Vérifications null : les éléments nommés existent forcément après InitializeComponent.
            if (panelOverview != null) _navigationService.RegisterPanel(OpticombatStrings.PanelIds.Overview, panelOverview);
            if (panelAntivirus != null) _navigationService.RegisterPanel(OpticombatStrings.PanelIds.Antivirus, panelAntivirus);
            if (panelClean != null) _navigationService.RegisterPanel(OpticombatStrings.PanelIds.Clean, panelClean);
            if (panelHistory != null) _navigationService.RegisterPanel(OpticombatStrings.PanelIds.History, panelHistory);
            if (panelOptions != null) _navigationService.RegisterPanel(OpticombatStrings.PanelIds.Options, panelOptions);

            var ui = UiBus;
            ui.FocusAntivirusSignaturesRequested -= SurDemandeFocusSignaturesAntivirus;
            ui.FocusAntivirusSignaturesRequested += SurDemandeFocusSignaturesAntivirus;

            // Le coordinateur gère les rafraîchissements par vue (extrait de MainWindow).
            _navRefreshCoordinator?.Detach();
            _navRefreshCoordinator = new Services.NavigationRefreshCoordinator(
                _navigationService,
                Dispatcher,
                refreshHistory:         RefreshHistoryAsync,
                refreshAntivirusStatus: RefreshAntivirusStatusCoreAsync,
                refreshSignatures:      () => RefreshSignaturesDisplayAsync(),
                refreshAntivirusData:   RefreshAntivirusDataAsync);

            _sidebarSync?.Detach();
            _sidebarSync = new SidebarSyncCoordinator(
                _navigationService,
                action => Dispatcher.BeginInvoke(action, DispatcherPriority.Background),
                new Dictionary<string, Action>
                {
                    [OpticombatStrings.PanelIds.Overview] = () => { if (navOverview != null) navOverview.IsChecked = true; },
                    [OpticombatStrings.PanelIds.Clean] = () => { if (navClean != null) navClean.IsChecked = true; },
                    [OpticombatStrings.PanelIds.Antivirus] = () => { if (navAntivirus != null) navAntivirus.IsChecked = true; },
                    [OpticombatStrings.PanelIds.History] = () => { if (navHistory != null) navHistory.IsChecked = true; },
                    [OpticombatStrings.PanelIds.Options] = () => { if (navOptions != null) navOptions.IsChecked = true; },
                });
        }

        private void SurDemandeMiseAJourSignatures(object? sender, EventArgs e) =>
            BtnManualUpdateSignatures_Click(this, new RoutedEventArgs());

        private void SurDemandeRafraichissementHistorique(object? sender, EventArgs e) =>
            Dispatcher.BeginInvoke(RefreshHistory, GetHistoryRefreshPriority());

        private void SurChangementProprieteScanViewModel(object? sender, PropertyChangedEventArgs e)
        {
            if (ViewModel == null) return;

            if (e.PropertyName == nameof(ScanViewModel.IsScanning))
            {
                if (_wasScanning && !ViewModel.IsScanning)
                    Dispatcher.BeginInvoke(RefreshHistory, GetHistoryRefreshPriority());

                _wasScanning = ViewModel.IsScanning;
            }

            if (e.PropertyName is nameof(ScanViewModel.IsScanning)
                or nameof(ScanViewModel.ScanProgressDetail)
                or nameof(ScanViewModel.IsUpdating))
                Dispatcher.InvokeAsync(RefreshLiveFooter);
        }

        private DispatcherPriority GetHistoryRefreshPriority() =>
            string.Equals(_navigationService.CurrentView, OpticombatStrings.PanelIds.Overview, StringComparison.OrdinalIgnoreCase)
                ? DispatcherPriority.Normal
                : DispatcherPriority.Background;

        private void SurDemandeFocusSignaturesAntivirus(object? sender, EventArgs e)
        {
            if (panelAntivirus is Views.AntivirusView av)
                av.SelectSignaturesTab();
        }

        private void SurDemandeRevueSessionHistorique(object? sender, ScanSession session)
        {
            ViewModel?.LoadThreatsFromHistorySession(session);
            _navigationService.NavigateTo(OpticombatStrings.PanelIds.Antivirus);
            if (panelAntivirus is Views.AntivirusView av)
                av.SelectScanTab();
        }

        private void SurDemandeOngletQuarantaine(object? sender, EventArgs e)
        {
            _navigationService.NavigateTo(OpticombatStrings.PanelIds.Antivirus);
            ViewModel?.LoadQuarantine(reset: true);
            RefreshQuarantineList();
            (panelAntivirus as Views.AntivirusView)?.SelectQuarantineTab();
        }

        private void UnhookServiceContainerEvents()
        {
            var ui = UiBus;
            ui.FocusAntivirusSignaturesRequested -= SurDemandeFocusSignaturesAntivirus;
            _serviceEvents.Detach();
        }

        // ── Navigation ───────────────────────────────────────────────────────────

        /// <summary>Déclenché par un RadioButton NavItem coché dans la sidebar.</summary>
        private void NavItem_Checked(object sender, RoutedEventArgs e)
        {
            if (_sidebarSync?.IsSyncing == true)
                return;

            if (sender is System.Windows.Controls.Primitives.ToggleButton tb
                && tb.Tag is string panelName)
            {
                SwitchPanel(panelName);
            }
        }

        /// <summary>Bascule le thème sombre/clair.</summary>
        private void BtnModesSombre_Click(object sender, RoutedEventArgs e)
        {
            ThemeManager.Toggle();
        }

        /// <summary>Ouvre la page du projet optiCombat sur SourceForge dans le navigateur par défaut.</summary>
        private void BtnWebsite_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = OpticombatStrings.Urls.OpticombatWebsite,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                AppLogger.Warn("MainWindow", "Ouverture du site web (Process.Start)", ex);
            }
        }

        // Ancien handler Button conservé pour compatibilité
        private void MenuButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string target)
                SwitchPanel(target);
        }

        /// <summary>
        /// Navigue vers le panneau identifié par <paramref name="panelName"/> et déclenche
        /// les rafraîchissements de données associés.
        /// </summary>
        public void SwitchPanel(string panelName) =>
            _navigationService.NavigateTo(panelName);

        // Les rafraîchissements de navigation sont maintenant gérés par NavigationRefreshCoordinator.

        // ── Rafraîchissement ─────────────────────────────────────────────────────
        // RefreshYaraStatus() est intentionnellement supprimé : YaraRulesCount et
        // YaraStatus sont désormais synchronisés dans RefreshSignaturesDisplay()
        // via le ViewModel, et UpdateYaraStatus() de AntivirusView est supprimée.

        private void RefreshAntivirusStatus()
        {
            _ = RefreshAntivirusStatusCoreAsync();
        }

        private Task RefreshAntivirusStatusCoreAsync() =>
            AntivirusSidebarCoordinator.RefreshAsync(BuildAntivirusSidebarHost());

        private AntivirusSidebarCoordinator.Host BuildAntivirusSidebarHost() => new()
        {
            IsClamAvInstalled = () => _container.ClamAv.IsClamAvInstalled(),
            GetYaraRulesCount = () => _container.Yara.RulesCount,
            GetClamActiveEngine = () => _container.ClamActiveEngine,
            OverviewPanel = panelOverview as IOverviewPanel,
            SidebarClamBadge = txtSidebarClamAvBadge,
            SidebarClamIcon = icoSidebarClamAv,
        };

        private void RefreshQuarantineList()
        {
            ViewModel?.RefreshQuarantineList();
        }

        private Task RefreshHistoryAsync()
        {
            RefreshHistory();
            return Task.CompletedTask;
        }

        private void RefreshHistory()
        {
            HistoryRefreshCoordinator.Refresh(new HistoryRefreshCoordinator.Host
            {
                Logger = _container.Logger,
                HistoryPanel = panelHistory as Views.HistoryControl,
                OverviewPanel = panelOverview as Views.OverviewControl,
                AntivirusPanel = panelAntivirus as Views.AntivirusView,
                RefreshOverviewProtection = RefreshOverviewProtectionAndRecommendations,
            });
        }

        private void SurMenaceTempsReelDetectee(object? sender, ThreatInfo threat)
        {
            Dispatcher.BeginInvoke(() =>
                RealTimeThreatCoordinator.Handle(threat, new RealTimeThreatCoordinator.Host
                {
                    ViewModel = ViewModel,
                    RefreshQuarantineList = RefreshQuarantineList,
                    RefreshOverviewProtection = RefreshOverviewProtectionAndRecommendations,
                }),
                DispatcherPriority.Background);
        }

        private void SurStatutAnalyseUsb(object? sender, RemovableDriveScanStatusEventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
                UsbScanStatusCoordinator.Handle(e, new UsbScanStatusCoordinator.Host
                {
                    SetStatus = (text, isError, isWarning, icon) =>
                        SetStatus(text, isError, isWarning, icon),
                }),
                DispatcherPriority.Background);
        }

        private void SurActionAntivirusTerminee(object? sender, ActionResult result)
        {
            Dispatcher.BeginInvoke(() =>
                AntivirusActionResultCoordinator.Handle(result, new AntivirusActionResultCoordinator.Host
                {
                    SetStatus = (msg, err, warn) => SetStatus(msg, isError: err, isWarning: warn),
                    RefreshQuarantineList = RefreshQuarantineList,
                    RefreshHistory = RefreshHistory,
                    AntivirusPanel = panelAntivirus as Views.AntivirusView,
                }),
                DispatcherPriority.Normal);
        }

        private void SurActivationToast(object? sender, ToastActivationEventArgs e)
        {
            Dispatcher.BeginInvoke(() => ToastActivationCoordinator.Handle(e, BuildToastHost()), DispatcherPriority.Normal);
        }

        private ToastActivationCoordinator.Host BuildToastHost() => new()
        {
            Services = _container,
            Navigation = _navigationService,
            ShowWindow = ShowWindow,
            SetStatus = (msg, err, warn) => SetStatus(msg, isError: err, isWarning: warn),
            RefreshQuarantineList = RefreshQuarantineList,
            RefreshAntivirusView = () => (panelAntivirus as Views.AntivirusView)?.RefreshAllData(),
            SelectAntivirusScanTab = () => (panelAntivirus as Views.AntivirusView)?.SelectScanTab(),
            SelectAntivirusQuarantineTab = () => (panelAntivirus as Views.AntivirusView)?.SelectQuarantineTab(),
            SelectAntivirusSignaturesTab = () => (panelAntivirus as Views.AntivirusView)?.SelectSignaturesTab(),
            TriggerManualSignatureUpdate = () => BtnManualUpdateSignatures_Click(this, new RoutedEventArgs()),
        };

        /// <summary>Titre de protection, recommandations hygiène et activité (vue d’ensemble).</summary>
        private void RefreshOverviewProtectionAndRecommendations()
        {
            if (panelOverview is not IOverviewPanel overview)
                return;

            OverviewRefreshCoordinator.RefreshProtectionAndRecommendations(
                OverviewRefreshContextBuilder.FromContainer(overview, _container));
        }

        public async Task RefreshAntivirusDataAsync()
        {
            RefreshAntivirusStatus();
            RefreshQuarantineList();
            RefreshHistory();
            await RefreshSignaturesDisplayAsync();
        }

        /// <summary>Rafraîchit les versions de signatures (onglet Antivirus + ViewModel).</summary>
        private async Task RefreshSignaturesDisplayAsync(bool forceRefresh = false)
        {
            await OverviewRefreshCoordinator.RefreshSignaturesAsync(
                new SignaturesRefreshContext(
                    _container.SignatureStatus,
                    panelOverview as IOverviewPanel,
                    panelAntivirus as IAntivirusSignaturesPanel,
                    snapshot => { if (ViewModel != null) snapshot.ApplyToScanViewModel(ViewModel); },
                    RefreshOverviewProtectionAndRecommendations),
                forceRefresh).ConfigureAwait(true);
        }

        private void SurDemandeExportHistoriqueHtml(object? sender, EventArgs e) =>
            Dispatcher.BeginInvoke(new Action(TryExportScanReportHtml), DispatcherPriority.Background);

        private void SurDemandeExportSessionScanPdf(object? sender, ScanSession session) =>
            Dispatcher.BeginInvoke(new Action(() => TryExportScanSessionPdf(session)), DispatcherPriority.Background);

        private ExportContext BuildExportContext() => new(
            this,
            _container.Logger,
            ViewModel?.Threats ?? Enumerable.Empty<ThreatInfo>(),
            _container.Quarantine.GetEntries(),
            (msg, err, warn) => SetStatus(msg, isError: err, isWarning: warn));

        private void TryExportScanReportHtml() =>
            _exportCoordinator.TryExportHtml(BuildExportContext());

        private void TryExportScanSessionPdf(ScanSession session) =>
            _exportCoordinator.TryExportSessionPdf(BuildExportContext(), session);

        // ── Statut ───────────────────────────────────────────────────────────────
        private void UpdateThemeToggleTooltip(bool isDark)
        {
            if (btnModesSombre == null) return;
            btnModesSombre.ToolTip = LocalizationService.GetString(
                isDark ? "Nav_TooltipThemeLight" : "Nav_TooltipThemeDark");
        }

        private void SurChangementTheme(object? sender, bool isDark)
        {
            Dispatcher.InvokeAsync(() =>
            {
                UpdateThemeToggleTooltip(isDark);
                panelOptions.SyncThemeControls();

                RefreshAntivirusStatus();
                RefreshOverviewProtectionAndRecommendations();
                _statusFooter.OnThemeChanged(IsLiveFooterActive, RefreshFooterDisplay);
            });
        }

        private void SetStatus(string text, bool isError = false, bool isWarning = false, string? iconKindName = null)
        {
            Dispatcher.InvokeAsync(() =>
            {
                _statusFooter.SetStatus(
                    text,
                    isError,
                    isWarning,
                    iconKindName,
                    lblStatus,
                    statusFooterIcon,
                    IsLiveFooterActive,
                    RefreshFooterDisplay);
                AppLogger.Debug("MainWindow", $"Statut: {text}");
            });
        }

        private void RefreshFooterDisplay()
        {
            if (!IsLiveFooterActive())
                _statusFooter.ApplyPinnedFooter(lblStatus, statusFooterIcon);
            else
                RefreshLiveFooter();
        }

        private bool IsLiveFooterActive()
        {
            if (ViewModel?.IsScanning == true)
                return true;
            if (IsSignatureUpdateRunning())
                return true;
            return ViewModel?.IsUpdating == true;
        }

        private bool IsSignatureUpdateRunning() =>
            _container.FreshclamUpdater.IsUpdating || _container.RulesUpdater.IsUpdating;

        private void RefreshLiveFooter() =>
            _statusFooter.RefreshLiveFooter(
                ViewModel,
                lblStatus,
                statusFooterIcon,
                statusFooterSpinner,
                IsSignatureUpdateRunning);

        private void ApplyVersionLabels()
        {
            // Nomenclature : vM.m (README, v1.0) + M.m.p (assembly / installateur).
            var release = ProductVersionInfo.ReleaseLabel;
            var semver = ProductVersionInfo.SemVer;
            if (txtSidebarVersion != null)
                txtSidebarVersion.Text = $"{release} ({semver})";
        }

        // ── Ré-affichage depuis la systray ou IPC ────────────────────────────────
        // WM_SHOWME et le hook WndProc sont implémentés dans IpcManager.
        private void ShowWindow()
        {
            if (WindowState == WindowState.Minimized)
                WindowState = WindowState.Normal;
            Show();
            Activate();
            Topmost = true;
            Topmost = false;
        }

        // Raccourcis clavier : voir Services.KeyboardShortcuts.

        // ── Gestion de l'état de la fenêtre (minimize → systray) ────────────────
        private void SurChangementEtatFenetre(object? sender, EventArgs e)
        {
            if (WindowState == WindowState.Minimized)
            {
                WindowTrayBehaviorCoordinator.OnMinimized(new WindowTrayBehaviorCoordinator.Host
                {
                    HideWindow = Hide,
                    SetTrayStatus = msg => SetStatus(msg),
                });
            }
        }

        // ── Fermeture ────────────────────────────────────────────────────────────
        private void SurFermetureFenetre(object? sender, CancelEventArgs e)
        {
            if (WindowTrayBehaviorCoordinator.TryCancelClose(_isClosing, e, new WindowTrayBehaviorCoordinator.Host
                {
                    HideWindow = Hide,
                    SetTrayStatus = msg => SetStatus(msg),
                }))
            {
                return;
            }

            PerformCleanShutdown();
        }

        private void PerformCleanShutdown()
        {
            MainWindowShutdownCoordinator.PerformCleanShutdown(new MainWindowShutdownCoordinator.Host
            {
                Tray = _trayCoordinator,
                SignatureRefresh = _signatureRefresh,
                UnhookServiceEvents = UnhookServiceContainerEvents,
                ViewModel = ViewModel,
                ViewModelPropertyChanged = SurChangementProprieteScanViewModel,
                NavRefresh = _navRefreshCoordinator,
                SidebarSync = _sidebarSync,
                Container = _container,
            });
        }

        // ── Quarantaine ──────────────────────────────────────────────────────────

        // ── Mise à jour des signatures ───────────────────────────────────────────

        // Handlers nommés — souscrits une seule fois à l'init pour éviter
        // l'accumulation de lambdas anonymes à chaque clic.
        private void SurSortieFreshclam(object? sender, string line)
            => (panelAntivirus as Views.AntivirusView)?.AppendSignatureLog($"[ClamAV] {line}");

        private void SurSortieMisesAJourRegles(object? sender, string line)
            => (panelAntivirus as Views.AntivirusView)?.AppendSignatureLog($"{LocalizationService.GetString("Status_SigLogRules")} {line}");

        private async void BtnManualUpdateSignatures_Click(object sender, RoutedEventArgs e)
        {
            var antivirusView = panelAntivirus as Views.AntivirusView;
            await ManualSignatureUpdateCoordinator.RunAsync(new ManualSignatureUpdateCoordinator.Host
            {
                Runner = _signatureUpdateRunner,
                Freshclam = _container.FreshclamUpdater,
                Rules = _container.RulesUpdater,
                SignatureStatus = _container.SignatureStatus,
                SetStatus = (text, isError, isWarning, icon) =>
                    SetStatus(text, isError, isWarning, icon),
                RefreshLiveFooter = RefreshLiveFooter,
                RefreshSignaturesDisplayAsync = force => RefreshSignaturesDisplayAsync(force),
                SetSignatureUpdating = updating => antivirusView?.SetSignatureUpdating(updating),
                AppendSignatureLog = line => antivirusView?.AppendSignatureLog(line),
            }).ConfigureAwait(true);
        }

        /// <summary>Annule la mise à jour de signatures en cours (freshclam.exe + règles YARA).</summary>
        public void BtnStopUpdateSignatures_Click(object sender, RoutedEventArgs e)
        {
            var antivirusView = panelAntivirus as Views.AntivirusView;
            ManualSignatureUpdateCoordinator.Stop(new ManualSignatureUpdateCoordinator.StopHost
            {
                Freshclam = _container.FreshclamUpdater,
                Rules = _container.RulesUpdater,
                SetStatus = (text, isError, isWarning, icon) =>
                    SetStatus(text, isError, isWarning, icon),
                AppendSignatureLog = msg => antivirusView?.AppendSignatureLog(msg),
                SetSignatureUpdating = updating => antivirusView?.SetSignatureUpdating(updating),
            });
        }
    }
}
