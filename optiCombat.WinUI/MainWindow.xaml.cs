using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Windowing;
using optiCombat.Coordinators;
using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Strings;
using optiCombat.WinUI.Services;
using optiCombat.WinUI.Views;
using System.Reflection;
using Windows.System;
using WinRT.Interop;

namespace optiCombat.WinUI;

public sealed partial class MainWindow : Window
{
    private OverviewPage? _overviewPage;
    private AntivirusPage? _antivirusPage;
    private HistoryPage? _historyPage;
    private CleanPage? _cleanPage;
    private OptionsPage? _optionsPage;

    private readonly WinUiTrayHost _tray = new();
    private readonly WinUiServiceEventCoordinator _serviceEvents = new();
    private WinUiNavigationService? _navigation;
    private WinUiShellScanCoordinator? _shellScan;
    private AppWindow? _appWindow;
    private bool _explicitExit;
    private bool _startupDone;

    public MainWindow()
    {
        InitializeComponent();
        Title = LocalizationService.GetString("App_TitleShort");
        VersionText.Text = $"v{Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0"}";
        RegisterKeyboardShortcuts();

        Activated += OnActivated;

        // Le HWND est créé caché. On l'affiche avant le chargement de l'accueil,
        // sinon la fenêtre n'apparaît qu'une fois les services initialisés.
        var hwnd = WindowNative.GetWindowHandle(this);
        if (hwnd != IntPtr.Zero)
            ShowWindowNative(hwnd, SwShow);
    }

    private void RegisterKeyboardShortcuts()
    {
        RegisterShortcut(VirtualKey.Number1, "overview");
        RegisterShortcut(VirtualKey.Number2, "clean");
        RegisterShortcut(VirtualKey.Number3, "antivirus");
        RegisterShortcut(VirtualKey.Number4, "history");
        RegisterShortcut(VirtualKey.Number5, "options");
    }

    private void RegisterShortcut(VirtualKey key, string tag)
    {
        var accelerator = new KeyboardAccelerator
        {
            Key = key,
            Modifiers = VirtualKeyModifiers.Control,
        };
        accelerator.Invoked += (_, args) =>
        {
            args.Handled = true;
            SelectNavigation(tag);
        };
        RootGrid.KeyboardAccelerators.Add(accelerator);
    }

    private void OnActivated(object sender, WindowActivatedEventArgs args)
    {
        if (_startupDone)
            return;

        _startupDone = true;
        InitializeShell();
    }

    private void InitializeShell()
    {
        var hwnd = WindowNative.GetWindowHandle(this);
        var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
        _appWindow = AppWindow.GetFromWindowId(windowId);
        _appWindow.Closing += AppWindow_Closing;

        if (_appWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.PreferredMinimumWidth = 1024;
            presenter.PreferredMinimumHeight = 600;
        }

        _appWindow.Resize(new Windows.Graphics.SizeInt32(1280, 720));

        _shellScan = new WinUiShellScanCoordinator(
            WinUiServiceHost.Instance.Antivirus,
            SelectNavigation,
            ShowWindow);

        _navigation = new WinUiNavigationService(SelectNavigation);
        WinUiServiceHost.Instance.Container.Navigation = _navigation;

        _serviceEvents.Attach(
            WinUiServiceHost.Instance.Container,
            ServiceContainer.UiEvents,
            OnSignatureUpdateRequested,
            OnHistoryRefreshRequested,
            OnReviewHistorySession,
            OnOpenQuarantineTab,
            OnThreatDetected,
            OnUsbScanStatus,
            OnToastActivated,
            OnActionCompleted);
        ServiceContainer.UiEvents.FocusAntivirusSignaturesRequested += OnFocusAntivirusSignaturesRequested;

        WinUiWindowMessageHook.Hook(this, SingleInstanceMessaging.WmShowMe, ShowWindow);
        WinUiWindowMessageHook.Hook(this, SingleInstanceMessaging.WmShellScan, () =>
            _ = _shellScan!.OnShellScanRequestedAsync());
        WinUiWindowMessageHook.Hook(this, WinUiWindowMessageHook.WmQueryEndSession, (_, _) => _explicitExit = true);
        WinUiWindowMessageHook.Hook(this, WinUiWindowMessageHook.WmEndSession, (wParam, _) =>
            _explicitExit = wParam != IntPtr.Zero);

        _tray.Initialize(hwnd, ShowWindow, ExitApplication);

        WinUiServiceHost.Instance.AttachWindow(
            new WinUiUserConfirmService(() => hwnd),
            new WinUiThreadScheduler(DispatcherQueue));

        ApplySavedTheme();
        EnsureWindowVisible(hwnd);
        ShowSection("overview");

        _ = RunStartupAsync();
    }

    private void ApplySavedTheme()
    {
        try
        {
            if (Content is FrameworkElement root)
                WinUiThemeManager.Initialize(WinUiServiceHost.Instance.Container.UserPreferencesAccessor, root);
            WinUiThemeManager.ThemeChanged += OnThemeChanged;
            UpdateThemeToggleIcon(WinUiThemeManager.IsEffectiveDark);
        }
        catch (Exception ex) { AppLogger.Warn("MainWindow", "ApplySavedTheme", ex); }
    }

    private void ThemeToggle_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dark = !WinUiThemeManager.IsDarkTheme;
            WinUiServiceHost.Instance.Options.ApplyTheme(dark);
            StatusText.Text = LocalizationService.GetString(dark ? "Status_ThemeDark" : "Status_ThemeLight");
        }
        catch (Exception ex) { AppLogger.Warn("MainWindow", "ThemeToggle", ex); }
    }

    private void OnThemeChanged(object? sender, bool dark)
    {
        UpdateThemeToggleIcon(dark);
        // Les Foreground assignés via GetBrush gardent l'ancienne brosse : on les recalcule.
        _ = RelabelBrushesForThemeAsync();
    }

    /// <summary>Soleil (E706) quand le sombre est actif — cliquer repasse en clair ; lune (E708) sinon.</summary>
    private void UpdateThemeToggleIcon(bool dark) =>
        ThemeToggleIcon.Glyph = dark ? "" : "";

    private async Task RelabelBrushesForThemeAsync()
    {
        try
        {
            if (_overviewPage != null)
                await WinUiServiceHost.Instance.RefreshOverviewAsync(_overviewPage).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("MainWindow", "RelabelBrushesForTheme", ex);
        }
    }

    private async Task RunStartupAsync()
    {
        try
        {
            await WinUiStartupCoordinator.RunAsync(new WinUiStartupCoordinator.Host
            {
                Container = WinUiServiceHost.Instance.Container,
                RefreshOverview = () => _ = RefreshOverviewAsync(),
                RefreshAntivirus = () => _ = RefreshAntivirusAsync(),
                RefreshHistory = () => _historyPage?.Refresh(),
                RefreshSignaturesAsync = () => WinUiServiceHost.Instance.RefreshAntivirusAsync(_antivirusPage),
                SetStatus = msg => StatusText.Text = msg,
                WarmUpYaraRulesAsync = async () =>
                {
                    try
                    {
                        var yara = WinUiServiceHost.Instance.Container.Yara;
                        if (yara == null || !yara.IsAvailable || yara.HasCompiled)
                            return;
                        await yara.CompileRulesAsync(CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (Exception ex) { AppLogger.Warn("MainWindow", "WarmUpYaraRulesAsync", ex); }
                },
                PendingShellScanPath = App.PendingShellScanPath,
                RunShellScanAsync = path => _shellScan!.RunShellScanAsync(path),
            }).ConfigureAwait(true);

            App.PendingShellScanPath = null;

            // Premier lancement : guide court (boîtes natives modales, après l'affichage de la fenêtre).
            DispatcherQueue.TryEnqueue(RunOnboardingIfNeeded);
        }
        catch (Exception ex)
        {
            StatusText.Text = LocalizationService.Format("Status_Error", ex.Message);
            AppLogger.Error("MainWindow", "Startup", ex);
        }
    }

    private void RunOnboardingIfNeeded()
    {
        try
        {
            var host = WinUiServiceHost.Instance;
            var container = host.Container;
            OnboardingCoordinator.RunIfNeeded(new OnboardingCoordinator.Host
            {
                Confirm = host.Confirm,
                Preferences = container.UserPreferencesAccessor.Current,
                SavePreferences = container.UserPreferencesAccessor.Current.Save,
                IsDefenderActive = DefenderCoexistenceService.IsDefenderActive,
                ApplyDefenderComplement = host.Options.SaveDefenderComplementMode,
                StartSignatureUpdate = () => OnOverviewActionRequested(this, "update"),
            });
        }
        catch (Exception ex)
        {
            AppLogger.Warn("MainWindow", "Onboarding", ex);
        }
    }

    public void ShowWindow()
    {
        EnsureWindowVisible(WindowNative.GetWindowHandle(this));
        StatusText.Text = OpticombatStrings.UiMessages.ProtectionActive;
    }

    private void EnsureWindowVisible(IntPtr hwnd)
    {
        if (hwnd != IntPtr.Zero)
            ShowWindowNative(hwnd, SwShow);
        _appWindow?.Show();
        Activate();
    }

    private const int SwShow = 5;

    [System.Runtime.InteropServices.DllImport("user32.dll", EntryPoint = "ShowWindow")]
    private static extern bool ShowWindowNative(IntPtr hWnd, int nCmdShow);

    private void HideToTray()
    {
        _appWindow?.Hide();
        StatusText.Text = OpticombatStrings.UiMessages.ProtectionReducedTray;
    }

    private void ExitApplication()
    {
        _explicitExit = true;
        _serviceEvents.Detach();
        ServiceContainer.UiEvents.FocusAntivirusSignaturesRequested -= OnFocusAntivirusSignaturesRequested;
        _tray.Dispose();
        try { WinUiServiceHost.Instance.Container.Shutdown(); }
        catch (Exception ex) { AppLogger.Warn("MainWindow", "Shutdown", ex); }
        Close();
        Application.Current.Exit();
    }

    private void AppWindow_Closing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (_explicitExit)
            return;

        args.Cancel = true;
        HideToTray();
    }

    private void Navigation_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is not NavigationViewItem item || item.Tag is not string tag)
            return;

        ShowSection(tag);
    }

    private void ShowSection(string tag)
    {
        // SelectionChanged peut être levé pendant InitializeComponent (IsSelected=True en XAML)
        // alors que PageHost / StatusText ne sont pas encore créés — le constructeur
        // rappelle ShowSection("overview") explicitement après InitializeComponent.
        if (PageHost is null || StatusText is null)
            return;

        var label = LocalizationService.GetString(ShellSections.NavLabelKey(tag));

        StatusText.Text = label;

        // Page déjà en cache : rafraîchir ses données (sinon elle afficherait l'état du premier affichage).
        var section = ShellSections.Normalize(tag);
        var cached = section switch
        {
            ShellSections.Antivirus => _antivirusPage != null,
            ShellSections.History => _historyPage != null,
            ShellSections.Overview => _overviewPage != null,
            _ => false,
        };

        PageHost.Content = section switch
        {
            ShellSections.Clean => GetCleanPage(),
            ShellSections.Antivirus => GetAntivirusPage(),
            ShellSections.History => GetHistoryPage(),
            ShellSections.Options => GetOptionsPage(),
            _ => GetOverviewPage()
        };

        if (cached)
        {
            _ = NavigationRefreshCoordinator.ApplyAsync(section, new NavigationRefreshCoordinator.Host
            {
                RefreshOverviewAsync = RefreshOverviewAsync,
                RefreshAntivirusAsync = () => RefreshAntivirusAsync(),
                RefreshHistory = () => _historyPage?.Refresh(),
            });
        }
    }

    private HistoryPage GetHistoryPage()
    {
        if (_historyPage != null)
            return _historyPage;

        _historyPage = new HistoryPage(WinUiServiceHost.Instance.History);
        _historyPage.Refresh();
        return _historyPage;
    }

    private CleanPage GetCleanPage()
    {
        _cleanPage ??= new CleanPage(WinUiServiceHost.Instance.Clean);
        return _cleanPage;
    }

    private OptionsPage GetOptionsPage()
    {
        _optionsPage ??= new OptionsPage(WinUiServiceHost.Instance.Options);
        return _optionsPage;
    }

    private AntivirusPage GetAntivirusPage()
    {
        if (_antivirusPage != null)
            return _antivirusPage;

        _antivirusPage = new AntivirusPage(WinUiServiceHost.Instance.Antivirus);
        _ = RefreshAntivirusAsync();
        return _antivirusPage;
    }

    private async Task RefreshAntivirusAsync(bool forceUpdate = false)
    {
        if (_antivirusPage == null)
            return;

        try
        {
            if (forceUpdate)
                await WinUiServiceHost.Instance.Antivirus.UpdateSignaturesAsync().ConfigureAwait(true);
            else
                await WinUiServiceHost.Instance.RefreshAntivirusAsync(_antivirusPage).ConfigureAwait(true);
            StatusText.Text = LocalizationService.GetString("Status_AntivirusRefreshed");
        }
        catch (Exception ex)
        {
            StatusText.Text = LocalizationService.Format("Status_AntivirusRefreshError", ex.Message);
        }
    }

    private OverviewPage GetOverviewPage()
    {
        if (_overviewPage != null)
            return _overviewPage;

        _overviewPage = new OverviewPage();
        _overviewPage.ActionRequested += OnOverviewActionRequested;
        _overviewPage.StatusMessageRequested += (_, msg) => StatusText.Text = msg;
        _ = RefreshOverviewAsync();
        return _overviewPage;
    }

    private async Task RefreshOverviewAsync()
    {
        if (_overviewPage == null)
            return;

        try
        {
            await WinUiServiceHost.Instance.RefreshOverviewAsync(_overviewPage).ConfigureAwait(true);
            StatusText.Text = LocalizationService.GetString("Status_OverviewRefreshed");
        }
        catch (Exception ex)
        {
            StatusText.Text = LocalizationService.Format("Status_OverviewRefreshError", ex.Message);
        }
    }

    private void OnOverviewActionRequested(object? sender, string action)
    {
        switch (action)
        {
            case "run-as-admin":
                RelaunchAsAdministrator();
                break;
            case "overview":
                SelectNavigation("overview");
                _ = RefreshOverviewAsync();
                break;
            case "update":
                // Comme optiSCAN : ouvrir Antivirus → Signatures puis lancer la mise à jour visible.
                SelectNavigation("antivirus");
                _antivirusPage?.SelectSignaturesTab();
                _ = RefreshAntivirusAsync(forceUpdate: true);
                break;
            case "antivirus":
                SelectNavigation("antivirus");
                _antivirusPage?.SelectScanTab();
                break;
            case "scan-quick":
                SelectNavigation("antivirus");
                _antivirusPage?.SelectScanTab();
                _ = WinUiServiceHost.Instance.Antivirus.QuickScanAsync();
                break;
            case "scan-full":
                SelectNavigation("antivirus");
                _antivirusPage?.SelectScanTab();
                _ = WinUiServiceHost.Instance.Antivirus.FullScanAsync();
                break;
            default:
                SelectNavigation(action);
                break;
        }
    }

    /// <summary>
    /// Relance optiCOMBAT en administrateur (analyse complète sans dossiers inaccessibles) :
    /// libère l'instance unique, demande l'UAC, puis ferme cette instance si la relance a réussi.
    /// </summary>
    private void RelaunchAsAdministrator()
    {
        if (ElevationHelper.IsRunningElevated())
        {
            StatusText.Text = LocalizationService.GetString("Status_AlreadyElevated");
            return;
        }

        App.ReleaseInstanceMutex();
        if (ElevationHelper.RelaunchElevated())
        {
            ExitApplication();
            return;
        }

        App.ReacquireInstanceMutex();
        StatusText.Text = LocalizationService.GetString("Status_ElevationCancelled");
    }

    public void SelectNavigation(string tag)
    {
        foreach (var item in Navigation.MenuItems)
        {
            if (item is NavigationViewItem navItem && navItem.Tag as string == tag)
            {
                Navigation.SelectedItem = navItem;
                return;
            }
        }

        ShowSection(tag);
    }

    private void OnSignatureUpdateRequested(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(() => _ = RefreshAntivirusAsync(forceUpdate: true));

    private void OnFocusAntivirusSignaturesRequested(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(() =>
        {
            SelectNavigation("antivirus");
            _antivirusPage?.SelectSignaturesTab();
        });

    private void OnHistoryRefreshRequested(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(() => _historyPage?.Refresh());

    private void OnReviewHistorySession(object? sender, ScanSession session)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            // « Traiter dans Analyse » : menaces de la session chargées dans l'onglet Analyse.
            WinUiServiceHost.Instance.Antivirus.LoadThreatsFromHistorySession(session);
            SelectNavigation("antivirus");
            _antivirusPage?.SelectScanTab();
        });
    }

    private void OnOpenQuarantineTab(object? sender, EventArgs e)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            SelectNavigation("antivirus");
            _antivirusPage?.SelectQuarantineTab();
            WinUiServiceHost.Instance.Antivirus.LoadQuarantine();
        });
    }

    private void OnThreatDetected(object? sender, ThreatInfo threat)
    {
        DispatcherQueue.TryEnqueue(() =>
            RealTimeThreatCoordinator.Handle(threat, new RealTimeThreatCoordinator.Host
            {
                SetStatus = msg => StatusText.Text = msg,
                RefreshProtectionBadge = WinUiServiceHost.Instance.Antivirus.RefreshProtectionBadge,
                RefreshQuarantineList = WinUiServiceHost.Instance.Antivirus.LoadQuarantine,
                RefreshOverview = () => _ = RefreshOverviewAsync(),
            }));
    }

    private void OnUsbScanStatus(object? sender, RemovableDriveScanStatusEventArgs e)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            StatusText.Text = UsbScanStatusCoordinator.Describe(e).Text;
            if (e.Phase == RemovableDriveScanPhase.Completed || e.ThreatsFound > 0)
                _historyPage?.Refresh();
        });
    }

    private void OnToastActivated(object? sender, ToastActivationEventArgs e) =>
        DispatcherQueue.TryEnqueue(() =>
        {
            if (_navigation is null)
                return;

            ToastActivationCoordinator.Handle(e, new ToastActivationCoordinator.Host
            {
                Services = WinUiServiceHost.Instance.Container,
                Navigation = _navigation,
                ShowWindow = ShowWindow,
                SetStatus = (msg, isError, isWarning) => StatusText.Text = msg,
                RefreshQuarantineList = () => WinUiServiceHost.Instance.Antivirus.LoadQuarantine(),
                RefreshAntivirusView = () => _ = RefreshAntivirusAsync(),
                SelectAntivirusScanTab = () =>
                {
                    SelectNavigation("antivirus");
                    _antivirusPage?.SelectScanTab();
                },
                SelectAntivirusQuarantineTab = () =>
                {
                    SelectNavigation("antivirus");
                    _antivirusPage?.SelectQuarantineTab();
                    WinUiServiceHost.Instance.Antivirus.LoadQuarantine();
                },
                SelectAntivirusSignaturesTab = () =>
                {
                    SelectNavigation("antivirus");
                    _antivirusPage?.SelectSignaturesTab();
                },
                TriggerManualSignatureUpdate = () => _ = WinUiServiceHost.Instance.Antivirus.UpdateSignaturesAsync(),
            });
        });

    private void OnActionCompleted(object? sender, ActionResult result) =>
        DispatcherQueue.TryEnqueue(() =>
            AntivirusActionResultCoordinator.Handle(result, new AntivirusActionResultCoordinator.Host
            {
                SetStatus = (msg, _, _) => StatusText.Text = msg,
                RefreshQuarantineList = WinUiServiceHost.Instance.Antivirus.LoadQuarantine,
                RefreshHistory = () => _historyPage?.Refresh(),
                RefreshOverview = () => _ = RefreshOverviewAsync(),
            }));
}
