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
        Title = "optiCombat - WinUI 3";
        VersionText.Text = $"v{Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0"}";
        ShowSection("overview");
        RegisterKeyboardShortcuts();

        Activated += OnActivated;
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

        WinUiWindowMessageHook.Hook(this, SingleInstanceMessaging.WmShowMe, ShowWindow);
        WinUiWindowMessageHook.Hook(this, SingleInstanceMessaging.WmShellScan, () =>
            _ = _shellScan!.OnShellScanRequestedAsync());

        _tray.Initialize(hwnd, ShowWindow, ExitApplication);

        ApplySavedTheme();

        _ = RunStartupAsync();
    }

    private void ApplySavedTheme()
    {
        try
        {
            var prefs = WinUiServiceHost.Instance.Container.UserPreferencesAccessor.Current;
            if (Content is FrameworkElement root)
                root.RequestedTheme = prefs.SyncWindowsTheme
                    ? ElementTheme.Default
                    : (prefs.DarkTheme ? ElementTheme.Dark : ElementTheme.Light);
            UpdateThemeToggleIcon(prefs.DarkTheme);
        }
        catch (Exception ex) { AppLogger.Warn("MainWindow", "ApplySavedTheme", ex); }
    }

    private void ThemeToggle_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var prefs = WinUiServiceHost.Instance.Container.UserPreferencesAccessor.Current;
            var dark = !prefs.DarkTheme;
            WinUiServiceHost.Instance.Options.ApplyTheme(dark);
            UpdateThemeToggleIcon(dark);
            StatusText.Text = dark ? "Thème sombre activé" : "Thème clair activé";
        }
        catch (Exception ex) { AppLogger.Warn("MainWindow", "ThemeToggle", ex); }
    }

    /// <summary>Soleil (E706) quand le sombre est actif — cliquer repasse en clair ; lune (E708) sinon.</summary>
    private void UpdateThemeToggleIcon(bool dark) =>
        ThemeToggleIcon.Glyph = dark ? "" : "";

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
        }
        catch (Exception ex)
        {
            StatusText.Text = LocalizationService.Format("Status_Error", ex.Message);
            AppLogger.Error("MainWindow", "Startup", ex);
        }
    }

    public void ShowWindow()
    {
        if (_appWindow == null)
            return;

        _appWindow.Show();
        Activate();
        StatusText.Text = OpticombatStrings.UiMessages.ProtectionActive;
    }

    private void HideToTray()
    {
        _appWindow?.Hide();
        StatusText.Text = OpticombatStrings.UiMessages.ProtectionReducedTray;
    }

    private void ExitApplication()
    {
        _explicitExit = true;
        _serviceEvents.Detach();
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

        var label = tag switch
        {
            "overview" => "Accueil",
            "clean" => "Nettoyer",
            "antivirus" => "Antivirus",
            "history" => "Historique",
            "options" => "Options",
            _ => "Accueil"
        };

        StatusText.Text = $"Section {label}";

        PageHost.Content = tag switch
        {
            "overview" => GetOverviewPage(),
            "clean" => GetCleanPage(),
            "antivirus" => GetAntivirusPage(),
            "history" => GetHistoryPage(),
            "options" => GetOptionsPage(),
            _ => new PlaceholderPage(label, "Socle WinUI 3 prêt pour le portage progressif des panneaux.")
        };
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
            StatusText.Text = "Antivirus synchronisé avec les services optiCombat";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Actualisation antivirus : {ex.Message}";
        }
    }

    private OverviewPage GetOverviewPage()
    {
        if (_overviewPage != null)
            return _overviewPage;

        _overviewPage = new OverviewPage();
        _overviewPage.ActionRequested += OnOverviewActionRequested;
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
            StatusText.Text = "Accueil synchronisé avec les services optiCombat";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Actualisation accueil : {ex.Message}";
        }
    }

    private void OnOverviewActionRequested(object? sender, string action)
    {
        switch (action)
        {
            case "run-as-admin":
                StatusText.Text = "Relance administrateur — à brancher via optiCombat.Platform";
                break;
            case "update":
                SelectNavigation("antivirus");
                _antivirusPage?.SelectSignaturesTab();
                _ = RefreshAntivirusAsync(forceUpdate: true);
                break;
            case "antivirus":
                SelectNavigation("antivirus");
                _antivirusPage?.SelectScanTab();
                break;
            default:
                SelectNavigation(action);
                break;
        }
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

    private void OnHistoryRefreshRequested(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(() => _historyPage?.Refresh());

    private void OnReviewHistorySession(object? sender, ScanSession session)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            SelectNavigation("history");
            WinUiServiceHost.Instance.History.TrySelectScanSession(session.SessionId);
            _historyPage?.Refresh();
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
        {
            WinUiServiceHost.Instance.Antivirus.RefreshProtectionBadge();
            StatusText.Text = LocalizationService.Format("Rtp_ThreatToastTitle", threat.VirusName);
        });
    }

    private void OnUsbScanStatus(object? sender, RemovableDriveScanStatusEventArgs e)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            StatusText.Text = e.Phase switch
            {
                RemovableDriveScanPhase.Started =>
                    LocalizationService.Format("Status_UsbScanStarting", e.DriveLabel),
                RemovableDriveScanPhase.Failed =>
                    LocalizationService.Format("Status_UsbScanFailed", e.DriveLabel),
                _ => LocalizationService.Format("Status_UsbScanComplete", e.DriveLabel, e.FilesScanned, e.ThreatsFound),
            };
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
        DispatcherQueue.TryEnqueue(() => StatusText.Text = result.Message);
}
