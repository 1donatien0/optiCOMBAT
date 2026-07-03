using Microsoft.UI.Xaml;
using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using System.Threading;

namespace optiCombat.WinUI;

public partial class App : Application
{
    private const string MutexName = "Global\\optiCombat_UniqueInstance";
    private static Mutex? _instanceMutex;
    private Window? _window;

    public static string[] LaunchArguments { get; private set; } = Array.Empty<string>();

    public static MainWindow? MainWindowInstance { get; private set; }

    public static string? PendingShellScanPath { get; internal set; }

    public App()
    {
        InitializeComponent();
        UnhandledException += OnUnhandledException;
    }

    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        LaunchArguments = Environment.GetCommandLineArgs().Skip(1).ToArray();
        LocalizationService.Initialize();

        if (ShellScanArguments.TryGetScanPath(LaunchArguments, out var shellPath)
            && ElevationHelper.NeedsElevation(shellPath)
            && !ElevationHelper.IsRunningElevated())
        {
            if (ElevationHelper.RelaunchElevated(ShellScanArguments.Scan, shellPath))
            {
                Exit();
                return;
            }
        }

        var headlessMode = HeadlessScanArguments.ParseMode(LaunchArguments);
        if (headlessMode == HeadlessScanArguments.Mode.Watchdog)
        {
            TamperProtectionService.RunWatchdogCheck();
            Exit();
            return;
        }

        if (headlessMode == HeadlessScanArguments.Mode.DefenderExclusions)
        {
            WindowsDefenderExclusionService.EnsureOpticombatExclusions();
            Exit();
            return;
        }

        if (headlessMode == HeadlessScanArguments.Mode.ServiceHost)
        {
            bool createdService;
            _instanceMutex = new Mutex(true, "Global\\optiCombat_ServiceHost", out createdService);
            if (!createdService)
            {
                Exit();
                return;
            }

            await RunServiceHostAsync().ConfigureAwait(true);
            Exit();
            return;
        }

        if (headlessMode is HeadlessScanArguments.Mode.FullScan or HeadlessScanArguments.Mode.QuickScan)
        {
            bool createdHeadless;
            _instanceMutex = new Mutex(true, MutexName, out createdHeadless);
            if (!createdHeadless)
            {
                try { new ScanLogManager().WriteToLog("[Headless] Instance déjà active — scan ignoré."); }
                catch { }
                _instanceMutex.Close();
                _instanceMutex = null;
                Exit();
                return;
            }

            await RunHeadlessAsync(headlessMode, HeadlessScanArguments.IsQuiet(LaunchArguments)).ConfigureAwait(true);
            Exit();
            return;
        }

        bool createdNew;
        _instanceMutex = new Mutex(true, MutexName, out createdNew);

        if (!createdNew)
        {
            if (ShellScanArguments.TryGetScanPath(LaunchArguments, out var existingScanPath)
                && ShellScanArguments.IsValidScanTarget(existingScanPath))
            {
                ShellScanRequest.Publish(existingScanPath);
                SingleInstanceMessaging.NotifyShellScanRequest();
            }

            SingleInstanceMessaging.NotifyShowExistingInstance();
            _instanceMutex.Close();
            _instanceMutex = null;
            Exit();
            return;
        }

        if (ShellScanArguments.TryGetScanPath(LaunchArguments, out var pendingShellPath)
            && ShellScanArguments.IsValidScanTarget(pendingShellPath))
        {
            PendingShellScanPath = pendingShellPath;
        }

        _window = new MainWindow();
        MainWindowInstance = (MainWindow)_window;
        _window.Activate();
    }

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
                HeadlessScanArguments.Mode.FullScan => await orchestrator.FullScanAsync().ConfigureAwait(false),
                HeadlessScanArguments.Mode.QuickScan => await orchestrator.QuickScanAsync().ConfigureAwait(false),
                _ => throw new InvalidOperationException("Mode headless non supporté")
            };

            logger.SaveScanResult(result);
            logger.WriteToLog(
                $"[Headless] Terminé — {result.FilesScanned} fichier(s), " +
                $"{result.ThreatsFound} menace(s), statut {result.Status}");

            if (container.ExclusionSettingsAccessor.Current.AutoQuarantineEnabled)
            {
                int q = quarantine.QuarantineAll(result.Threats, result.SessionId);
                logger.WriteToLog($"[Headless] Quarantaine automatique : {q} fichier(s)");
            }

            if (!quiet && result.ThreatsFound > 0)
            {
                try { container.Notifications.ShowScanCompleted(result.ThreatsFound, result.FilesScanned); }
                catch (Exception ex) { logger.WriteToLog($"[Headless] Notification: {ex.Message}"); }
            }
        }
        catch (Exception ex)
        {
            try { new ScanLogManager().WriteToLog($"[Headless] FATAL: {ex}"); }
            catch { }
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
            catch { }
        }
    }

    private static void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        try
        {
            var logDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiCombat",
                "Logs");
            Directory.CreateDirectory(logDir);
            File.AppendAllText(
                Path.Combine(logDir, "winui-crash.log"),
                $"[{DateTimeOffset.Now:O}] {e.Exception}\n");
        }
        catch
        {
        }
    }
}
