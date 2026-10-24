using optiCombat.Models;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;

namespace optiCombat.Services;

/// <summary>Installation et supervision du service Windows optiCombat.Service (protection système avancée).</summary>
[SupportedOSPlatform("windows")]
public static class PlatformProtectionBootstrap
{
    public const string ServiceName = "optiCombatProtection";
    public const string ServiceDisplayName = "optiCombat Protection";

    private static IUserPreferencesAccessor _prefs = new DefaultUserPreferencesAccessor();

    public static void Initialize(IUserPreferencesAccessor? preferences = null)
    {
        if (preferences != null)
            _prefs = preferences;
    }

    /// <summary>Tests uniquement : sonde IPC, dossier des exécutables et délai d'attente du service.</summary>
    internal static Func<bool>? RemoteProbeOverride { get; set; }

    internal static string? BaseDirectoryOverride { get; set; }

    internal static TimeSpan StartPollDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    private static string BaseDirectory => BaseDirectoryOverride ?? AppContext.BaseDirectory;

    public static bool IsPlatformModeEnabled() =>
        _prefs.Current.UsePlatformProtectionService;

    public static bool IsRemoteProtectionActive()
    {
        if (!IsPlatformModeEnabled())
            return false;

        if (RemoteProbeOverride is { } probe)
            return probe();

        try
        {
            using var client = new Platform.ProtectionPipeClient();
            return client.IsServiceReachable();
        }
        catch
        {
            return false;
        }
    }

    public static void EnsurePlatformProtectionRunning()
    {
        if (!IsPlatformModeEnabled())
            return;

        if (IsRemoteProtectionActive())
            return;

        if (TryStartWindowsService())
            return;

        TryLaunchServiceHostProcess();
    }

    public static bool TryInstallWindowsService()
    {
        try
        {
            var serviceExe = Path.Combine(BaseDirectory, "optiCombat.Service.exe");
            if (!File.Exists(serviceExe))
            {
                AppLogger.Warn("PlatformProtection", "optiCombat.Service.exe absent");
                return false;
            }

            if (IsServiceInstalled())
                return true;

            var binPath = $"\"{serviceExe}\"";
            RunSc($"create {ServiceName} binPath= {binPath} start= auto DisplayName= \"{ServiceDisplayName}\"");
            RunSc($"description {ServiceName} \"Moteur de protection optiCombat (RTP, AMSI, IPC)\"");
            AppLogger.Info("PlatformProtection", "Service Windows enregistré");
            return true;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformProtection", "TryInstallWindowsService", ex);
            return false;
        }
    }

    public static bool TryStartWindowsService()
    {
        try
        {
            TryInstallWindowsService();
            if (!IsServiceInstalled())
                return false;

            RunSc($"start {ServiceName}");
            for (var i = 0; i < 10; i++)
            {
                if (IsRemoteProtectionActive())
                    return true;
                Thread.Sleep(StartPollDelay);
            }

            return IsRemoteProtectionActive();
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformProtection", "TryStartWindowsService", ex);
            return false;
        }
    }

    public static void TryLaunchServiceHostProcess()
    {
        try
        {
            var exe = Path.Combine(BaseDirectory, "optiCombat.exe");
            if (!File.Exists(exe))
                return;

            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("--service-host");
            if (SystemShell.Current.Run(psi, timeoutMs: null).Started)
                AppLogger.Info("PlatformProtection", "Processus --service-host lancé (secours)");
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformProtection", "TryLaunchServiceHostProcess", ex);
        }
    }

    public static void TryStopWindowsService()
    {
        try
        {
            if (IsServiceInstalled())
                RunSc($"stop {ServiceName}");
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformProtection", "TryStopWindowsService", ex);
        }
    }

    public static void TryUninstallWindowsService()
    {
        try
        {
            TryStopWindowsService();
            if (IsServiceInstalled())
                RunSc($"delete {ServiceName}");
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformProtection", "TryUninstallWindowsService", ex);
        }
    }

    private static bool IsServiceInstalled()
    {
        try
        {
            var outcome = SystemShell.Current.Run(new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"query {ServiceName}",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
            }, 5_000);
            return outcome.Succeeded && outcome.Output.Contains("SERVICE_NAME", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static void RunSc(string arguments) =>
        SystemShell.Current.Run(new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
        }, 30_000);
}
