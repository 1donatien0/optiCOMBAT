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

    public static bool IsPlatformModeEnabled() =>
        _prefs.Current.UsePlatformProtectionService;

    public static bool IsRemoteProtectionActive()
    {
        if (!IsPlatformModeEnabled())
            return false;

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
            var serviceExe = Path.Combine(AppContext.BaseDirectory, "optiCombat.Service.exe");
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
                Thread.Sleep(500);
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
            var exe = Path.Combine(AppContext.BaseDirectory, "optiCombat.exe");
            if (!File.Exists(exe))
                return;

            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("--service-host");
            Process.Start(psi);
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
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"query {ServiceName}",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
            });
            if (proc == null)
                return false;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5_000);
            return proc.ExitCode == 0 && output.Contains("SERVICE_NAME", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static void RunSc(string arguments)
    {
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        proc?.WaitForExit(30_000);
    }
}
