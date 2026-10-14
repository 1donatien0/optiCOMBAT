using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using Microsoft.Win32;
using optiCombat.Platform;

namespace optiCombat.Services;

public enum PlatformComponentState
{
    Active,
    Inactive,
    Warning,
    NotApplicable,
}

public sealed class PlatformComponentStatus
{
    public string LabelKey { get; init; } = string.Empty;
    public PlatformComponentState State { get; init; }
}

public sealed class PlatformProtectionStatusReport
{
    public IReadOnlyList<PlatformComponentStatus> Components { get; init; } = Array.Empty<PlatformComponentStatus>();
    public bool HasWarnings { get; init; }
}

/// <summary>État AMSI, minifilter, IPC et coexistence Defender.</summary>
[SupportedOSPlatform("windows")]
public static class PlatformProtectionStatusService
{
    private const string AmsiProviderGuid = "{A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B}";

    public static PlatformProtectionStatusReport Evaluate(IUserPreferencesAccessor? preferences = null)
    {
        if (!PlatformProtectionFeatureGate.IsUserActivatable)
        {
            return new PlatformProtectionStatusReport
            {
                Components =
                [
                    new PlatformComponentStatus
                    {
                        LabelKey = "Platform_PlannedUnavailable",
                        State = PlatformComponentState.NotApplicable,
                    },
                ],
                HasWarnings = false,
            };
        }

        var items = new List<PlatformComponentStatus>();
        var prefs = (preferences ?? new DefaultUserPreferencesAccessor()).Current;

        if (prefs.UsePlatformProtectionService)
        {
            var ipc = PlatformProtectionBootstrap.IsRemoteProtectionActive();
            items.Add(new PlatformComponentStatus
            {
                LabelKey = ipc ? "Platform_IpcActive" : "Platform_IpcInactive",
                State = ipc ? PlatformComponentState.Active : PlatformComponentState.Warning,
            });
        }
        else
        {
            items.Add(new PlatformComponentStatus
            {
                LabelKey = "Platform_IpcDisabled",
                State = PlatformComponentState.NotApplicable,
            });
        }

        var dllPath = Path.Combine(AppContext.BaseDirectory, "optiCombat.AmsiProvider.dll");
        var dllPresent = File.Exists(dllPath);
        var amsiRegistered = IsAmsiProviderRegistered(dllPath);

        if (!dllPresent)
        {
            items.Add(new PlatformComponentStatus
            {
                LabelKey = "Platform_AmsiDllMissing",
                State = PlatformComponentState.Warning,
            });
        }
        else if (!amsiRegistered)
        {
            items.Add(new PlatformComponentStatus
            {
                LabelKey = "Platform_AmsiNotRegistered",
                State = PlatformComponentState.Warning,
            });
        }
        else
        {
            items.Add(new PlatformComponentStatus
            {
                LabelKey = "Platform_AmsiRegistered",
                State = PlatformComponentState.Active,
            });
        }

        if (IsDefenderServiceRunning() && amsiRegistered)
        {
            items.Add(new PlatformComponentStatus
            {
                LabelKey = "Platform_DefenderMayOverride",
                State = PlatformComponentState.Warning,
            });
        }

        var sysPresent = File.Exists(Path.Combine(AppContext.BaseDirectory, "optiCombat.Minifilter.sys"));
        var fltLoaded = IsMinifilterLoaded();

        if (fltLoaded)
        {
            items.Add(new PlatformComponentStatus
            {
                LabelKey = "Platform_MinifilterLoaded",
                State = PlatformComponentState.Active,
            });
        }
        else if (sysPresent)
        {
            items.Add(new PlatformComponentStatus
            {
                LabelKey = "Platform_MinifilterNotLoaded",
                State = PlatformComponentState.Warning,
            });
        }
        else
        {
            items.Add(new PlatformComponentStatus
            {
                LabelKey = "Platform_MinifilterAbsent",
                State = PlatformComponentState.Inactive,
            });
        }

        return new PlatformProtectionStatusReport
        {
            Components = items,
            HasWarnings = items.Any(c => c.State is PlatformComponentState.Warning or PlatformComponentState.Inactive),
        };
    }

    internal static bool IsAmsiProviderRegistered(string expectedDllPath)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\AMSI\Providers\{AmsiProviderGuid}");
            var path = key?.GetValue("Path") as string;
            return !string.IsNullOrWhiteSpace(path)
                && string.Equals(Path.GetFullPath(path), Path.GetFullPath(expectedDllPath), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    internal static bool IsMinifilterLoaded()
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "fltmc.exe",
                Arguments = "filters",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
            });
            if (proc == null)
                return false;

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10_000);
            return output.Contains("optiCombatMinifilter", StringComparison.OrdinalIgnoreCase)
                || output.Contains("optiCombat.Minifilter", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsDefenderServiceRunning()
    {
        try
        {
            using var sc = new System.ServiceProcess.ServiceController("WinDefend");
            return sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
        }
        catch
        {
            return false;
        }
    }
}
