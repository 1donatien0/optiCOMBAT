using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace optiCombat.Services;

/// <summary>Enregistrement AMSI et chargement du minifilter (nécessite droits admin à l'installation).</summary>
[SupportedOSPlatform("windows")]
public static class PlatformRegistration
{
    private const string AmsiProviderGuid = "{A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B}";
    private const string AmsiProviderName = "optiCombat AMSI Provider";

    public static void TryRegisterAmsiProvider()
    {
        try
        {
            var dll = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "optiCombat.AmsiProvider.dll");
            if (!File.Exists(dll))
            {
                AppLogger.Warn("PlatformRegistration", "optiCombat.AmsiProvider.dll absent — AMSI non enregistré");
                return;
            }

            using var key = Registry.LocalMachine.CreateSubKey($@"SOFTWARE\Microsoft\AMSI\Providers\{AmsiProviderGuid}");
            key?.SetValue(string.Empty, AmsiProviderName);
            key?.SetValue("Path", dll, RegistryValueKind.String);
            AppLogger.Info("PlatformRegistration", "Fournisseur AMSI enregistré");
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformRegistration", "TryRegisterAmsiProvider", ex);
        }
    }

    public static void TryLoadMinifilter()
    {
        try
        {
            var sys = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "optiCombat.Minifilter.sys");
            if (!File.Exists(sys))
            {
                AppLogger.Warn("PlatformRegistration", "optiCombat.Minifilter.sys absent — minifilter non chargé");
                return;
            }

            var dest = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "optiCombat.Minifilter.sys");
            if (!File.Exists(dest))
                File.Copy(sys, dest, overwrite: true);

            RunProcess("fltmc.exe", "load optiCombatMinifilter");
            AppLogger.Info("PlatformRegistration", "Minifilter chargé (ou déjà actif)");
        }
        catch (Exception ex)
        {
            AppLogger.Warn("PlatformRegistration", "TryLoadMinifilter — test signing ou admin requis", ex);
        }
    }

    public static void TryUnloadMinifilter()
    {
        try { RunProcess("fltmc.exe", "unload optiCombatMinifilter"); } catch { }
    }

    private static void RunProcess(string file, string args)
    {
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = file,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        proc?.WaitForExit(15_000);
    }
}
