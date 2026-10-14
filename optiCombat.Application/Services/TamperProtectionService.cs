using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using System.Threading;

namespace optiCombat.Services
{
    /// <summary>
    /// Anti-manipulation : tâche planifiée de surveillance et relance de la protection.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class TamperProtectionService
    {
        private const string WatchdogTaskName = "optiCombat_Watchdog";

        private readonly string _exePath;
        private readonly IUserPreferencesAccessor _prefs;
        private readonly IExclusionSettingsAccessor _exclusions;

        public TamperProtectionService(
            IUserPreferencesAccessor? preferences = null,
            IExclusionSettingsAccessor? exclusions = null)
        {
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
            _exePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "optiCombat.exe");
        }

        public bool EnsureWatchdogTask()
        {
            if (!_prefs.Current.TamperProtectionEnabled)
                return DeleteWatchdogTask();

            try
            {
                DeleteWatchdogTask();
                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                psi.ArgumentList.Add("/Create");
                psi.ArgumentList.Add("/F");
                psi.ArgumentList.Add("/TN");
                psi.ArgumentList.Add(WatchdogTaskName);
                psi.ArgumentList.Add("/SC");
                psi.ArgumentList.Add("MINUTE");
                psi.ArgumentList.Add("/MO");
                psi.ArgumentList.Add("15");
                psi.ArgumentList.Add("/RL");
                psi.ArgumentList.Add("LIMITED");
                psi.ArgumentList.Add("/TR");
                psi.ArgumentList.Add($"{_exePath} --watchdog --quiet");

                using var proc = Process.Start(psi);
                proc?.WaitForExit(15_000);
                var ok = proc is { ExitCode: 0 };
                if (ok)
                    AppLogger.Info("TamperProtection", "Tâche watchdog enregistrée");
                return ok;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("TamperProtection", "EnsureWatchdogTask", ex);
                return false;
            }
        }

        public bool DeleteWatchdogTask()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                psi.ArgumentList.Add("/Delete");
                psi.ArgumentList.Add("/F");
                psi.ArgumentList.Add("/TN");
                psi.ArgumentList.Add(WatchdogTaskName);
                using var proc = Process.Start(psi);
                proc?.WaitForExit(10_000);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Exécuté par <c>--watchdog</c> : relance la protection si RTP attendue mais aucune instance.</summary>
        public static void RunWatchdogCheck()
        {
            var exclusions = new DefaultExclusionSettingsAccessor();
            var prefs = new DefaultUserPreferencesAccessor();
            if (!exclusions.Current.RealTimeEnabled || !prefs.Current.TamperProtectionEnabled)
                return;

            if (prefs.Current.UsePlatformProtectionService)
            {
                if (PlatformProtectionBootstrap.IsRemoteProtectionActive())
                    return;

                PlatformProtectionBootstrap.EnsurePlatformProtectionRunning();
                return;
            }

            const string mutexName = "Global\\optiCombat_UniqueInstance";
            try
            {
                using var existing = Mutex.OpenExisting(mutexName);
                return;
            }
            catch (WaitHandleCannotBeOpenedException)
            {
                /* aucune instance — relancer */
            }

            try
            {
                var exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "optiCombat.exe");
                var psi = new ProcessStartInfo
                {
                    FileName = exe,
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Minimized,
                };
                psi.ArgumentList.Add("--guard");
                Process.Start(psi);
                AppLogger.Info("TamperProtection", "Watchdog — relance session garde");
            }
            catch (Exception ex)
            {
                AppLogger.Warn("TamperProtection", "RunWatchdogCheck", ex);
            }
        }
    }
}
