using Microsoft.Win32;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace optiCombat.Services
{
    /// <summary>
    /// Agrège plusieurs sources (registre legacy, orchestrateur Win11, correctifs WMI, WUA COM)
    /// pour réduire les faux négatifs lorsque <c>LastSuccessTime</c> est vide.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class WindowsUpdateProbe : IWindowsUpdateProbe
    {
        public static readonly TimeSpan DefaultMaxAge = TimeSpan.FromDays(60);

        private static readonly (RegistryHive Hive, string SubKey, string ValueName)[] RegistryCandidates =
        {
            (RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install",
                "LastSuccessTime"),
            (RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect",
                "LastSuccessTime"),
            (RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\UpdateOrchestrator\Install",
                "LastSuccessTime"),
            (RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\UX\StateInfo",
                "LastSuccessTime"),
            (RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\UX\StateInfo",
                "LastUpdateInstalledTime"),
        };

        public bool HasRecentSuccessfulInstall(TimeSpan maxAge)
        {
            var last = TryGetLastSuccessfulInstallUtc();
            return last.HasValue && DateTime.UtcNow - last.Value <= maxAge;
        }

        public DateTime? TryGetLastSuccessfulInstallUtc()
        {
            DateTime? best = null;

            foreach (var utc in CollectRegistryCandidates())
                best = WindowsUpdateTimeParser.MaxUtc(best, utc);

            best = WindowsUpdateTimeParser.MaxUtc(best, TryGetLatestHotfixUtc());
            best = WindowsUpdateTimeParser.MaxUtc(best, TryGetLatestWuaInstallUtc());

            return best;
        }

        private static IEnumerable<DateTime?> CollectRegistryCandidates()
        {
            foreach (var (hive, subKey, valueName) in RegistryCandidates)
            {
                DateTime? utc = null;
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
                    using var key = baseKey.OpenSubKey(subKey);
                    if (WindowsUpdateTimeParser.TryParseWmiUtc14(key?.GetValue(valueName) as string, out var parsed))
                        utc = parsed;
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("WindowsUpdateProbe", $"Registre {subKey}\\{valueName}", ex);
                }

                if (utc.HasValue)
                    yield return utc;
            }
        }

        private static DateTime? TryGetLatestHotfixUtc()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT InstalledOn FROM Win32_QuickFixEngineering");
                DateTime? best = null;

                foreach (ManagementObject obj in searcher.Get())
                {
                    try
                    {
                        if (obj["InstalledOn"] is not string raw || string.IsNullOrWhiteSpace(raw))
                            continue;

                        if (!DateTime.TryParse(raw, out var local))
                            continue;

                        var utc = local.Kind == DateTimeKind.Utc
                            ? local
                            : DateTime.SpecifyKind(local, DateTimeKind.Local).ToUniversalTime();

                        best = WindowsUpdateTimeParser.MaxUtc(best, utc);
                    }
                    finally
                    {
                        obj.Dispose();
                    }
                }

                return best;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("WindowsUpdateProbe", "WMI Win32_QuickFixEngineering", ex);
                return null;
            }
        }

        /// <summary>Agent Windows Update (COM) — souvent peuplé sur Windows 11.</summary>
        private static DateTime? TryGetLatestWuaInstallUtc()
        {
            object? session = null;
            object? searcher = null;
            object? entries = null;

            try
            {
                var sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session");
                if (sessionType == null)
                    return null;

                session = Activator.CreateInstance(sessionType)!;
                dynamic dSession = session;
                searcher = dSession.CreateUpdateSearcher();
                dynamic dSearcher = searcher;

                int count = (int)dSearcher.GetTotalHistoryCount();
                if (count <= 0)
                    return null;

                int start = Math.Max(1, count - 40);
                entries = dSearcher.QueryHistory(start, count);
                dynamic dEntries = entries;

                DateTime? best = null;
                for (int i = 0; i < dEntries.Count; i++)
                {
                    dynamic entry = dEntries.Item[i];
                    try
                    {
                        int resultCode = (int)entry.ResultCode;
                        if (resultCode is not (1 or 2))
                            continue;

                        DateTime when = entry.Date;
                        var utc = when.Kind == DateTimeKind.Utc
                            ? when
                            : DateTime.SpecifyKind(when, DateTimeKind.Local).ToUniversalTime();
                        best = WindowsUpdateTimeParser.MaxUtc(best, utc);
                    }
                    finally
                    {
                        ComReleaseHelper.Release(entry);
                    }
                }

                return best;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("WindowsUpdateProbe", "WUA COM", ex);
                return null;
            }
            finally
            {
                ComReleaseHelper.Release(entries);
                ComReleaseHelper.Release(searcher);
                ComReleaseHelper.Release(session);
            }
        }
    }
}
