using optiCombat.Models;
using System.Collections.Concurrent;
using System.IO;
using System.Management;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;

namespace optiCombat.Services
{
    /// <summary>
    /// Surveillance des créations de processus (WMI) — complète la RTP fichier
    /// en analysant les exécutables et hôtes de scripts au lancement.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class ProcessStartMonitor : IDisposable
    {
        private static readonly Regex QuotedPathRegex = new(
            @"[""']([^""']+\.(?:exe|dll|scr|com|msi|bat|cmd|ps1|vbs|js|hta|wsf|jar))[""']",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private readonly ProtectionScanGateway _scanGateway;
        private readonly QuarantineManager _quarantineManager;
        private readonly NotificationService _notifications;
        private readonly ConcurrentDictionary<string, DateTime> _recentScans = new(StringComparer.OrdinalIgnoreCase);
        private readonly SemaphoreSlim _scanSemaphore = new(2, 2);
        private readonly Func<bool> _isSuspended;

        private ManagementEventWatcher? _watcher;
        private bool _enabled;
        private bool _disposed;

        public event EventHandler<ThreatInfo>? ThreatDetected;

        private readonly IUserPreferencesAccessor _prefs;
        private readonly IExclusionSettingsAccessor _exclusions;

        public ProcessStartMonitor(
            ProtectionScanGateway scanGateway,
            QuarantineManager quarantineManager,
            NotificationService notifications,
            Func<bool>? isSuspended = null,
            IUserPreferencesAccessor? preferences = null,
            IExclusionSettingsAccessor? exclusions = null)
        {
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
            _scanGateway = scanGateway;
            _quarantineManager = quarantineManager;
            _notifications = notifications;
            _isSuspended = isSuspended ?? (() => false);
        }

        public void Start()
        {
            if (_enabled)
                return;

            try
            {
                var query = new WqlEventQuery(
                    "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");
                _watcher = new ManagementEventWatcher(query);
                _watcher.EventArrived += SurProcessDemarre;
                _watcher.Start();
                _enabled = true;
                AppLogger.Info("ProcessStartMonitor", "Surveillance des processus activée");
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ProcessStartMonitor", "Start", ex);
            }
        }

        public void Stop()
        {
            if (!_enabled)
                return;

            try
            {
                if (_watcher != null)
                {
                    _watcher.EventArrived -= SurProcessDemarre;
                    _watcher.Stop();
                    _watcher.Dispose();
                    _watcher = null;
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ProcessStartMonitor", "Stop", ex);
            }

            _recentScans.Clear();
            _enabled = false;
            AppLogger.Info("ProcessStartMonitor", "Surveillance des processus désactivée");
        }

        private void SurProcessDemarre(object sender, EventArrivedEventArgs e)
        {
            if (_isSuspended())
                return;

            try
            {
                if (e.NewEvent?["TargetInstance"] is not ManagementBaseObject target)
                    return;

                var processName = target["Name"]?.ToString();
                if (string.IsNullOrWhiteSpace(processName))
                    return;

                var pid = Convert.ToInt32(target["ProcessId"]);
                var paths = ResolvePathsToScan(processName, pid, target["CommandLine"]?.ToString());
                foreach (var path in paths)
                    _ = HandlePathAsync(path);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ProcessStartMonitor", "SurProcessDemarre", ex);
            }
        }

        private IEnumerable<string> ResolvePathsToScan(string processName, int pid, string? commandLine)
        {
            var results = new List<string>();

            var image = TryGetExecutablePath(pid);
            if (!string.IsNullOrWhiteSpace(image) && File.Exists(image) && RiskyFileExtensions.IsRisky(image))
                results.Add(image);

            if (RiskyFileExtensions.IsScriptHostProcess(processName) && !string.IsNullOrWhiteSpace(commandLine))
            {
                foreach (Match match in QuotedPathRegex.Matches(commandLine))
                {
                    var candidate = match.Groups[1].Value;
                    if (File.Exists(candidate) && RiskyFileExtensions.IsRisky(candidate))
                        results.Add(candidate);
                }

                foreach (var token in commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = token.Trim('"', '\'');
                    if (File.Exists(trimmed) && RiskyFileExtensions.IsRisky(trimmed))
                        results.Add(trimmed);
                }
            }

            return results.Distinct(StringComparer.OrdinalIgnoreCase);
        }

        private static string? TryGetExecutablePath(int processId)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {processId}");
                foreach (ManagementObject obj in searcher.Get())
                    return obj["ExecutablePath"]?.ToString();
            }
            catch
            {
                /* accès refusé ou processus terminé */
            }

            return null;
        }

        private async Task HandlePathAsync(string filePath)
        {
            var now = DateTime.UtcNow;
            if (_recentScans.TryGetValue(filePath, out var last) && (now - last) < TimeSpan.FromSeconds(45))
                return;
            _recentScans[filePath] = now;

            await Task.Delay(400).ConfigureAwait(false);
            if (!File.Exists(filePath) || _exclusions.Current.IsFileExcluded(filePath))
                return;

            await _scanSemaphore.WaitAsync().ConfigureAwait(false);
            try
            {
                var result = await _scanGateway.ScanFileAsync(filePath).ConfigureAwait(false);
                foreach (var threat in result.Threats)
                {
                    _notifications.ShowThreatDetected(threat);
                    if (_exclusions.Current.AutoQuarantineEnabled)
                    {
                        if (_prefs.Current.BackupBeforeQuarantine)
                            ThreatRemediationService.TryCreateSafetyCopy(threat);

                        if (_quarantineManager.Quarantine(threat))
                            _notifications.ShowQuarantined(threat);
                    }

                    ThreatDetected?.Invoke(this, threat);
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ProcessStartMonitor", $"Scan {filePath}", ex);
            }
            finally
            {
                _scanSemaphore.Release();
            }
        }

        public void Dispose()
        {
            if (_disposed)
                return;
            Stop();
            _scanSemaphore.Dispose();
            _disposed = true;
        }
    }
}
