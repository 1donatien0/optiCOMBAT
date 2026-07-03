using System.IO;
using System.Management;
using System.Runtime.Versioning;
using optiCombat.Localization;
using optiCombat.Models;

namespace optiCombat.Services
{
    /// <summary>
    /// Détecte le branchement de lecteurs amovibles (USB, carte SD…) et lance un scan
    /// en arrière-plan via <see cref="ScanOrchestrator"/>.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class RemovableDriveScanService : IDisposable
    {
        private const int MountSettleDelayMs = 2000;
        private const int PollIntervalMs = 4000;
        private static readonly TimeSpan QuickScanTimeout = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan DetailedScanTimeout = TimeSpan.FromMinutes(45);
        private static readonly TimeSpan RiskyFileEnumTimeout = TimeSpan.FromSeconds(90);
        private const int WmiDeviceArrival = 2;
        private const int WmiDeviceRemoval = 3;

        private readonly ScanOrchestrator _orchestrator;
        private readonly QuarantineManager _quarantine;
        private readonly NotificationService _notifications;
        private readonly ScanLogManager _logger;
        private readonly RealTimeProtection _realTimeProtection;
        private readonly IUiEventBus _uiEvents;
        private readonly IUserPreferencesAccessor _prefs;
        private readonly IExclusionSettingsAccessor _exclusions;
        private readonly HashSet<string> _knownRoots = new(StringComparer.OrdinalIgnoreCase);
        private readonly SemaphoreSlim _scanLock = new(1, 1);
        private readonly object _lifecycleLock = new();

        private ManagementEventWatcher? _volumeWatcher;
        private System.Threading.Timer? _pollTimer;
        private bool _started;
        private bool _disposed;

        public event EventHandler<ThreatInfo>? ThreatDetected;

        /// <summary>Émis au début et à la fin d'une analyse USB (thread pool — marshaler vers l'UI).</summary>
        public event EventHandler<RemovableDriveScanStatusEventArgs>? ScanStatusChanged;

        public RemovableDriveScanService(
            ScanOrchestrator orchestrator,
            QuarantineManager quarantine,
            NotificationService notifications,
            ScanLogManager logger,
            RealTimeProtection realTimeProtection,
            IUiEventBus uiEvents,
            IUserPreferencesAccessor? preferences = null,
            IExclusionSettingsAccessor? exclusions = null)
        {
            _orchestrator = orchestrator;
            _quarantine = quarantine;
            _notifications = notifications;
            _logger = logger;
            _realTimeProtection = realTimeProtection;
            _uiEvents = uiEvents;
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
        }

        public void Start()
        {
            lock (_lifecycleLock)
            {
                if (_started || _disposed) return;
                SeedKnownRemovableRoots();
                TryStartVolumeWatcher();
                _pollTimer = new System.Threading.Timer(
                    _ => PollForNewDrives(),
                    null,
                    PollIntervalMs,
                    PollIntervalMs);
                _started = true;
                AppLogger.Info("RemovableDriveScan", "Surveillance des lecteurs amovibles démarrée.");
            }
        }

        public void Stop()
        {
            lock (_lifecycleLock)
            {
                if (!_started) return;
                _volumeWatcher?.Stop();
                _volumeWatcher?.Dispose();
                _volumeWatcher = null;
                _pollTimer?.Dispose();
                _pollTimer = null;
                _started = false;
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            Stop();
            _scanLock.Dispose();
            _disposed = true;
        }

        private void SeedKnownRemovableRoots()
        {
            foreach (var root in RemovableDriveDiscovery.GetReadyRemovableRoots())
                _knownRoots.Add(root);
        }

        private void TryStartVolumeWatcher()
        {
            try
            {
                var query = new WqlEventQuery(
                    "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2 OR EventType = 3");
                _volumeWatcher = new ManagementEventWatcher(query);
                _volumeWatcher.EventArrived += (_, e) => OnVolumeChange(e);
                _volumeWatcher.Start();
            }
            catch (Exception ex)
            {
                AppLogger.Warn("RemovableDriveScan", "WMI Win32_VolumeChangeEvent indisponible — repli sur polling.", ex);
            }
        }

        private void OnVolumeChange(EventArrivedEventArgs e)
        {
            try
            {
                var props = e.NewEvent?.Properties;
                if (props == null) return;

                var eventType = Convert.ToInt32(props["EventType"]?.Value ?? 0);
                var driveName = props["DriveName"]?.Value as string;

                if (eventType == WmiDeviceRemoval && !string.IsNullOrWhiteSpace(driveName))
                {
                    var root = RemovableDriveDiscovery.NormalizeRootFromDriveName(driveName);
                    if (root != null)
                        _knownRoots.Remove(root);
                    return;
                }

                if (eventType == WmiDeviceArrival)
                    _ = ScheduleScanNewDrivesAsync();
            }
            catch (Exception ex)
            {
                AppLogger.Warn("RemovableDriveScan", "OnVolumeChange", ex);
            }
        }

        private void PollForNewDrives() =>
            _ = ScheduleScanNewDrivesAsync();

        private async Task ScheduleScanNewDrivesAsync()
        {
            if (!_prefs.Current.RemovableDriveScanEnabled)
                return;

            try
            {
                await Task.Delay(MountSettleDelayMs).ConfigureAwait(false);
                var newRoots = RemovableDriveDiscovery.FindNewRemovableRoots(_knownRoots);
                foreach (var root in newRoots)
                {
                    _knownRoots.Add(root);
                    await ScanRootIfEligibleAsync(root).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("RemovableDriveScan", "ScheduleScanNewDrivesAsync", ex);
            }
        }

        private async Task ScanRootIfEligibleAsync(string root)
        {
            if (!_prefs.Current.RemovableDriveScanEnabled)
                return;

            if (!RemovableDriveDiscovery.TryGetDriveInfo(root, out var drive))
                return;

            if (!RemovableDriveDiscovery.IsWithinSizeLimit(drive.TotalSize, _prefs.Current.RemovableDriveMaxSizeGb))
            {
                AppLogger.Info("RemovableDriveScan", $"Lecteur ignoré (taille) : {root}");
                return;
            }

            if (_exclusions.Current.IsFolderExcluded(root))
            {
                AppLogger.Info("RemovableDriveScan", $"Lecteur exclu : {root}");
                return;
            }

            if (!_orchestrator.IsClamAvAvailable && !_orchestrator.IsYaraAvailable)
            {
                AppLogger.Warn("RemovableDriveScan", "Aucun moteur disponible — scan USB ignoré.");
                return;
            }

            await _scanLock.WaitAsync().ConfigureAwait(false);
            try
            {
                await RunScanAsync(root).ConfigureAwait(false);
            }
            finally
            {
                _scanLock.Release();
            }
        }

        private async Task RunScanAsync(string root)
        {
            var driveLabel = RemovableDriveDiscovery.GetDriveDisplayLabel(root);
            var detailed = _prefs.Current.RemovableDriveScanDetailed;
            AppLogger.Info("RemovableDriveScan", $"Analyse du lecteur {root}… (mode {(detailed ? "complet" : "rapide")})");

            NotifyScanStatus(RemovableDriveScanPhase.Started, root, driveLabel, 0, 0);

            if (_prefs.Current.ActionNotificationsEnabled)
                _notifications.ShowRemovableDriveScanStarted(driveLabel);

            ScanResult? result = null;
            var scanSucceeded = false;

            _realTimeProtection.Suspend();
            try
            {
                using var cts = new CancellationTokenSource(detailed ? DetailedScanTimeout : QuickScanTimeout);
                try
                {
                    result = detailed
                        ? await ScanDetailedAsync(root, cts.Token).ConfigureAwait(false)
                        : await ScanQuickAsync(root, cts.Token).ConfigureAwait(false);
                    scanSucceeded = result.Status is ScanStatus.Completed or ScanStatus.Cancelled;
                }
                catch (OperationCanceledException)
                {
                    AppLogger.Warn("RemovableDriveScan", $"Analyse {root} annulée (délai dépassé).");
                }
                catch (Exception ex)
                {
                    AppLogger.Error("RemovableDriveScan", $"Échec scan {root}", ex);
                }

                if (scanSucceeded && result != null)
                {
                    _logger.SaveScanResult(result);
                    _prefs.Current.IncrementScanCount(ScanType.RemovableDrive);
                    _uiEvents.RequestScanHistoryViewsRefresh();

                    if (result.Threats.Count > 0)
                    {
                        if (_exclusions.Current.AutoQuarantineEnabled)
                        {
                            int n = 0;
                            foreach (var threat in result.Threats.ToList())
                            {
                                if (_quarantine.Quarantine(threat, result.SessionId))
                                {
                                    n++;
                                    _logger.TryRemoveThreatFromSession(result.SessionId, threat.FilePath);
                                }
                            }
                            if (n > 0)
                            {
                                AppLogger.Info("RemovableDriveScan", $"{n} fichier(s) mis en quarantaine sur {root}.");
                                _uiEvents.RequestScanHistoryViewsRefresh();
                            }
                        }

                        foreach (var threat in result.Threats)
                            ThreatDetected?.Invoke(this, threat);
                    }

                    if (_prefs.Current.ActionNotificationsEnabled)
                        _notifications.ShowRemovableDriveScanCompleted(
                            driveLabel, result.Threats.Count, result.FilesScanned);
                }
            }
            finally
            {
                _realTimeProtection.Resume();

                var phase = scanSucceeded ? RemovableDriveScanPhase.Completed : RemovableDriveScanPhase.Failed;
                var threats = result?.Threats.Count ?? 0;
                var files = result?.FilesScanned ?? 0;
                NotifyScanStatus(phase, root, driveLabel, threats, files);
            }
        }

        private async Task<ScanResult> ScanDetailedAsync(string root, CancellationToken ct)
        {
            var result = await _orchestrator.ScanFolderBackgroundAsync(root, ScanType.RemovableDrive, ct).ConfigureAwait(false);
            result.Type = ScanType.RemovableDrive;
            return result;
        }

        /// <summary>
        /// Scan USB rapide : extensions à risque, plafonnées, moteurs en série (évite les verrous USB).
        /// Repli sur scan dossier si la liste de fichiers échoue.
        /// </summary>
        private async Task<ScanResult> ScanQuickAsync(string root, CancellationToken ct)
        {
            var files = await Task.Run(
                () => RemovableDriveDiscovery.CollectRiskyFiles(
                    root,
                    RemovableDriveDiscovery.QuickScanMaxFiles,
                    ct,
                    RiskyFileEnumTimeout,
                    _exclusions),
                ct).ConfigureAwait(false);

            AppLogger.Info("RemovableDriveScan",
                $"Mode rapide {root} — {files.Count} fichier(s) à risque.");

            ScanResult result;
            if (files.Count > 0)
            {
                result = await _orchestrator.ScanFileListAsync(
                    files,
                    root,
                    ScanType.RemovableDrive,
                    progress: null,
                    ct,
                    scanEnginesSequentially: true).ConfigureAwait(false);

                if (result.Status is ScanStatus.Error or ScanStatus.Cancelled)
                {
                    AppLogger.Warn("RemovableDriveScan",
                        $"Scan liste {root} interrompu ({result.Status}) — repli scan récursif.");
                    result = await _orchestrator.ScanFolderBackgroundAsync(root, ScanType.RemovableDrive, ct)
                        .ConfigureAwait(false);
                }
            }
            else
            {
                var now = DateTime.Now;
                result = new ScanResult
                {
                    Type = ScanType.RemovableDrive,
                    TargetPath = root,
                    StartedAt = now,
                    FinishedAt = now,
                    Status = ScanStatus.Completed,
                    FilesScanned = 0,
                };
            }

            result.Type = ScanType.RemovableDrive;
            return result;
        }

        private void NotifyScanStatus(
            RemovableDriveScanPhase phase,
            string root,
            string driveLabel,
            int threatsFound,
            int filesScanned)
        {
            try
            {
                ScanStatusChanged?.Invoke(this, new RemovableDriveScanStatusEventArgs(
                    phase, root, driveLabel, threatsFound, filesScanned));
            }
            catch (Exception ex)
            {
                AppLogger.Warn("RemovableDriveScan", "ScanStatusChanged", ex);
            }
        }
    }

    public enum RemovableDriveScanPhase
    {
        Started,
        Completed,
        Failed
    }

    public sealed class RemovableDriveScanStatusEventArgs : EventArgs
    {
        public RemovableDriveScanStatusEventArgs(
            RemovableDriveScanPhase phase,
            string root,
            string driveLabel,
            int threatsFound,
            int filesScanned)
        {
            Phase = phase;
            Root = root;
            DriveLabel = driveLabel;
            ThreatsFound = threatsFound;
            FilesScanned = filesScanned;
        }

        public RemovableDriveScanPhase Phase { get; }
        public string Root { get; }
        public string DriveLabel { get; }
        public int ThreatsFound { get; }
        public int FilesScanned { get; }
    }

    /// <summary>Détection et filtrage des lecteurs amovibles (testable).</summary>
    internal static class RemovableDriveDiscovery
    {
        public const int QuickScanMaxFiles = 4000;

        public static IReadOnlyList<string> GetReadyRemovableRoots()
        {
            var list = new List<string>();
            foreach (var d in DriveInfo.GetDrives())
            {
                if (TryNormalizeRoot(d, out var root))
                    list.Add(root);
            }
            return list;
        }

        public static IReadOnlyList<string> FindNewRemovableRoots(ISet<string> knownRoots)
        {
            var list = new List<string>();
            foreach (var d in DriveInfo.GetDrives())
            {
                if (!TryNormalizeRoot(d, out var root))
                    continue;
                if (!knownRoots.Contains(root))
                    list.Add(root);
            }
            return list;
        }

        public static string? NormalizeRootFromDriveName(string driveName)
        {
            if (string.IsNullOrWhiteSpace(driveName))
                return null;
            var trimmed = driveName.Trim().TrimEnd('\\');
            if (trimmed.Length == 2 && trimmed[1] == ':')
                return trimmed + "\\";
            return null;
        }

        public static bool IsWithinSizeLimit(long totalBytes, int maxSizeGb)
        {
            if (maxSizeGb <= 0)
                return true;
            if (totalBytes <= 0)
                return true;
            return totalBytes <= (long)maxSizeGb * 1024L * 1024L * 1024L;
        }

        public static bool TryGetDriveInfo(string root, out DriveInfo drive)
        {
            drive = null!;
            try
            {
                var letter = root.TrimEnd('\\');
                if (letter.Length < 2)
                    return false;
                drive = new DriveInfo(letter);
                return drive.IsReady && IsEligibleForAutoScan(drive);
            }
            catch
            {
                return false;
            }
        }

        public static string GetDriveDisplayLabel(string root)
        {
            try
            {
                var letter = root.TrimEnd('\\');
                if (letter.Length < 2)
                    return root;
                var drive = new DriveInfo(letter);
                if (drive.IsReady && !string.IsNullOrWhiteSpace(drive.VolumeLabel))
                    return $"{letter} ({drive.VolumeLabel})";
                return letter;
            }
            catch
            {
                return root.TrimEnd('\\');
            }
        }

        /// <summary>Tous les fichiers du volume (pas seulement les extensions RTP), plafonnés.</summary>
        public static IEnumerable<string> EnumerateAllFiles(string root, int maxFiles)
        {
            if (!Directory.Exists(root))
                yield break;

            var stack = new Stack<string>();
            stack.Push(root);
            var count = 0;

            while (stack.Count > 0 && count < maxFiles)
            {
                var dir = stack.Pop();
                IEnumerable<string> subDirs;
                IEnumerable<string> files;
                try
                {
                    subDirs = Directory.EnumerateDirectories(dir);
                    files = Directory.EnumerateFiles(dir);
                }
                catch
                {
                    continue;
                }

                foreach (var sub in subDirs)
                {
                    try
                    {
                        if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0)
                            continue;
                    }
                    catch { continue; }
                    stack.Push(sub);
                }

                foreach (var file in files)
                {
                    yield return file;
                    count++;
                    if (count >= maxFiles)
                        yield break;
                }
            }
        }

        /// <summary>Fichiers à risque uniquement (même critère que la protection temps réel).</summary>
        public static IEnumerable<string> EnumerateRiskyFiles(string root, int maxFiles) =>
            CollectRiskyFiles(root, maxFiles, CancellationToken.None);

        /// <summary>
        /// Collecte les fichiers à risque par extension (plus rapide qu'un parcours fichier par fichier).
        /// Respecte <paramref name="maxFiles"/>, le jeton d'annulation et un délai max d'énumération.
        /// </summary>
        public static List<string> CollectRiskyFiles(
            string root,
            int maxFiles,
            CancellationToken ct,
            TimeSpan? enumerationTimeout = null,
            IExclusionSettingsAccessor? exclusions = null)
        {
            var list = new List<string>(Math.Min(maxFiles, 256));
            if (!Directory.Exists(root) || maxFiles <= 0)
                return list;

            var deadline = enumerationTimeout.HasValue
                ? DateTime.UtcNow + enumerationTimeout.Value
                : DateTime.MaxValue;
            var excl = (exclusions ?? new DefaultExclusionSettingsAccessor()).Current;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var ext in RiskyFileExtensions.All)
            {
                if (list.Count >= maxFiles || ct.IsCancellationRequested || DateTime.UtcNow >= deadline)
                    break;

                IEnumerable<string> candidates;
                try
                {
                    candidates = Directory.EnumerateFiles(root, "*" + ext, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var file in candidates)
                {
                    if (list.Count >= maxFiles || ct.IsCancellationRequested || DateTime.UtcNow >= deadline)
                        return list;
                    if (ShouldSkipUsbScanPath(file))
                        continue;
                    if (excl.IsFileExcluded(file))
                        continue;
                    if (!seen.Add(file))
                        continue;
                    list.Add(file);
                }
            }

            return list;
        }

        internal static bool ShouldSkipUsbScanPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return true;

            var parts = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            foreach (var part in parts)
            {
                if (part.Equals("$RECYCLE.BIN", StringComparison.OrdinalIgnoreCase)
                    || part.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase)
                    || part.Equals("RECYCLER", StringComparison.OrdinalIgnoreCase)
                    || part.Equals("RECYCLED", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Lecteur amovible classique ou clé USB souvent exposée en <see cref="DriveType.Fixed"/> par Windows.
        /// </summary>
        internal static bool IsEligibleForAutoScan(DriveInfo drive)
        {
            if (!drive.IsReady)
                return false;
            if (drive.DriveType is DriveType.Network or DriveType.CDRom or DriveType.NoRootDirectory)
                return false;
            if (drive.DriveType == DriveType.Removable)
                return true;
            if (IsSystemVolume(drive))
                return false;
            if (drive.DriveType == DriveType.Fixed)
                return IsUsbOrRemovableBackingDisk(drive.Name);
            return false;
        }

        private static bool IsSystemVolume(DriveInfo drive)
        {
            try
            {
                var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
                if (sys.Length >= 3)
                {
                    var sysRoot = sys[..3];
                    if (drive.Name.Equals(sysRoot, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch { /* ignore */ }
            return false;
        }

        private static bool IsUsbOrRemovableBackingDisk(string driveName)
        {
            var deviceId = driveName.TrimEnd('\\');
            if (deviceId.Length < 2)
                return false;

            try
            {
                using var logical = new ManagementObjectSearcher(
                    $"SELECT DriveType FROM Win32_LogicalDisk WHERE DeviceID='{deviceId}'");
                foreach (ManagementObject obj in logical.Get())
                {
                    if (obj["DriveType"] is uint dt && dt == 2)
                        return true;
                }

                using var parts = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{deviceId}'}} WHERE AssocClass=Win32_LogicalDiskToPartition");
                foreach (ManagementObject partition in parts.Get())
                {
                    var partId = partition["DeviceID"]?.ToString();
                    if (string.IsNullOrEmpty(partId))
                        continue;

                    var escaped = partId.Replace(@"\", @"\\");
                    using var disks = new ManagementObjectSearcher(
                        $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{escaped}'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition");
                    foreach (ManagementObject disk in disks.Get())
                    {
                        var iface = disk["InterfaceType"]?.ToString() ?? string.Empty;
                        var media = disk["MediaType"]?.ToString() ?? string.Empty;
                        var pnp = disk["PNPDeviceID"]?.ToString() ?? string.Empty;
                        if (iface.Equals("USB", StringComparison.OrdinalIgnoreCase))
                            return true;
                        if (media.Contains("Removable", StringComparison.OrdinalIgnoreCase))
                            return true;
                        if (pnp.Contains("USB", StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("RemovableDriveDiscovery", $"WMI lecteur {deviceId}", ex);
            }

            return false;
        }

        private static bool TryNormalizeRoot(DriveInfo drive, out string root)
        {
            root = string.Empty;
            try
            {
                if (!IsEligibleForAutoScan(drive))
                    return false;
                root = drive.RootDirectory.FullName;
                if (!root.EndsWith('\\'))
                    root += '\\';
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
