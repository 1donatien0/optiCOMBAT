using System.Collections.Concurrent;
using System.IO;

namespace optiCombat.Services
{
    /// <summary>
    /// Protection en temps réel via FileSystemWatcher.
    /// Surveille les dossiers critiques et analyse immédiatement les nouveaux/modifiés fichiers.
    /// </summary>
    public class RealTimeProtection : IDisposable
    {
        private readonly ProtectionScanGateway _scanGateway;
        private readonly QuarantineManager _quarantineManager;
        private readonly NotificationService _notifications;
        private readonly ConcurrentDictionary<string, DateTime> _recentlyScanned;
        private readonly List<FileSystemWatcher> _watchers;
        private readonly SemaphoreSlim _scanSemaphore;
        // Timer dédié au nettoyage périodique du cache, même si le watcher ne reçoit pas d'événements.
        private System.Threading.Timer? _cacheCleanupTimer;
        private bool _isEnabled;
        private bool _disposed;
        private int _suspendCount;

        // Délai d'attente après création/modification (éviter les scans sur écriture partielle)
        private static readonly TimeSpan StabilizationDelay = TimeSpan.FromMilliseconds(500);

        public event EventHandler<Models.ThreatInfo>? ThreatDetected;
        public bool IsEnabled => _isEnabled;

        /// <summary>Ignore les événements watcher pendant un scan manuel (compteur réentrant).</summary>
        public void Suspend() => Interlocked.Increment(ref _suspendCount);

        /// <summary>Réactive la surveillance après <see cref="Suspend"/>.</summary>
        public void Resume()
        {
            if (Interlocked.Decrement(ref _suspendCount) < 0)
                Interlocked.Exchange(ref _suspendCount, 0);
        }

        private bool IsSuspended => Volatile.Read(ref _suspendCount) > 0;

        /// <summary>Vrai pendant un scan manuel ou USB (surveillance processus en pause).</summary>
        public bool IsPaused => IsSuspended;

        private readonly IUserPreferencesAccessor _prefs;
        private readonly IExclusionSettingsAccessor _exclusions;

        public RealTimeProtection(
            ProtectionScanGateway scanGateway,
            QuarantineManager quarantineManager,
            NotificationService notifications,
            IUserPreferencesAccessor? preferences = null,
            IExclusionSettingsAccessor? exclusions = null)
        {
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
            _scanGateway = scanGateway;
            _quarantineManager = quarantineManager;
            _notifications = notifications;
            _recentlyScanned = new ConcurrentDictionary<string, DateTime>();
            _watchers = new List<FileSystemWatcher>();
            _scanSemaphore = new SemaphoreSlim(3); // Max 3 scans simultanés
        }

        /// <summary>
        /// Démarre la surveillance en temps réel sur les dossiers critiques, le bureau et les téléchargements.
        /// Sans effet si la protection est déjà active.
        /// </summary>
        public void Start()
        {
            if (_isEnabled) return;

            foreach (var folder in RealTimeWatchPaths.GetWatchFolders(_exclusions))
                AddWatcher(folder);

            // Cleanup périodique du cache : toutes les 5 min, on supprime les
            // entrées de plus de 5 min. Indépendant de l'arrivée d'événements,
            // ce qui évite la croissance silencieuse du cache si la machine reste inactive.
            _cacheCleanupTimer = new System.Threading.Timer(
                _ => { try { CleanupRecentCache(); } catch { /* swallow */ } },
                state: null,
                dueTime: TimeSpan.FromMinutes(5),
                period: TimeSpan.FromMinutes(5));

            _isEnabled = true;
            WriteLog("Protection temps réel activée");
        }

        /// <summary>
        /// Arrête la surveillance en temps réel et libère tous les <see cref="FileSystemWatcher"/> actifs.
        /// Sans effet si la protection est déjà arrêtée.
        /// </summary>
        public void Stop()
        {
            if (!_isEnabled) return;

            _cacheCleanupTimer?.Dispose();
            _cacheCleanupTimer = null;

            foreach (var watcher in _watchers)
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            _watchers.Clear();
            _recentlyScanned.Clear();

            _isEnabled = false;
            WriteLog("Protection temps réel désactivée");
        }

        private void AddWatcher(string path)
        {
            if (_exclusions.Current.IsFolderExcluded(path))
                return;

            try
            {
                var watcher = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                    Filter = "*.*",
                    // Buffer 64 KB (vs 8 KB par défaut) : sur les machines avec
                    // beaucoup d'écritures (build IDE, navigateurs, antivirus tiers),
                    // évite la perte d'événements liée à un overflow buffer kernel.
                    InternalBufferSize = 64 * 1024,
                };

                watcher.Created += SurFichierModifie;
                watcher.Changed += SurFichierModifie;
                watcher.Renamed += SurFichierRenomme;
                watcher.Error += SurErreurWatcher;

                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                WriteLog($"Impossible de surveiller {path} : {ex.Message}");
            }
        }

        // CRITIQUE : ces deux handlers sont async void (imposé par la signature
        // FileSystemEventHandler). Toute exception non gérée crashe le process.
        // Un fichier crafté qui déclenche une exception suffirait à désactiver la
        // protection temps réel. On enrobe donc TOUT le corps en try/catch global.
        /// <summary>
        /// Réagit à la création/modification d'un fichier et déclenche un scan si nécessaire.
        /// </summary>
        /// <remarks>
        /// Le corps est en <c>try/catch</c> global : un crash dans un handler <c>async void</c>
        /// mettrait fin à la protection temps réel.
        /// On dé-duplique et on attend un bref délai de stabilisation pour éviter de scanner
        /// un fichier encore en cours d'écriture.
        /// </remarks>
        private async void SurFichierModifie(object sender, FileSystemEventArgs e)
        {
            try
            {
                // Ignorer les dossiers
                if (Directory.Exists(e.FullPath)) return;

                if (IsSuspended) return;

                if (!RiskyFileExtensions.IsRisky(e.FullPath)) return;

                // Dédup immédiate (avant le délai de stabilisation) pour éviter deux
                // événements concurrents sur le même fichier avant l'écriture du cache.
                var utcNow = DateTime.UtcNow;
                if (!_recentlyScanned.TryAdd(e.FullPath, utcNow))
                {
                    if (_recentlyScanned.TryGetValue(e.FullPath, out var t) &&
                        (utcNow - t) < TimeSpan.FromSeconds(30))
                        return;
                    _recentlyScanned[e.FullPath] = utcNow;
                }

                await Task.Delay(StabilizationDelay);

                if (!File.Exists(e.FullPath)) return;

                CleanupRecentCache();

                await _scanSemaphore.WaitAsync();
                try
                {
                    await ScanFileAsync(e.FullPath, e.ChangeType);
                }
                finally
                {
                    _scanSemaphore.Release();
                }

                _recentlyScanned[e.FullPath] = DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                // Logger sans propager — protection temps réel ne doit JAMAIS crasher.
                WriteLog($"[RTP] SurFichierModifie exception ({e.FullPath}): {ex.Message}");
            }
        }

        /// <summary>
        /// Réagit à un renommage de fichier (scan sur le nouveau chemin si applicable).
        /// </summary>
        /// <remarks>
        /// Même stratégie que SurFichierModifie : déduplication + stabilisation + protection
        /// contre les exceptions (handler async void).
        /// </remarks>
        private async void SurFichierRenomme(object sender, RenamedEventArgs e)
        {
            try
            {
                if (Directory.Exists(e.FullPath)) return;

                if (IsSuspended) return;

                if (!RiskyFileExtensions.IsRisky(e.FullPath)) return;

                var utcNow = DateTime.UtcNow;
                if (!_recentlyScanned.TryAdd(e.FullPath, utcNow))
                {
                    if (_recentlyScanned.TryGetValue(e.FullPath, out var t) &&
                        (utcNow - t) < TimeSpan.FromSeconds(30))
                        return;
                    _recentlyScanned[e.FullPath] = utcNow;
                }

                await Task.Delay(StabilizationDelay);
                if (!File.Exists(e.FullPath)) return;

                CleanupRecentCache();

                await _scanSemaphore.WaitAsync();
                try
                {
                    await ScanFileAsync(e.FullPath, WatcherChangeTypes.Renamed);
                }
                finally
                {
                    _scanSemaphore.Release();
                }

                _recentlyScanned[e.FullPath] = DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                WriteLog($"[RTP] SurFichierRenomme exception ({e.FullPath}): {ex.Message}");
            }
        }

        /// <summary>
        /// Logue les erreurs du <see cref="FileSystemWatcher"/>.
        /// </summary>
        /// <remarks>
        /// Le watcher peut générer des erreurs non critiques ; on se limite à journaliser
        /// pour conserver la stabilité générale.
        /// </remarks>
        private void SurErreurWatcher(object sender, ErrorEventArgs e)
        {
            WriteLog($"Erreur FileSystemWatcher : {e.GetException()?.Message}");
        }

        private async Task ScanFileAsync(string filePath, WatcherChangeTypes changeType)
        {
            try
            {
                // Ne pas rescanner un fichier individuellement exclu
                if (_exclusions.Current.IsFileExcluded(filePath))
                {
                    WriteLog($"[RTP] Fichier exclu, ignoré : {filePath}");
                    return;
                }

                var result = await _scanGateway.ScanFileAsync(filePath);

                if (result.ThreatsFound > 0)
                {
                    foreach (var threat in result.Threats)
                    {
                        // Notification toast
                        _notifications.ShowThreatDetected(threat);

                        if (_exclusions.Current.AutoQuarantineEnabled)
                        {
                            if (_prefs.Current.BackupBeforeQuarantine)
                                ThreatRemediationService.TryCreateSafetyCopy(threat);

                            // Quarantaine automatique activée par l'utilisateur
                            if (_quarantineManager.Quarantine(threat))
                            {
                                WriteLog($"[RTP] Quarantaine auto : {threat.FileName} ({threat.VirusName})");
                                _notifications.ShowQuarantined(threat);
                            }
                        }

                        // Notifier l'UI dans tous les cas — elle gère l'action si pas d'auto-quarantaine
                        ThreatDetected?.Invoke(this, threat);
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"[RTP] Erreur scan {filePath} : {ex.Message}");
            }
        }

        private void CleanupRecentCache()
        {
            var threshold = DateTime.UtcNow.AddMinutes(-5);
            foreach (var kvp in _recentlyScanned)
            {
                if (kvp.Value < threshold)
                    _recentlyScanned.TryRemove(kvp.Key, out _);
            }
        }

        private static void WriteLog(string message)
        {
            // Niveau Info par défaut. Les exceptions sérieuses sont loggées en
            // Error directement par les handlers async void.
            AppLogger.Info("RealTimeProtection", message);
        }

        /// <summary>Arrête la protection et libère le sémaphore et le timer de nettoyage.</summary>
        public void Dispose()
        {
            if (_disposed) return;
            Stop();
            _scanSemaphore.Dispose();
            _disposed = true;
        }
    }
}
