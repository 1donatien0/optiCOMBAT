using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services.OptiCombat;
using System.IO;
using System.Linq;

namespace optiCombat.Services
{
    /// <summary>
    /// Coordonne les scans antivirus. Délègue au cœur Rust optiCombat (opticombat.dll)
    /// lorsque la bibliothèque native est déployée ; sinon lance ClamAV et YARA en parallèle
    /// (<see cref="Task.WhenAll"/>) puis fusionne leurs résultats.
    /// </summary>
    /// <remarks>
    /// YaraParallelism retiré : depuis le passage en single-process (un seul
    /// yara64.exe avec --recursive), YARA gère lui-même son parallélisme
    /// interne et l'orchestration n'a plus à le faire.
    /// </remarks>
    public class ScanOrchestrator
    {
        private readonly IClamAvOrchestratorBackend _clamAv;
        private readonly IYaraOrchestratorBackend _yara;
        private readonly IUserPreferencesAccessor _prefs;
        private readonly IExclusionSettingsAccessor _exclusions;
        private readonly OptiCombatScanEngine? _optiCombat;

        // ── État ─────────────────────────────────────────────────────────────────

        /// <summary><c>true</c> si le cœur Rust optiCombat (opticombat.dll) est actif.</summary>
        public bool IsOptiCombatAvailable => _optiCombat?.IsAvailable == true;

        /// <summary><c>true</c> si clamscan.exe est détecté et opérationnel.</summary>
        public bool IsClamAvAvailable => IsOptiCombatAvailable || _clamAv.IsClamAvInstalled();

        /// <summary><c>true</c> si le moteur YARA est disponible et possède des règles compilées.</summary>
        public bool IsYaraAvailable => _yara.IsAvailable;

        /// <summary>Nombre de règles YARA actuellement chargées.</summary>
        public int YaraRulesCount => _yara.RulesCount;

        // ── Construction ─────────────────────────────────────────────────────────

        /// <summary>
        /// Crée un orchestrateur avec les moteurs fournis (ou de nouveaux si <c>null</c>).
        /// </summary>
        public ScanOrchestrator(ClamAvEngine? clamAv = null, YaraEngine? yara = null)
            : this((IClamAvOrchestratorBackend?)clamAv, (IYaraOrchestratorBackend?)yara)
        {
        }

        internal ScanOrchestrator(
            IClamAvOrchestratorBackend? clamAv = null,
            IYaraOrchestratorBackend? yara = null,
            IUserPreferencesAccessor? preferences = null,
            IExclusionSettingsAccessor? exclusions = null,
            OptiCombatScanEngine? optiCombat = null)
        {
            _clamAv = clamAv ?? new ClamAvEngine();
            _yara = yara ?? new YaraEngine();
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
            _optiCombat = optiCombat;
        }

        // ── API publique ─────────────────────────────────────────────────────────

        /// <summary>
        /// Analyse un fichier unique avec ClamAV et YARA en parallèle.
        /// Retourne immédiatement un résultat vide si le fichier est dans les exclusions.
        /// </summary>
        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            if (_exclusions.Current.IsFileExcluded(filePath))
            {
                return Task.FromResult(new ScanResult
                {
                    Type = ScanType.File,
                    TargetPath = filePath,
                    StartedAt = DateTime.Now,
                    FinishedAt = DateTime.Now,
                    Status = ScanStatus.Completed,
                    FilesSkipped = 1
                });
            }
            if (IsOptiCombatAvailable)
                return _optiCombat!.ScanFileAsync(filePath, progress, ct);
            return RunPipelineAsync(ScanType.File, filePath, false, progress, ct);
        }

        /// <summary>Analyse récursivement un dossier avec ClamAV et YARA en parallèle.</summary>
        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            if (IsOptiCombatAvailable)
                return _optiCombat!.ScanFolderAsync(folderPath, progress, ct);
            return RunPipelineAsync(ScanType.Folder, folderPath, true, progress, ct, skipYaraFileCount: false);
        }

        /// <summary>Analyse récursive sans pré-dénombrement YARA (scan USB complet en arrière-plan).</summary>
        internal Task<ScanResult> ScanFolderBackgroundAsync(string folderPath, ScanType type, CancellationToken ct = default)
        {
            if (IsOptiCombatAvailable)
                return _optiCombat!.ScanFolderAsync(folderPath, progress: null, ct);
            return RunPipelineAsync(type, folderPath, true, progress: null, ct, skipYaraFileCount: true);
        }

        /// <summary>Analyse une liste de fichiers (ClamAV --file-list + YARA par lots).</summary>
        public Task<ScanResult> ScanFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            ScanType type = ScanType.Folder,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default,
            bool scanEnginesSequentially = false)
        {
            var filtered = files
                .Where(f => !_exclusions.Current.IsFileExcluded(f))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (filtered.Count == 0)
            {
                var now = DateTime.Now;
                return Task.FromResult(new ScanResult
                {
                    Type = type,
                    TargetPath = targetPath,
                    StartedAt = now,
                    FinishedAt = now,
                    Status = ScanStatus.Completed,
                    FilesScanned = 0,
                });
            }

            if (IsOptiCombatAvailable)
                return RunNativeFileListAsync(type, targetPath, filtered, progress, ct);
            return RunFileListPipelineAsync(type, targetPath, filtered, progress, ct, scanEnginesSequentially);
        }

        /// <summary>Analyse rapide sur les dossiers système prioritaires (voir <see cref="ScanTargets"/>).</summary>
        public Task<ScanResult> QuickScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            if (IsOptiCombatAvailable)
                return _optiCombat!.QuickScanAsync(progress, ct);
            return RunMultiTargetPipelineAsync(ScanType.QuickScan, ScanTargets.QuickScanTargets(), progress, ct);
        }

        /// <summary>Analyse complète sur l'ensemble des cibles définies dans <see cref="ScanTargets"/>.</summary>
        public Task<ScanResult> FullScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            if (IsOptiCombatAvailable)
                return _optiCombat!.FullScanAsync(progress, ct);
            return RunMultiTargetPipelineAsync(
                ScanType.FullScan,
                ScanTargets.FullScanTargets(_prefs.Current.IncludeRemovableInFullScan),
                progress,
                ct);
        }

        // ── Pipeline interne ─────────────────────────────────────────────────────

        /// <summary>Scan fichier par fichier via le cœur Rust (mode liste rapide).</summary>
        private async Task<ScanResult> RunNativeFileListAsync(
            ScanType type,
            string targetPath,
            IReadOnlyList<string> files,
            IProgress<ScanProgress>? progress,
            CancellationToken ct)
        {
            var aggregate = new ScanResult
            {
                Type = type,
                TargetPath = targetPath,
                StartedAt = DateTime.Now,
                Status = ScanStatus.Completed,
            };

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var one = await _optiCombat!.ScanFileAsync(file, progress, ct).ConfigureAwait(false);
                aggregate.FilesScanned += one.FilesScanned;
                aggregate.Threats.AddRange(one.Threats);
            }

            aggregate.FinishedAt = DateTime.Now;
            return aggregate;
        }

        /// <summary>
        /// Exécute ClamAV et YARA en parallèle sur une cible unique, puis fusionne les résultats.
        /// Les dossiers appartenant au répertoire d'installation sont automatiquement exclus.
        /// </summary>
        private async Task<ScanResult> RunPipelineAsync(
            ScanType type, string target, bool recursive, IProgress<ScanProgress>? progress, CancellationToken ct,
            bool skipYaraFileCount = false)
        {
            if (recursive && AppInstallPaths.IsUnderInstallRoot(target))
            {
                var now = DateTime.Now;
                return new ScanResult
                {
                    Type = type,
                    TargetPath = target,
                    StartedAt = now,
                    FinishedAt = now,
                    Status = ScanStatus.Completed,
                    FilesSkipped = 1,
                };
            }

            var engineProgress = new ScanProgressRelay().ToParent(progress);

            Task<ScanResult> clamTask = recursive
                ? _clamAv.ScanFolderAsync(target, engineProgress, ct)
                : _clamAv.ScanFileAsync(target, engineProgress, ct);

            Task<ScanResult> yaraTask = recursive
                ? RunYaraOnFolderAsync(target, engineProgress, ct, skipYaraFileCount)
                : RunYaraOnFileAsync(target, engineProgress, ct);

            await Task.WhenAll(clamTask, yaraTask);

            return ScanThreatMerger.Merge(type, target, await clamTask, await yaraTask, _exclusions);
        }

        private async Task<ScanResult> RunFileListPipelineAsync(
            ScanType type,
            string targetPath,
            IReadOnlyList<string> files,
            IProgress<ScanProgress>? progress,
            CancellationToken ct,
            bool scanEnginesSequentially)
        {
            var engineProgress = new ScanProgressRelay().ToParent(progress);

            if (scanEnginesSequentially)
            {
                var clamResult = await _clamAv.ScanFileListAsync(files, targetPath, engineProgress, ct)
                    .ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                var yaraResult = await RunYaraOnFileListAsync(files, targetPath, engineProgress, ct)
                    .ConfigureAwait(false);
                return ScanThreatMerger.Merge(type, targetPath, clamResult, yaraResult, _exclusions);
            }

            var clamTask = _clamAv.ScanFileListAsync(files, targetPath, engineProgress, ct);
            var yaraTask = RunYaraOnFileListAsync(files, targetPath, engineProgress, ct);
            await Task.WhenAll(clamTask, yaraTask).ConfigureAwait(false);
            return ScanThreatMerger.Merge(type, targetPath, await clamTask, await yaraTask, _exclusions);
        }

        /// <summary>Délègue l'agrégation multi-cibles à <see cref="MultiTargetScanAggregator"/>.</summary>
        private Task<ScanResult> RunMultiTargetPipelineAsync(ScanType type, List<string> targets, IProgress<ScanProgress>? progress, CancellationToken ct) =>
            MultiTargetScanAggregator.AggregateAsync(
                type,
                targets,
                (t, targetProgress, token) => RunPipelineAsync(type, t, true, targetProgress, token),
                ct,
                progress,
                skipIfDirectoryMissing: true,
                reportTargetProgress: true);

        // ── YARA helpers ─────────────────────────────────────────────────────────

        /// <summary>Exécute YARA sur un fichier unique et convertit les matchs en <see cref="ThreatInfo"/>.</summary>
        private async Task<ScanResult> RunYaraOnFileAsync(string filePath, IProgress<ScanProgress>? progress, CancellationToken ct)
        {
            var result = new ScanResult
            {
                Type = ScanType.File,
                TargetPath = filePath,
                StartedAt = DateTime.Now
            };

            if (!_yara.IsAvailable)
            {
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
                return result;
            }

            if (_exclusions.Current.IsFileExcluded(filePath))
            {
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
                result.FilesSkipped = 1;
                return result;
            }

            try
            {
                var allMatches = await _yara.ScanFileAsync(filePath, ct);
                var excl = _exclusions.Current;
                var matches = allMatches
                    .FindAll(m => !excl.IsFileExcluded(m.FilePath) && !excl.IsRuleExcluded(m.RuleName));

                long fileSize = -1;
                try { fileSize = new FileInfo(filePath).Length; }
                catch { /* taille indisponible — non bloquant */ }

                foreach (var m in matches)
                {
                    var threat = new ThreatInfo
                    {
                        FilePath = filePath,
                        VirusName = m.RuleName,
                        DetectedAt = DateTime.Now,
                        Status = ThreatStatus.Detected,
                        FileSize = fileSize,
                        DetectedBy = "YARA"
                    };
                    result.Threats.Add(threat);

                    progress?.Report(new ScanProgress
                    {
                        Message = $"{m.RuleName} — {filePath}",
                        Phase = ScanPhase.ThreatFound,
                        ThreatInfo = threat,
                        ThreatsFound = result.ThreatsFound,
                        CurrentFilePath = filePath,
                    });
                }

                result.FilesScanned = 1;
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
            }
            catch (OperationCanceledException)
            {
                result.Status = ScanStatus.Cancelled;
                result.FinishedAt = DateTime.Now;
            }
            catch (Exception ex)
            {
                // CORRECTION : catch vide silencieux → impossible de diagnostiquer
                // un crash YARA (binaire manquant, règles corrompues, etc.).
                AppLogger.Warn("ScanOrchestrator", $"RunYaraOnFileAsync ({filePath})", ex);
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
            }

            return result;
        }

        private async Task<ScanResult> RunYaraOnFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<ScanProgress>? progress,
            CancellationToken ct)
        {
            var result = new ScanResult
            {
                Type = ScanType.Folder,
                TargetPath = targetPath,
                StartedAt = DateTime.Now,
            };

            if (!_yara.IsAvailable)
            {
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
                return result;
            }

            try
            {
                progress?.Report(new ScanProgress
                {
                    Message = LocalizationService.Format("Scan_Yara_StartingWithCount", Path.GetFileName(targetPath), files.Count),
                    Phase = ScanPhase.Starting,
                    TotalFiles = files.Count,
                    CurrentFilePath = targetPath,
                });

                int scanned = 0;
                var yaraProgress = new Progress<string>(_ =>
                {
                    var n = System.Threading.Interlocked.Increment(ref scanned);
                    progress?.Report(new ScanProgress
                    {
                        Phase = ScanPhase.Scanning,
                        TotalFiles = files.Count,
                        FilesScanned = Math.Min(n, files.Count),
                        YaraFilesScanned = Math.Min(n, files.Count),
                        CurrentFilePath = targetPath,
                    });
                });

                var allMatches = await _yara.ScanFilesAsync(files, yaraProgress, ct).ConfigureAwait(false);
                var exclusions = _exclusions.Current;
                var filteredMatches = allMatches
                    .Where(m => !exclusions.IsFileExcluded(m.FilePath))
                    .Where(m => !exclusions.IsRuleExcluded(m.RuleName))
                    .ToList();

                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var m in filteredMatches)
                {
                    var key = $"{m.FilePath}|{m.RuleName}";
                    if (!seen.Add(key)) continue;

                    long fileSize = -1;
                    try { fileSize = new FileInfo(m.FilePath).Length; }
                    catch { /* ignore */ }

                    var threat = new ThreatInfo
                    {
                        FilePath = m.FilePath,
                        VirusName = m.RuleName,
                        DetectedAt = DateTime.Now,
                        Status = ThreatStatus.Detected,
                        FileSize = fileSize,
                        DetectedBy = "YARA"
                    };
                    result.Threats.Add(threat);

                    progress?.Report(new ScanProgress
                    {
                        Message = $"{m.RuleName} — {m.FilePath}",
                        Phase = ScanPhase.ThreatFound,
                        ThreatsFound = result.Threats.Count,
                        ThreatInfo = threat,
                        CurrentFilePath = m.FilePath,
                        YaraMatchesFound = result.Threats.Count,
                    });
                }

                result.FilesScanned = files.Count;
                result.Status = ct.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;

                progress?.Report(new ScanProgress
                {
                    Message = $"{result.FilesScanned:N0} fichiers analysés.",
                    Phase = ScanPhase.Completed,
                    FilesScanned = result.FilesScanned,
                    YaraFilesScanned = result.FilesScanned,
                    TotalFiles = files.Count,
                    ThreatsFound = result.Threats.Count,
                });
            }
            catch (OperationCanceledException)
            {
                result.Status = ScanStatus.Cancelled;
                result.FinishedAt = DateTime.Now;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScanOrchestrator", $"RunYaraOnFileListAsync ({targetPath})", ex);
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
            }

            return result;
        }

        /// <summary>Exécute YARA en mode récursif (single-process) sur un dossier et convertit les matchs en <see cref="ThreatInfo"/>.</summary>
        private async Task<ScanResult> RunYaraOnFolderAsync(
            string folderPath, IProgress<ScanProgress>? progress, CancellationToken ct, bool skipFileCount = false)
        {
            var result = new ScanResult
            {
                Type = ScanType.Folder,
                TargetPath = folderPath,
                StartedAt = DateTime.Now
            };

            if (!_yara.IsAvailable)
            {
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
                return result;
            }

            try
            {
                const int CountCap = 100_000;
                const int UnknownTotalFiles = 0;
                int total = skipFileCount ? UnknownTotalFiles : 0;
                if (!skipFileCount)
                {
                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(folderPath, "*.*", SearchOption.AllDirectories))
                        {
                            if (ct.IsCancellationRequested) break;
                            if (_exclusions.Current.IsFileExcluded(file))
                                continue;
                            if (++total >= CountCap) { total = UnknownTotalFiles; break; }
                        }
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("ScanOrchestrator", $"Énumération {folderPath}", ex);
                    }
                }

                progress?.Report(new ScanProgress
                {
                    Message = total > 0
                        ? LocalizationService.Format("Scan_Yara_StartingWithCount", Path.GetFileName(folderPath), total)
                        : LocalizationService.Format("Scan_Yara_Starting", Path.GetFileName(folderPath)),
                    Phase = ScanPhase.Starting,
                    TotalFiles = total,
                    CurrentFilePath = folderPath,
                });

                // Single-process : un seul yara64.exe avec --recursive.
                // YARA émet un message tous les ~20 lignes stdout (matches), pas par fichier.
                // Si total > 0, on répartit les N messages reçus uniformément sur [0, total]
                // pour une barre de progression fidèle au nombre de fichiers.
                // Si total = 0 (inconnu / >100k), on laisse le compteur libre (ProgressBar indéterminée).
                int filesYara = 0;
                int msgCount = 0;
                var yaraProgress = new Progress<string>(msg =>
                {
                    var msgs = System.Threading.Interlocked.Increment(ref msgCount);
                    int n;
                    if (total > 0)
                    {
                        // YaraEngine émet ~1 message par YaraProgressInterval (~20) lignes traitées.
                        // On interpole : chaque message ≈ YaraProgressInterval fichiers parcourus.
                        n = Math.Min(msgs * YaraEngine.YaraProgressInterval, total);
                        System.Threading.Interlocked.Exchange(ref filesYara, n);
                    }
                    else
                    {
                        n = System.Threading.Interlocked.Increment(ref filesYara);
                    }
                    progress?.Report(new ScanProgress
                    {
                        Message = msg,
                        Phase = ScanPhase.Scanning,
                        TotalFiles = total,
                        FilesScanned = n,
                        YaraFilesScanned = n,
                        CurrentFilePath = folderPath,
                    });
                });

                var allMatches = await _yara.ScanFolderAsync(folderPath, yaraProgress, ct);

                // Filtre exclusions (dossiers + règles ignorées).
                var exclusions = _exclusions.Current;
                var filteredMatches = allMatches
                    .Where(m => !exclusions.IsFileExcluded(m.FilePath))
                    .Where(m => !exclusions.IsRuleExcluded(m.RuleName))
                    .ToList();

                // Conversion en ThreatInfo : un match = une menace, dédupliquée
                // par (chemin + règle). yara peut émettre la même règle plusieurs
                // fois pour un même fichier si plusieurs strings matchent.
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var m in filteredMatches)
                {
                    var key = $"{m.FilePath}|{m.RuleName}";
                    if (!seen.Add(key)) continue;

                    long fileSize = -1;
                    try { fileSize = new FileInfo(m.FilePath).Length; }
                    catch { /* taille indisponible */ }

                    var threat = new ThreatInfo
                    {
                        FilePath = m.FilePath,
                        VirusName = m.RuleName,
                        DetectedAt = DateTime.Now,
                        Status = ThreatStatus.Detected,
                        FileSize = fileSize,
                        DetectedBy = "YARA"
                    };
                    result.Threats.Add(threat);

                    progress?.Report(new ScanProgress
                    {
                        Message = $"{m.RuleName} — {m.FilePath}",
                        Phase = ScanPhase.ThreatFound,
                        ThreatsFound = result.Threats.Count,
                        ThreatInfo = threat,
                        CurrentFilePath = m.FilePath,
                        YaraMatchesFound = result.Threats.Count,
                    });
                }

                result.FilesScanned = total > 0 ? total : Math.Max(filesYara, 1);
                result.Status = ct.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;

                progress?.Report(new ScanProgress
                {
                    Message = $"{result.FilesScanned:N0} fichiers analysés.",
                    Phase = ScanPhase.Completed,
                    FilesScanned = result.FilesScanned,
                    YaraFilesScanned = result.FilesScanned,
                    TotalFiles = total,
                    ThreatsFound = result.Threats.Count,
                });
            }
            catch (OperationCanceledException)
            {
                result.Status = ScanStatus.Cancelled;
                result.FinishedAt = DateTime.Now;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScanOrchestrator", $"RunYaraOnFolderAsync ({folderPath})", ex);
                result.Status = ScanStatus.Completed;
                result.FinishedAt = DateTime.Now;
            }

            return result;
        }

        // GetQuickScanTargets retiré : la source unique est désormais
        // ScanTargets.QuickScanTargets() (cf. ScanTargets.cs).
    }
}