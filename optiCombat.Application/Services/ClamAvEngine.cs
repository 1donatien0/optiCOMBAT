using optiCombat.Localization;
using optiCombat.Models;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace optiCombat.Services
{
    /// <summary>
    /// Moteur de scan ClamAV — enveloppe clamscan.exe en mode processus.
    /// Détecte automatiquement clamav/x64 ou clamav/x86 selon l'architecture.
    /// Supporte : fichier, dossier, scan rapide, scan complet, annulation, progression.
    /// </summary>
    public class ClamAvEngine : IClamAvOrchestratorBackend
    {
        private readonly string _clamavDir;
        private readonly string _clamscanExe;
        private readonly object _parseLock = new();
        private readonly IExclusionSettingsAccessor _exclusions;

        // ── Construction ─────────────────────────────────────────────────────────

        public ClamAvEngine(string? clamavDir = null, IExclusionSettingsAccessor? exclusions = null)
        {
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
            _clamavDir = clamavDir ?? ClamAvDatabasePaths.ResolveClamAvBinDir("clamscan.exe");
            _clamscanExe = Path.Combine(_clamavDir, "clamscan.exe");
        }

        /// <summary>
        /// Répertoire de la base de signatures : priorité dossier 'database' local,
        /// sinon le répertoire ClamAV lui-même (pour les installs système).
        /// </summary>
        public string DatabaseDir
        {
            get
            {
                // Même logique que FreshclamUpdater : dossier inscriptible (souvent
                // %LocalAppData% si l'app est sous Program Files).
                return ClamAvDatabasePaths.ResolveWritableDatabaseDir(_clamavDir);
            }
        }

        // ── Vérification ─────────────────────────────────────────────────────────

        private bool? _cachedInstalled;
        private DateTime _cachedInstalledAtUtc = DateTime.MinValue;
        private static readonly TimeSpan InstallProbeCacheTtl = TimeSpan.FromSeconds(60);

        /// <summary>
        /// Vérifie que clamscan.exe est présent et fonctionnel en exécutant <c>--version</c>.
        /// Résultat mis en cache 60 s pour limiter les lancements de processus à chaque navigation.
        /// </summary>
        public bool IsClamAvInstalled()
        {
            if (_cachedInstalled.HasValue
                && (DateTime.UtcNow - _cachedInstalledAtUtc) < InstallProbeCacheTtl)
                return _cachedInstalled.Value;

            var result = ProbeClamAvInstalled();
            _cachedInstalled = result;
            _cachedInstalledAtUtc = DateTime.UtcNow;
            return result;
        }

        private bool ProbeClamAvInstalled()
        {
            if (!File.Exists(_clamscanExe)) return false;
            try
            {
                using var proc = new Process { StartInfo = BuildStartInfo(_clamscanExe, "--version") };
                proc.Start();
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(3000);
                return output.Contains("ClamAV");
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ClamAvEngine", "IsClamAvInstalled — version ou processus indisponible", ex);
                return false;
            }
        }

        /// <summary>
        /// Retourne la version de ClamAV (première ligne de <c>clamscan --version</c>).
        /// Retourne la clé localisée <c>Clam_NotInstalled</c> ou <c>Clam_VersionError</c>
        /// si l'exécutable est absent ou si une exception survient.
        /// </summary>
        public async Task<string> GetVersionAsync()
        {
            if (!File.Exists(_clamscanExe))
                return LocalizationService.GetString("Clam_NotInstalled");
            try
            {
                var (stdout, _) = await RunProcessAsync(_clamscanExe, "--version");
                return stdout.Trim().Split('\n')[0]; // Première ligne seulement
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ClamAvEngine", "GetVersionAsync", ex);
                return LocalizationService.GetString("Clam_VersionError");
            }
        }

        // ── Méthodes de scan publiques ────────────────────────────────────────────

        /// <summary>
        /// Analyse un fichier unique avec clamscan.
        /// Lève <see cref="FileNotFoundException"/> si le fichier est introuvable.
        /// </summary>
        public Task<ScanResult> ScanFileAsync(
            string filePath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("Fichier introuvable.", filePath);
            return RunScanAsync(ScanType.File, filePath, recursive: false, progress, ct);
        }

        /// <summary>
        /// Analyse récursivement un dossier avec clamscan.
        /// Lève <see cref="DirectoryNotFoundException"/> si le dossier est introuvable.
        /// </summary>
        public Task<ScanResult> ScanFolderAsync(
            string folderPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (!Directory.Exists(folderPath))
                throw new DirectoryNotFoundException($"Dossier introuvable : {folderPath}");
            return RunScanAsync(ScanType.Folder, folderPath, recursive: true, progress, ct);
        }

        /// <summary>
        /// Analyse une liste de fichiers en un seul processus clamscan (--file-list).
        /// Utilisé pour le scan USB rapide (extensions à risque uniquement).
        /// </summary>
        public Task<ScanResult> ScanFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (files.Count == 0)
            {
                var now = DateTime.Now;
                return Task.FromResult(new ScanResult
                {
                    Type = ScanType.Folder,
                    TargetPath = targetPath,
                    StartedAt = now,
                    FinishedAt = now,
                    Status = ScanStatus.Completed,
                    FilesScanned = 0,
                });
            }

            return RunFileListScanAsync(files, targetPath, progress, ct);
        }

        /// <summary>Analyse rapide sur les dossiers système prioritaires (chemins définis dans <see cref="ScanTargets"/>).</summary>
        public async Task<ScanResult> QuickScanAsync(
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            return await RunMultiTargetScanAsync(ScanType.QuickScan, ScanTargets.QuickScanTargets(), progress, ct);
        }

        /// <summary>Analyse complète sur l'ensemble des cibles définies dans <see cref="ScanTargets"/>.</summary>
        public async Task<ScanResult> FullScanAsync(
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            return await RunMultiTargetScanAsync(ScanType.FullScan, ScanTargets.FullScanTargets(), progress, ct);
        }

        // ── Implémentation interne ────────────────────────────────────────────────

        private Task<ScanResult> RunFileListScanAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<ScanProgress>? progress,
            CancellationToken ct) =>
            RunScanCoreAsync(ScanType.Folder, targetPath, progress, ct, args =>
            {
                var listPath = Path.Combine(Path.GetTempPath(), "opticombat_clam_" + Guid.NewGuid().ToString("N") + ".lst");
                var existing = files.Where(File.Exists).ToList();
                if (existing.Count == 0)
                    throw new InvalidOperationException("Aucun fichier accessible dans la liste de scan.");

                File.WriteAllLines(listPath, existing, System.Text.Encoding.UTF8);
                BuildFileListScanArgs(args, listPath);
                return listPath;
            });

        private Task<ScanResult> RunScanAsync(
            ScanType type, string targetPath, bool recursive,
            IProgress<ScanProgress>? progress, CancellationToken ct) =>
            RunScanCoreAsync(type, targetPath, progress, ct, args =>
            {
                BuildScanArgs(args, targetPath, recursive);
                return null;
            });

        private async Task<ScanResult> RunScanCoreAsync(
            ScanType type,
            string targetPath,
            IProgress<ScanProgress>? progress,
            CancellationToken ct,
            Func<Collection<string>, string?> configureArgs)
        {
            ValidateInstallation();

            var result = new ScanResult
            {
                Type = type,
                TargetPath = targetPath,
                StartedAt = DateTime.Now,
                Status = ScanStatus.Running
            };

            progress?.Report(new ScanProgress
            {
                Message = LocalizationService.Format("Scan_Progress_Starting", Path.GetFileName(targetPath)),
                Phase = ScanPhase.Starting,
                CurrentFilePath = targetPath,
            });

            string? tempFileList = null;
            try
            {
                var startInfo = BuildStartInfo(_clamscanExe);
                tempFileList = configureArgs(startInfo.ArgumentList);

                using var proc = new Process { StartInfo = startInfo };

                proc.OutputDataReceived += (_, e) =>
                {
                    if (!string.IsNullOrWhiteSpace(e.Data))
                        ParseScanLine(e.Data, result, progress);
                };
                proc.ErrorDataReceived += (_, e) =>
                {
                    if (!string.IsNullOrWhiteSpace(e.Data))
                        AppLogger.Warn("ClamAV", $"stderr: {e.Data}");
                };

                proc.Start();
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();

                await WaitForProcessAsync(proc, ct);

                try { proc.WaitForExit(); } catch { /* déjà terminé */ }

                result.FinishedAt = DateTime.Now;
                result.Status = ct.IsCancellationRequested
                    ? ScanStatus.Cancelled
                    : ScanStatus.Completed;

                if (ct.IsCancellationRequested && !proc.HasExited)
                    proc.Kill(entireProcessTree: true);
            }
            catch (OperationCanceledException)
            {
                result.Status = ScanStatus.Cancelled;
                result.FinishedAt = DateTime.Now;
            }
            catch (Exception ex)
            {
                result.Status = ScanStatus.Error;
                result.ErrorMessage = ex.Message;
                result.FinishedAt = DateTime.Now;
            }
            finally
            {
                if (!string.IsNullOrEmpty(tempFileList))
                {
                    try { File.Delete(tempFileList); } catch { /* ignore */ }
                }
            }

            progress?.Report(new ScanProgress
            {
                Message = result.SummaryDisplay,
                Phase = ScanPhase.Completed,
                FilesScanned = result.FilesScanned,
                ClamFilesScanned = result.FilesScanned,
                ThreatsFound = result.ThreatsFound
            });

            return result;
        }

        private Task<ScanResult> RunMultiTargetScanAsync(
            ScanType type, List<string> targets,
            IProgress<ScanProgress>? progress, CancellationToken ct) =>
            MultiTargetScanAggregator.AggregateAsync(
                type,
                targets,
                (t, targetProgress, token) => RunScanAsync(type, t, recursive: true, targetProgress, token),
                ct,
                progress,
                skipIfDirectoryMissing: false,
                reportTargetProgress: true);

        // ── Parsing ──────────────────────────────────────────────────────────────

        private void ParseScanLine(
            string line, ScanResult result, IProgress<ScanProgress>? progress)
        {
            lock (_parseLock)
            {
                ParseScanLineCore(line, result, progress);
            }
        }

        private void ParseScanLineCore(
            string line, ScanResult result, IProgress<ScanProgress>? progress) =>
            ClamScanLineParser.ProcessLine(line, result, progress, _exclusions);

        // ── Helpers ──────────────────────────────────────────────────────────────

        /// <summary>
        /// Remplit ArgumentList plutôt que de construire une string.
        /// ArgumentList échappe correctement les espaces, guillemets et
        /// caractères spéciaux (CommandLineToArgvW round-trip), évitant les
        /// pièges d'injection si target contient un caractère exotique.
        /// </summary>
        private void BuildScanArgs(Collection<string> args, string target, bool recursive)
        {
            if (recursive) args.Add("--recursive");

            // Ne pas parcourir le dossier d'optiCombat lors d'un scan parent (ex. C:\).
            if (recursive && !AppInstallPaths.IsUnderInstallRoot(target))
            {
                foreach (var pattern in AppInstallPaths.GetClamScanExcludePatterns())
                    args.Add($"--exclude={pattern}");
            }

            args.Add("--stdout");
            // NB: --no-summary supprimé. Le résumé "Scanned files: N" en fin
            // d'output est notre source de vérité pour le compteur final
            // (cf. ParseStats), à la place de l'incrément ligne par ligne.

            var dbDir = DatabaseDir;
            if (!string.IsNullOrEmpty(dbDir))
                args.Add($"--database={dbDir}"); // ArgumentList gère l'échappement (quoting)

            args.Add(target);
        }

        private void BuildFileListScanArgs(Collection<string> args, string listPath)
        {
            args.Add("--stdout");
            var dbDir = DatabaseDir;
            if (!string.IsNullOrEmpty(dbDir))
                args.Add($"--database={dbDir}");
            args.Add($"--file-list={listPath}");
        }

        /// <summary>
        /// Crée un ProcessStartInfo avec les bons drapeaux I/O. L'appelant doit
        /// remplir <c>ArgumentList</c> via une surcharge dédiée (BuildScanArgs).
        /// On ne définit jamais Arguments en chaîne — pour un échappement sûr.
        /// </summary>
        private static ProcessStartInfo BuildStartInfo(string exe) =>
            new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8
            };

        /// <summary>Surcharge pour les commandes simples (--version) avec un seul argument.</summary>
        private static ProcessStartInfo BuildStartInfo(string exe, string singleArg)
        {
            var psi = BuildStartInfo(exe);
            psi.ArgumentList.Add(singleArg);
            return psi;
        }

        private static async Task WaitForProcessAsync(Process proc, CancellationToken ct)
        {
            var tcs = new TaskCompletionSource<bool>();
            proc.EnableRaisingEvents = true;
            proc.Exited += (_, _) => tcs.TrySetResult(true);

            using (ct.Register(() =>
            {
                try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); }
                catch (Exception ex)
                {
                    AppLogger.Warn("ClamAvEngine", "Annulation — arrêt clamscan", ex);
                }
                tcs.TrySetCanceled();
            }))
            {
                try { await tcs.Task; }
                catch (TaskCanceledException) { }
            }
        }

        private async Task<(string stdout, string stderr)> RunProcessAsync(string exe, string args)
        {
            using var proc = new Process { StartInfo = BuildStartInfo(exe, args) };
            proc.Start();
            var stdout = await proc.StandardOutput.ReadToEndAsync();
            var stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();
            return (stdout, stderr);
        }

        private void ValidateInstallation()
        {
            if (!File.Exists(_clamscanExe))
                throw new InvalidOperationException(
                    $"clamscan.exe introuvable dans : {_clamavDir}\n" +
                    "Placez les binaires ClamAV dans 'clamav/x64/' ou 'clamav/x86/'.");
        }

        // GetQuickScanTargets retiré : la source unique est désormais
        // ScanTargets.QuickScanTargets() (cf. ScanTargets.cs).
    }

}
