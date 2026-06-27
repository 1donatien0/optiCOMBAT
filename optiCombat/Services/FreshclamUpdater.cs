using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using optiCombat.Localization;
using optiCombat.Strings;

namespace optiCombat.Services
{
    /// <summary>
    /// Lance freshclam.exe pour mettre à jour la base de signatures ClamAV.
    /// Découverte automatique des chemins selon l'architecture (x64/x86) et
    /// l'installation système.
    /// </summary>
    public class FreshclamUpdater : ISignatureUpdateCanceller, ISignatureAutoUpdateTarget
    {
        // ── Constantes ────────────────────────────────────────────────────────────

        /// <summary>Délai max d'une mise à jour avant kill automatique.</summary>
        private static readonly TimeSpan UpdateTimeout = TimeSpan.FromMinutes(5);

        /// <summary>Âge à partir duquel un verrou freshclam est considéré orphelin.</summary>
        private static readonly TimeSpan StaleLockAge = TimeSpan.FromMinutes(10);

        // ── Chemins ───────────────────────────────────────────────────────────────

        private readonly string _freshclamExe;
        /// <summary>Répertoire inscriptible pour daily/main et les tmp freshclam.</summary>
        private readonly string _databaseDir;
        private readonly string _freshclamConf;
        private readonly string _certsDir;
        /// <summary>Répertoire contenant <c>clamav.crt</c> pour freshclam 1.5+ (souvent LocalAppData si PF en lecture seule).</summary>
        private string _effectiveCvdCertsDir;

        private static readonly Uri ClamAvRootCertUri =
            new(OpticombatStrings.Urls.ClamAvRootCertRaw, UriKind.Absolute);

        private System.Threading.Timer? _autoUpdateTimer;
        private CancellationTokenSource? _currentCts;
        private readonly object _ctsLock = new();

        // ── Événements et état ────────────────────────────────────────────────────

        /// <summary>Déclenché à chaque ligne de sortie de freshclam.</summary>
        public event EventHandler<string>? UpdateOutput;

        /// <summary>Déclenché à la fin de la mise à jour (succès ou échec).</summary>
        public event EventHandler<UpdateResult>? UpdateCompleted;

        public DateTime? LastUpdateTime { get; private set; }
        public string DatabaseVersion { get; private set; }
        public bool IsUpdating { get; private set; }

        // ── Constructeur ──────────────────────────────────────────────────────────

        public FreshclamUpdater(string? clamavDir = null)
        {
            var dir = clamavDir ?? ClamAvDatabasePaths.ResolveClamAvBinDir("freshclam.exe");

            _freshclamExe = Path.Combine(dir, "freshclam.exe");
            _databaseDir = ClamAvDatabasePaths.ResolveWritableDatabaseDir(dir);
            _freshclamConf = Path.Combine(dir, "freshclam.conf");
            _certsDir = Path.Combine(dir, "certs");
            _effectiveCvdCertsDir = _certsDir;
            DatabaseVersion = VersionDisplayHelper.UnknownLabel;
        }

        // ── Mise à jour automatique ───────────────────────────────────────────────

        /// <summary>Active les mises à jour automatiques (toutes les 24 h par défaut).</summary>
        public void EnableAutoUpdate(TimeSpan? interval = null)
        {
            var period = interval ?? TimeSpan.FromHours(24);
            _autoUpdateTimer?.Dispose();
            // TimerCallback est void — on ne peut pas utiliser async directement.
            // Task.Run avec catch complet garantit qu'aucune exception ne remonte
            // sur le ThreadPool et ne crashe le processus silencieusement.
            _autoUpdateTimer = new System.Threading.Timer(
                _ =>
                {
                    if (IsUpdating) return;
                    _ = Task.Run(async () =>
                    {
                        try { await UpdateAsync().ConfigureAwait(false); }
                        catch (OperationCanceledException) { /* annulé normalement */ }
                        catch (Exception ex)
                        {
                            AppLogger.Warn("FreshclamUpdater", "Auto-update", ex);
                        }
                    });
                },
                null, period, period);
        }

        /// <summary>Désactive les mises à jour automatiques.</summary>
        public void DisableAutoUpdate()
        {
            _autoUpdateTimer?.Dispose();
            _autoUpdateTimer = null;
        }

        /// <summary>Indique si le timer de mise à jour périodique est actif.</summary>
        public bool IsAutoUpdateEnabled => _autoUpdateTimer != null;

        // ── Annulation ─────────────────────────────────────────────────────────────

        /// <summary>
        /// Annule la mise à jour en cours (tue freshclam.exe).
        /// Sans effet si aucune mise à jour n'est active.
        /// </summary>
        public void CancelUpdate()
        {
            lock (_ctsLock)
            {
                try { _currentCts?.Cancel(); }
                catch (ObjectDisposedException) { /* déjà disposé */ }
            }
        }

        // ── Mise à jour manuelle ──────────────────────────────────────────────────

        /// <summary>
        /// Lance freshclam.exe et retourne le résultat.
        /// Si freshclam.exe est absent, retourne un succès silencieux (signatures locales).
        /// </summary>
        public async Task<UpdateResult> UpdateAsync(CancellationToken ct = default)
        {
            if (IsUpdating)
                return new UpdateResult { Success = false, Message = LocalizationService.GetString("Freshclam_AlreadyUpdating") };

            IsUpdating = true;

            // CTS interne lié au token externe + au timeout global.
            var internalCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            internalCts.CancelAfter(UpdateTimeout);

            lock (_ctsLock) { _currentCts = internalCts; }

            var token = internalCts.Token;
            var result = new UpdateResult { StartedAt = DateTime.Now };

            try
            {
                if (!File.Exists(_freshclamExe))
                {
                    result.Success = true;
                    result.Message = LocalizationService.GetString("Freshclam_ExeNotFound");
                    result.AlreadyUpToDate = true;
                    SurSortieFreshclam(LocalizationService.GetString("Freshclam_ExeNotFoundLog"));
                    return result;
                }

                // Pré-vérification : connectivité réseau (évite un timeout long et opaque).
                if (!IsNetworkAvailable())
                {
                    result.Success = false;
                    result.Message = LocalizationService.GetString("Freshclam_NoNetwork");
                    SurSortieFreshclam(LocalizationService.GetString("Freshclam_NoNetworkLog"));
                    return result;
                }

                // Pré-vérification : nettoyer un éventuel verrou freshclam orphelin.
                CleanupStaleLocks();

                await EnsureCodeSigningCertificatesPresentAsync(token).ConfigureAwait(false);

                // ArgumentList : pas de concaténation de chaîne ; conf et datadir (chemins avec espaces) sont échappés token par token.
                var psi = new ProcessStartInfo
                {
                    FileName = _freshclamExe,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    // Working dir explicite : freshclam cherche freshclam.conf
                    // dans son cwd si --config-file n'est pas trouvé.
                    WorkingDirectory = Path.GetDirectoryName(_freshclamExe) ?? string.Empty,
                };
                if (HasUsableRootCert())
                {
                    psi.Environment["CVD_CERTS_DIR"] = _effectiveCvdCertsDir;
                }

                BuildArguments(psi.ArgumentList);

                using var proc = new Process
                {
                    StartInfo = psi,
                    EnableRaisingEvents = true,
                };

                var tcs = new TaskCompletionSource<bool>(
                    TaskCreationOptions.RunContinuationsAsynchronously);
                proc.Exited += (_, _) => tcs.TrySetResult(true);

                proc.OutputDataReceived += (_, e) =>
                {
                    if (e.Data == null) return;
                    SurSortieFreshclam(e.Data);
                    if (e.Data.Contains("up-to-date", StringComparison.OrdinalIgnoreCase) ||
                        e.Data.Contains("up to date", StringComparison.OrdinalIgnoreCase))
                        result.AlreadyUpToDate = true;
                };
                proc.ErrorDataReceived += (_, e) =>
                {
                    if (e.Data != null) SurSortieFreshclam($"[ERR] {e.Data}");
                };

                using (token.Register(() =>
                {
                    try
                    {
                        if (!proc.HasExited)
                        {
                            SurSortieFreshclam(UiLogText.Info(LocalizationService.GetString("Freshclam_LogCancelProcess")));
                            proc.Kill(entireProcessTree: true);
                        }
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("FreshclamUpdater", "Kill process", ex);
                    }
                    tcs.TrySetCanceled(token);
                }))
                {
                    proc.Start();
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();
                    await tcs.Task.ConfigureAwait(false);
                }

                result.ExitCode = proc.ExitCode;
                result.FinishedAt = DateTime.Now;

                // freshclam: 0 = mis à jour, 1 = déjà à jour, >=2 = erreur
                result.Success = proc.ExitCode is 0 or 1;
                result.Message = proc.ExitCode switch
                {
                    0 => LocalizationService.GetString("Freshclam_SuccessUpdated"),
                    1 => LocalizationService.GetString("Freshclam_SuccessUpToDate"),
                    _ => LocalizationService.Format("Freshclam_ErrorExitCode", proc.ExitCode)
                };

                if (result.Success)
                {
                    LastUpdateTime = DateTime.Now;
                    DatabaseVersion = await GetLocalDatabaseVersionAsync().ConfigureAwait(false);
                    result.Version = DatabaseVersion;
                }
            }
            catch (OperationCanceledException)
            {
                result.Success = false;
                // Différencier annulation utilisateur vs timeout global.
                result.Message = ct.IsCancellationRequested
                    ? LocalizationService.GetString("Freshclam_CancelledUser")
                    : LocalizationService.Format("Freshclam_CancelledTimeout", (int)UpdateTimeout.TotalMinutes);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = LocalizationService.Format("Vm_ScanError", ex.Message);
                AppLogger.Error("FreshclamUpdater", "UpdateAsync", ex);
            }
            finally
            {
                DatabaseVersion = await GetLocalDatabaseVersionAsync().ConfigureAwait(false);
                lock (_ctsLock)
                {
                    if (ReferenceEquals(_currentCts, internalCts))
                        _currentCts = null;
                }
                internalCts.Dispose();
                IsUpdating = false;
                UpdateCompleted?.Invoke(this, result);
            }

            return result;
        }

        // ── Version locale ─────────────────────────────────────────────────────────

        public async Task<string> GetLocalDatabaseVersionAsync()
        {
            try
            {
                if (!Directory.Exists(_databaseDir))
                    return VersionDisplayHelper.UnknownLabel;

                string[] candidates = {
                    Path.Combine(_databaseDir, "daily.cld"),
                    Path.Combine(_databaseDir, "daily.cvd"),
                    Path.Combine(_databaseDir, "main.cld"),
                    Path.Combine(_databaseDir, "main.cvd")
                };

                foreach (var filePath in candidates)
                {
                    if (!File.Exists(filePath)) continue;
                    try
                    {
                        var header = ReadFileHeader(filePath, 512);

                        var m = Regex.Match(header, @"ClamAV-VDB:[^:]+:(\d+):");
                        if (m.Success && m.Groups[1].Value.All(char.IsDigit))
                            return m.Groups[1].Value;

                        m = Regex.Match(header, @"version:\s*(\d+)", RegexOptions.IgnoreCase);
                        if (m.Success && m.Groups[1].Value.All(char.IsDigit))
                            return m.Groups[1].Value;
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("FreshclamUpdater", $"Lecture {filePath}", ex);
                    }
                }

                if (File.Exists(_freshclamExe))
                    return await GetVersionFromProcessAsync().ConfigureAwait(false);

                return VersionDisplayHelper.UnknownLabel;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("FreshclamUpdater", "GetLocalDatabaseVersion", ex);
                return VersionDisplayHelper.UnknownLabel;
            }
        }

        /// <summary>
        /// Dernière MAJ réussie via freshclam dans cette session, sinon date des bases .cvd/.cld locales
        /// (installateur, CI, fetch-runtime-deps). Aligné avec <see cref="GetLastSignatureChangeDisplay"/>.
        /// </summary>
        public DateTime? GetLastSignatureUpdateTime()
        {
            if (LastUpdateTime.HasValue)
                return LastUpdateTime.Value;
            var utc = GetLatestLocalDatabaseWriteTime();
            return utc?.ToLocalTime();
        }

        /// <summary>
        /// Date du dernier succès freshclam, sinon dernière modification des bases .cld/.cvd.
        /// </summary>
        public string GetLastSignatureChangeDisplay()
        {
            var t = GetLastSignatureUpdateTime();
            return t.HasValue ? t.Value.ToString("dd/MM/yyyy HH:mm") : "—";
        }

        private DateTime? GetLatestLocalDatabaseWriteTime()
        {
            try
            {
                if (!Directory.Exists(_databaseDir))
                    return null;
                DateTime? max = null;
                foreach (var name in new[] { "daily.cld", "daily.cvd", "main.cld", "main.cvd" })
                {
                    var p = Path.Combine(_databaseDir, name);
                    if (!File.Exists(p)) continue;
                    var w = File.GetLastWriteTimeUtc(p);
                    if (max == null || w > max.Value) max = w;
                }
                return max;
            }
            catch
            {
                return null;
            }
        }

        // ── Helpers privés ─────────────────────────────────────────────────────────

        /// <summary>
        /// Vérifie qu'au moins une interface réseau est UP et non-loopback.
        /// Test rapide local — ne garantit pas que database.clamav.net est joignable
        /// mais évite un timeout long quand l'utilisateur est offline.
        /// </summary>
        private static bool IsNetworkAvailable()
        {
            try { return NetworkInterface.GetIsNetworkAvailable(); }
            catch { return true; /* en cas de doute, on laisse passer */ }
        }

        /// <summary>
        /// Supprime les verrous freshclam orphelins (mirrors.dat lock, freshclam.pid)
        /// laissés par un process précédent qui aurait crashé.
        /// </summary>
        private void CleanupStaleLocks()
        {
            try
            {
                if (!Directory.Exists(_databaseDir)) return;

                // Noms de verrous connus de freshclam selon les versions.
                string[] lockFiles =
                {
                    Path.Combine(_databaseDir, "freshclam.pid"),
                    Path.Combine(_databaseDir, "mirrors.dat.lock"),
                    Path.Combine(_databaseDir, "freshclam.dat.lock"),
                };

                foreach (var lockPath in lockFiles)
                {
                    if (!File.Exists(lockPath)) continue;
                    try
                    {
                        var age = DateTime.Now - File.GetLastWriteTime(lockPath);
                        if (age > StaleLockAge)
                        {
                            File.Delete(lockPath);
                            SurSortieFreshclam(UiLogText.Info(LocalizationService.Format(
                                "Freshclam_LogStaleLockRemoved", Path.GetFileName(lockPath))));
                        }
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("FreshclamUpdater", $"Cleanup {lockPath}", ex);
                    }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("FreshclamUpdater", "CleanupStaleLocks", ex);
            }
        }

        /// <summary>
        /// Remplit <see cref="ProcessStartInfo.ArgumentList"/> (échappement sûr des chemins) au lieu de concaténer une ligne de commande.
        /// .NET gère le quoting Windows pour chaque token.
        ///
        /// IMPORTANT : freshclam exige le format "--option=valeur" (un seul
        /// token, avec '=') et NON "--option valeur" (deux tokens séparés)
        /// pour les options à valeur (--datadir, --config-file). Le format
        /// espacé renvoie freshclam exit code 2 (FCE_CONFIG, erreur de
        /// configuration). On construit donc un seul argument par option.
        /// </summary>
        private void BuildArguments(System.Collections.ObjectModel.Collection<string> args)
        {
            args.Add("--show-progress");
            args.Add("--no-warnings");

            try
            {
                Directory.CreateDirectory(_databaseDir);
                // Toujours passer --datadir : même si le conf contient DatabaseDirectory,
                // freshclam doit pouvoir créer tmp.* dans un dossier inscriptible.
                args.Add($"--datadir={_databaseDir}");
            }
            catch (Exception ex)
            {
                AppLogger.Warn("FreshclamUpdater", "BuildArguments datadir", ex);
            }

            var conf = EnsureConfExists();
            if (conf != null)
            {
                args.Add($"--config-file={conf}");
            }

            AppLogger.Info("FreshclamUpdater",
                $"Args: {string.Join(" ", args)}");
        }

        /// <summary>
        /// Garantit l'existence d'un freshclam.conf valide.
        ///
        /// Stratégie : on privilégie TOUJOURS un emplacement writable hors
        /// Program Files (LocalAppData), pour deux raisons :
        ///  1. Le fichier dans Program Files peut être en lecture seule sans
        ///     droits admin.
        ///  2. La UAC Virtualization de Windows redirige les écritures dans
        ///     Program Files vers VirtualStore, ce qui peut faire diverger le
        ///     fichier vu par notre process et celui vu par freshclam.exe.
        ///
        /// On tente aussi en best effort de "neutraliser" le conf corrompu
        /// dans Program Files (BOM, ancienne version) pour éviter qu'il soit
        /// chargé si jamais notre --config-file était ignoré.
        /// </summary>
        private string? EnsureConfExists()
        {
            var fallbackDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiCombat", "clamav");
            var fallbackConf = Path.Combine(fallbackDir, "freshclam.conf");

            return FreshclamConfSupport.EnsureWritableConf(
                fallbackConf,
                _freshclamConf,
                _ => BuildConfBytes(),
                path => SurSortieFreshclam(UiLogText.Info(LocalizationService.Format("Freshclam_LogConfRepaired", path))));
        }

        private byte[]? BuildConfBytes()
        {
            try
            {
                Directory.CreateDirectory(_databaseDir);
                var dbDirForConf = FreshclamConfSupport.NormalizePathForConf(_databaseDir);
                var logForConf = FreshclamConfSupport.NormalizePathForConf(ResolveWritableLogPath());
                var includeCerts = HasUsableRootCert();
                var certsDir = includeCerts
                    ? FreshclamConfSupport.NormalizePathForConf(_effectiveCvdCertsDir)
                    : null;

                return FreshclamConfSupport.BuildConfBytes(
                    ProductVersionInfo.ConfMarkerMajor,
                    dbDirForConf,
                    logForConf,
                    includeCerts,
                    certsDir);
            }
            catch (Exception ex)
            {
                AppLogger.Error("FreshclamUpdater", "BuildConfBytes", ex);
                return null;
            }
        }

        /// <summary>
        /// Détermine un chemin de log inscriptible. Retourne le chemin dans le dossier
        /// base de données s'il est accessible en écriture, sinon une solution de repli dans
        /// LocalAppData (évite les échecs sur Program Files sans admin).
        /// </summary>
        private string ResolveWritableLogPath()
        {
            var primary = Path.Combine(_databaseDir, "freshclam.log");
            try
            {
                Directory.CreateDirectory(_databaseDir);
                using var fs = new FileStream(primary, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite);
                return primary;
            }
            catch
            {
                var fallbackDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "optiCombat", "logs");
                try { Directory.CreateDirectory(fallbackDir); } catch { /* approche prudente */ }
                return Path.Combine(fallbackDir, "freshclam.log");
            }
        }

        private static string ReadFileHeader(string path, int maxBytes)
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var buf = new byte[Math.Min(maxBytes, (int)fs.Length)];
            _ = fs.Read(buf, 0, buf.Length);
            return System.Text.Encoding.ASCII.GetString(buf);
        }

        private async Task<string> GetVersionFromProcessAsync()
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                using var proc = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = _freshclamExe,
                        Arguments = "--version",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,  // drainer stderr pour éviter deadlock pipe
                        CreateNoWindow = true
                    },
                    EnableRaisingEvents = true
                };
                proc.Start();

                // Lire stdout et stderr en parallèle pour éviter le deadlock pipe
                var stdoutTask = proc.StandardOutput.ReadToEndAsync(cts.Token);
                var stderrTask = proc.StandardError.ReadToEndAsync(cts.Token);

                await Task.WhenAll(stdoutTask, stderrTask).ConfigureAwait(false);
                await proc.WaitForExitAsync(cts.Token).ConfigureAwait(false);

                var output = await stdoutTask.ConfigureAwait(false);
                var m = Regex.Match(output, @"(?:ClamAV\s+[\d.]+/|version\s+)(\d{4,6})");
                return m.Success ? m.Groups[1].Value : VersionDisplayHelper.UnknownLabel;
            }
            catch { return VersionDisplayHelper.UnknownLabel; }
        }

        private bool HasUsableRootCert()
        {
            try
            {
                var p = Path.Combine(_effectiveCvdCertsDir, "clamav.crt");
                return Directory.Exists(_effectiveCvdCertsDir)
                       && File.Exists(p)
                       && new FileInfo(p).Length >= 256;
            }
            catch
            {
                return false;
            }
        }

        private async Task EnsureCodeSigningCertificatesPresentAsync(CancellationToken ct)
        {
            _effectiveCvdCertsDir = _certsDir;
            var bundled = Path.Combine(AppContext.BaseDirectory, "clamav", "certs", "clamav.crt");

            bool tryDeploy(string dir)
            {
                try
                {
                    Directory.CreateDirectory(dir);
                    var dest = Path.Combine(dir, "clamav.crt");
                    if (File.Exists(dest) && new FileInfo(dest).Length >= 256)
                        return true;
                    if (File.Exists(bundled))
                    {
                        File.Copy(bundled, dest, overwrite: true);
                        SurSortieFreshclam(LocalizationService.Format("Freshclam_LogCvdCert", dest));
                    }
                    return File.Exists(dest) && new FileInfo(dest).Length >= 256;
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("FreshclamUpdater", $"tryDeploy {dir}", ex);
                    return false;
                }
            }

            if (tryDeploy(_certsDir))
                return;

            var fallback = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiCombat", "clamav", "cvd-certs");

            if (!tryDeploy(fallback))
                await TryDownloadClamAvRootCertAsync(fallback, ct).ConfigureAwait(false);

            var fbCert = Path.Combine(fallback, "clamav.crt");
            if (File.Exists(fbCert) && new FileInfo(fbCert).Length >= 256)
            {
                _effectiveCvdCertsDir = fallback;
                if (!string.Equals(_effectiveCvdCertsDir, _certsDir, StringComparison.OrdinalIgnoreCase))
                    SurSortieFreshclam(LocalizationService.Format("Freshclam_LogCvdCertsDir", _effectiveCvdCertsDir));
                return;
            }

            SurSortieFreshclam(UiLogText.Warn(LocalizationService.GetString("Freshclam_LogCvdCertMissing")));
        }

        private static async Task TryDownloadClamAvRootCertAsync(string destDir, CancellationToken ct)
        {
            try
            {
                Directory.CreateDirectory(destDir);
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(25) };
                http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", ProductVersionInfo.HttpUserAgent);
                var bytes = await http.GetByteArrayAsync(ClamAvRootCertUri, ct).ConfigureAwait(false);
                if (bytes.Length < 256) return;
                var path = Path.Combine(destDir, "clamav.crt");
                await File.WriteAllBytesAsync(path, bytes, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("FreshclamUpdater", "TryDownloadClamAvRootCertAsync", ex);
            }
        }

        private void SurSortieFreshclam(string line)
            => UpdateOutput?.Invoke(this, line);
    }

    // ── DTO de résultat ────────────────────────────────────────────────────────────

    /// <summary>Résultat d'une mise à jour de signatures ClamAV.</summary>
    public class UpdateResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? Version { get; set; }
        public bool AlreadyUpToDate { get; set; }
        public int ExitCode { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime? FinishedAt { get; set; }
    }
}
