using optiCombat.Localization;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace optiCombat.Services
{
    /// <summary>
    /// Moteur YARA — exécute yara64/yara32.exe en ligne de commande.
    /// Compile les règles avec yarac64/yarac32.exe pour accélérer les scans répétés.
    /// </summary>
    public class YaraEngine : IYaraOrchestratorBackend
    {
        /// <summary>
        /// Fréquence d'émission des messages de progression dans RunYaraScanRecursiveAsync :
        /// un message est émis toutes les N lignes stdout traitées.
        /// Exposé pour que ScanOrchestrator puisse interpoler le compteur de fichiers.
        /// </summary>
        public const int YaraProgressInterval = 20;

        private readonly string _yaraExe;     // yara64.exe / yara32.exe
        private readonly string _yaracExe;    // yarac64.exe / yarac32.exe (compilateur)
        private readonly string _rulesDirectory;
        private readonly string _compiledRulesPath;
        private readonly string _rulesCountCachePath;
        // Empreinte enregistrée au moment de la dernière compilation réussie.
        // Permet de détecter qu'un .yar a été modifié depuis la dernière compilation
        // sans attendre la suppression manuelle de _compiled.yarc.
        private readonly string _compiledStampPath;
        private readonly IExclusionSettingsAccessor _exclusions;

        /// <summary>Limite de caractères capturés depuis la sortie standard de yara.</summary>
        private const int MaxYaraStdoutCaptureChars = 2_000_000;

        public bool IsAvailable { get; private set; }
        public int RulesCount { get; private set; }

        /// <summary>
        /// <c>true</c> si <c>_compiled.yarc</c> existe ET correspond à l'état actuel des fichiers .yar.
        /// Un <c>false</c> ici déclenche automatiquement une recompilation au prochain scan.
        /// </summary>
        public bool HasCompiled => YaraRulesCacheSupport.IsCompiledUpToDate(
            _rulesDirectory, _compiledRulesPath, _compiledStampPath);

        // ── Constructeur ─────────────────────────────────────────────────────────

        public YaraEngine(
            string? yaraDir = null,
            string? rulesDir = null,
            IExclusionSettingsAccessor? exclusions = null)
        {
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var arch = Environment.Is64BitProcess ? "64" : "32";

            var resolvedYaraDir = yaraDir ?? Path.Combine(baseDir, "yara");

            _yaraExe = Path.Combine(resolvedYaraDir, $"yara{arch}.exe");
            _yaracExe = Path.Combine(resolvedYaraDir, $"yarac{arch}.exe");

            _rulesDirectory = rulesDir ?? Path.Combine(baseDir, "rules");
            _compiledRulesPath = Path.Combine(_rulesDirectory, "_compiled.yarc");
            _rulesCountCachePath = Path.Combine(_rulesDirectory, ".rules_count.cache");
            _compiledStampPath = Path.Combine(_rulesDirectory, "_compiled.stamp");

            IsAvailable = CheckAvailability();
            if (IsAvailable)
                RulesCount = CountRules();
        }

        // ── Disponibilité ─────────────────────────────────────────────────────────

        private bool CheckAvailability()
        {
            if (!File.Exists(_yaraExe))
                return false;
            if (!Directory.Exists(_rulesDirectory))
                return false;
            return Directory.GetFiles(_rulesDirectory, "*.yar").Length > 0;
        }

        /// <summary>
        /// Vérifie que <c>_compiled.yarc</c> existe ET que son empreinte correspond
        /// à l'état actuel des fichiers .yar. Retourne <c>false</c> si le fichier
        /// est absent, si <c>_compiled.stamp</c> est absent ou périmé (modification
        /// manuelle d'une règle, ajout/suppression d'un .yar).
        /// </summary>
        // L2 fix : regex multiline plutôt que StartsWith("rule ") ligne par ligne.
        // StartsWith manquait les règles précédées d'indentation, de commentaires,
        // ou définies sans espace supplémentaire ; la regex matche "rule <ident>"
        // n'importe où en début de ligne (y compris avec tabulation).
        private static readonly Regex RuleStartRegex = new(
            @"^\s*rule\s+[A-Za-z_]\w*",
            RegexOptions.Multiline | RegexOptions.Compiled);

        private int CountRules()
        {
            try
            {
                var files = Directory.GetFiles(_rulesDirectory, "*.yar");
                if (files.Length == 0)
                    return 0;

                Array.Sort(files, StringComparer.OrdinalIgnoreCase);
                var stamp = YaraRulesCacheSupport.ComputeRulesDirectoryFingerprint(files);
                if (TryReadRulesCountCache(stamp, out var cached))
                    return cached;

                int count = 0;
                foreach (var f in files)
                    count += RuleStartRegex.Count(File.ReadAllText(f));
                if (count <= 0)
                    count = files.Length;

                TryWriteRulesCountCache(stamp, count);
                return count;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("YaraEngine", "CountRules", ex);
                return 0;
            }
        }

        private bool TryReadRulesCountCache(string stamp, out int count)
        {
            count = 0;
            if (!File.Exists(_rulesCountCachePath))
                return false;
            try
            {
                var lines = File.ReadAllLines(_rulesCountCachePath);
                if (lines.Length < 2)
                    return false;
                if (!string.Equals(lines[0].Trim(), stamp, StringComparison.Ordinal))
                    return false;
                return int.TryParse(lines[1].Trim(), out count) && count >= 0;
            }
            catch
            {
                return false;
            }
        }

        private void TryWriteRulesCountCache(string stamp, int count)
        {
            try
            {
                File.WriteAllText(_rulesCountCachePath, stamp + Environment.NewLine + count, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("YaraEngine", "Écriture .rules_count.cache", ex);
            }
        }

        /// <summary>Accumule stdout yara avec un plafond pour limiter la mémoire.</summary>
        private sealed class YaraStdoutCapture
        {
            public readonly StringBuilder Builder = new();
            public bool Truncated;
            private int _capturedChars;

            public void SurLigneYara(string? line, int maxChars)
            {
                if (line == null || Truncated)
                    return;
                var add = line.Length + 2;
                if (_capturedChars + add > maxChars)
                {
                    Truncated = true;
                    return;
                }
                Builder.AppendLine(line);
                _capturedChars += add;
            }
        }

        // ── Compilation des règles ────────────────────────────────────────────────

        /// <summary>
        /// Compile toutes les règles .yar en un fichier .yarc pour accélérer les scans.
        /// Utilise yarac64.exe (ou yarac32.exe).
        /// </summary>
        public async Task<bool> CompileRulesAsync(CancellationToken ct = default)
        {
            if (!IsAvailable) return false;
            if (!File.Exists(_yaracExe)) return false; // yarac non disponible

            var ruleFiles = Directory.GetFiles(_rulesDirectory, "*.yar");
            if (ruleFiles.Length == 0) return false;

            // ArgumentList plutôt que concaténation de chaîne —
            // chaque fichier de règle est passé comme argument distinct, le
            // quoting est géré par .NET (CommandLineToArgvW round-trip safe)
            // même si un chemin contient des espaces ou des guillemets.
            var psi = new ProcessStartInfo
            {
                FileName = _yaracExe,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            foreach (var f in ruleFiles) psi.ArgumentList.Add(f);
            psi.ArgumentList.Add(_compiledRulesPath);

            using var process = new Process { StartInfo = psi };

            try
            {
                process.Start();
                // Lire stderr pour les erreurs de compilation
                var errTask = process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync(ct);
                try { process.WaitForExit(); }
                catch { /* processus déjà terminé — drain buffer (cf. ClamAvEngine) */ }
                var err = await errTask;

                if (!string.IsNullOrWhiteSpace(err))
                    AppLogger.Warn("yarac", err);

                var success = process.ExitCode == 0 && File.Exists(_compiledRulesPath);
                if (success)
                {
                    // Persiste l'empreinte courante → HasCompiled détectera tout
                    // changement ultérieur dans les .yar sans attendre une suppression manuelle.
                    try
                    {
                        Array.Sort(ruleFiles, StringComparer.OrdinalIgnoreCase);
                        YaraRulesCacheSupport.WriteCompiledStamp(_compiledStampPath, ruleFiles);
                    }
                    catch (Exception stampEx)
                    {
                        AppLogger.Warn("yarac", "Écriture _compiled.stamp échouée", stampEx);
                    }
                }
                return success;
            }
            catch (Exception ex)
            {
                AppLogger.Error("yarac", "Compilation échouée", ex);
                return false;
            }
        }

        // ── Scan d'un fichier ─────────────────────────────────────────────────────

        /// <summary>
        /// Scanne un fichier. Retourne la liste des règles qui ont matché.
        /// Utilise les règles compilées si disponibles, sinon les .yar un par un.
        /// </summary>
        public async Task<List<YaraMatch>> ScanFileAsync(
            string filePath, CancellationToken ct = default)
        {
            var matches = new List<YaraMatch>();
            if (!IsAvailable || !File.Exists(filePath)) return matches;
            if (_exclusions.Current.IsFileExcluded(filePath)) return matches;

            // Tenter compilation si pas encore fait
            if (!HasCompiled)
                await CompileRulesAsync(ct);

            if (HasCompiled)
            {
                // Scan avec règles compilées : yara64.exe --compiled-rules rules.yarc fichier
                // ArgumentList → guillemets/échappement sûr, pas de concaténation de chaîne.
                var results = await RunYaraScanAsync(
                    new[] { "--compiled-rules", _compiledRulesPath, filePath },
                    filePath, ct);
                matches.AddRange(results);
            }
            else
            {
                // Solution de repli : scan avec chaque .yar individuellement
                foreach (var ruleFile in Directory.GetFiles(_rulesDirectory, "*.yar"))
                {
                    if (ct.IsCancellationRequested) break;
                    var results = await RunYaraScanAsync(
                        new[] { ruleFile, filePath }, filePath, ct);
                    matches.AddRange(results);
                }
            }

            return matches;
        }

        /// <summary>
        /// Scanne une liste de fichiers en lots (un processus yara par lot).
        /// Évite le scan récursif complet du volume pour le mode USB rapide.
        /// </summary>
        public async Task<List<YaraMatch>> ScanFilesAsync(
            IReadOnlyList<string> files,
            IProgress<string>? progress = null,
            CancellationToken ct = default)
        {
            var matches = new List<YaraMatch>();
            if (!IsAvailable || files.Count == 0) return matches;

            if (!HasCompiled)
                await CompileRulesAsync(ct);

            const int batchSize = 32;
            for (var i = 0; i < files.Count; i += batchSize)
            {
                if (ct.IsCancellationRequested) break;

                var batch = new List<string>(batchSize);
                for (var j = i; j < files.Count && batch.Count < batchSize; j++)
                {
                    var path = files[j];
                    if (File.Exists(path) && !_exclusions.Current.IsFileExcluded(path))
                        batch.Add(path);
                }

                if (batch.Count == 0) continue;

                progress?.Report(LocalizationService.Format("Scan_Yara_Recursive", batch.Count.ToString()));

                if (HasCompiled)
                {
                    var args = new List<string> { "-N", "--compiled-rules", _compiledRulesPath };
                    args.AddRange(batch);
                    matches.AddRange(await RunYaraScanRecursiveAsync(args, ct, progress).ConfigureAwait(false));
                }
                else
                {
                    foreach (var ruleFile in Directory.GetFiles(_rulesDirectory, "*.yar"))
                    {
                        if (ct.IsCancellationRequested) break;
                        var args = new List<string> { "-N", ruleFile };
                        args.AddRange(batch);
                        matches.AddRange(await RunYaraScanRecursiveAsync(args, ct, progress).ConfigureAwait(false));
                    }
                }
            }

            return matches;
        }

        /// <summary>Retourne true si au moins une règle YARA matche le fichier.</summary>
        public async Task<bool> IsMaliciousAsync(string filePath, CancellationToken ct = default)
            => (await ScanFileAsync(filePath, ct)).Count > 0;

        /// <summary>
        /// Scanne un dossier entier en UN SEUL processus yara avec --recursive.
        ///
        /// L'ancienne approche (un processus par fichier dans ScanOrchestrator)
        /// dominait le temps de scan pour les gros dossiers : pour 10 000 fichiers,
        /// 10 000 lancements de yara64.exe, soit ~10 minutes uniquement de
        /// surcoût lié aux lancements. Cette méthode passe le dossier directement à yara qui
        /// l'itère lui-même, divisant le temps global par un facteur 10 à 50.
        ///
        /// La sortie de yara conserve le format "RuleName Path" pour chaque match,
        /// avec un chemin absolu permettant de reconstruire le ThreatInfo correctement.
        /// </summary>
        public async Task<List<YaraMatch>> ScanFolderAsync(
            string folderPath,
            IProgress<string>? progress = null,
            CancellationToken ct = default)
        {
            var matches = new List<YaraMatch>();
            if (!IsAvailable || !Directory.Exists(folderPath)) return matches;
            if (AppInstallPaths.IsUnderInstallRoot(folderPath)) return matches;

            // Compilation au besoin (idem ScanFileAsync).
            if (!HasCompiled)
                await CompileRulesAsync(ct);

            // Construction de la commande : --recursive + dossier en argument.
            // -N (no-warnings) supprime les avertissements verbeux.
            // ArgumentList : guillemets et chemins correctement échappés.
            string[] args;
            if (HasCompiled)
            {
                args = new[] { "-N", "--compiled-rules", "--recursive", _compiledRulesPath, folderPath };
            }
            else
            {
                // Sans règles compilées : scan séquentiel par règle, encore N fois
                // moins de lancements qu'un processus par fichier.
                foreach (var ruleFile in Directory.GetFiles(_rulesDirectory, "*.yar"))
                {
                    if (ct.IsCancellationRequested) break;
                    progress?.Report(LocalizationService.Format("Scan_Yara_Rule", Path.GetFileNameWithoutExtension(ruleFile)));
                    var sub = await RunYaraScanAsync(
                        new[] { "-N", "--recursive", ruleFile, folderPath },
                        folderPath, ct);
                    matches.AddRange(sub);
                }
                return matches;
            }

            progress?.Report(LocalizationService.Format("Scan_Yara_Recursive", Path.GetFileName(folderPath)));
            return await RunYaraScanRecursiveAsync(args, ct, progress);
        }

        /// <summary>
        /// Variante de RunYaraScanAsync pour les scans récursifs : la sortie yara
        /// est au format "RuleName /chemin/absolu/fichier" — chaque ligne est un
        /// match indépendant, avec un fichier potentiellement différent.
        /// </summary>
        private async Task<List<YaraMatch>> RunYaraScanRecursiveAsync(
            IEnumerable<string> args,
            CancellationToken ct,
            IProgress<string>? progress = null)
        {
            var matches = new List<YaraMatch>();
            var stdoutLines = 0;

            var psi = new ProcessStartInfo
            {
                FileName = _yaraExe,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var process = new Process { StartInfo = psi };

            try
            {
                process.Start();

                var cap = new YaraStdoutCapture();
                var stderrLines = new StringBuilder();
                process.OutputDataReceived += (_, e) =>
                {
                    cap.SurLigneYara(e.Data, MaxYaraStdoutCaptureChars);
                    if (string.IsNullOrEmpty(e.Data)) return;
                    var n = System.Threading.Interlocked.Increment(ref stdoutLines);
                    if (progress != null && (n == 1 || n % YaraProgressInterval == 0))
                        progress.Report(e.Data);
                };
                process.ErrorDataReceived += (_, e) => { if (e.Data != null) stderrLines.AppendLine(e.Data); };
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                using (ct.Register(() =>
                {
                    try
                    {
                        if (!process.HasExited)
                            process.Kill(entireProcessTree: true);
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("YaraEngine", "Annulation — arrêt yara", ex);
                    }
                }))
                {
                    await process.WaitForExitAsync(ct).ConfigureAwait(false);
                }

                try { process.WaitForExit(); }
                catch { /* processus déjà terminé — drain stdout */ }

                if (cap.Truncated)
                {
                    AppLogger.Warn("YaraEngine",
                        "Sortie stdout YARA tronquée (limite mémoire) — certains matchs peuvent manquer.");
                }

                var stderrContent = stderrLines.ToString().Trim();
                if (!string.IsNullOrEmpty(stderrContent))
                    AppLogger.Warn("YARA/stderr (récursif)", stderrContent);

                foreach (var line in cap.Builder.ToString()
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (line.StartsWith("0x")) continue;

                    // Format yara : "RuleName <espace> /chemin/absolu/fichier"
                    // Le chemin peut contenir des espaces — on prend le premier
                    // espace après la règle puis tout le reste.
                    var spaceIdx = line.IndexOf(' ');
                    if (spaceIdx <= 0) continue;

                    var ruleName = line[..spaceIdx].Trim();
                    var matchedPath = line[(spaceIdx + 1)..].Trim();

                    if (!string.IsNullOrEmpty(ruleName) && !string.IsNullOrEmpty(matchedPath)
                        && !_exclusions.Current.IsFileExcluded(matchedPath))
                        matches.Add(new YaraMatch { RuleName = ruleName, FilePath = matchedPath });
                }
            }
            catch (Exception ex)
            {
                AppLogger.Error("YARA", "Scan récursif", ex);
            }

            return matches;
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        private async Task<List<YaraMatch>> RunYaraScanAsync(
            IEnumerable<string> args, string filePath, CancellationToken ct)
        {
            var matches = new List<YaraMatch>();

            // ArgumentList + using Process : libération du processus garantie.
            var psi = new ProcessStartInfo
            {
                FileName = _yaraExe,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                // CORRECTION : StandardOutputEncoding absent → chemins non-ASCII
                // (accents, caractères Unicode) tronqués ou mal décodés.
                // Cohérence avec RunYaraScanRecursiveAsync qui le spécifie déjà.
                StandardOutputEncoding = Encoding.UTF8,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var process = new Process { StartInfo = psi };

            try
            {
                process.Start();

                var cap = new YaraStdoutCapture();
                var stderrLines = new System.Text.StringBuilder();
                process.OutputDataReceived += (_, e) => cap.SurLigneYara(e.Data, MaxYaraStdoutCaptureChars);
                // CORRECTION : BeginErrorReadLine() sans handler = stderr drainé mais
                // silencieusement perdu. On ajoute un handler pour logger les erreurs YARA.
                process.ErrorDataReceived += (_, e) => { if (e.Data != null) stderrLines.AppendLine(e.Data); };
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                using (ct.Register(() =>
                {
                    try
                    {
                        if (!process.HasExited)
                            process.Kill(entireProcessTree: true);
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("YaraEngine", "Annulation — arrêt yara", ex);
                    }
                }))
                {
                    await process.WaitForExitAsync(ct).ConfigureAwait(false);
                }

                // Drain final synchrone : garantit la réception des dernières
                // lignes capturées avant que outputSb soit lu (cf. doc MS).
                try { process.WaitForExit(); }
                catch { /* processus déjà terminé */ }

                if (cap.Truncated)
                {
                    AppLogger.Warn("YaraEngine",
                        "Sortie stdout YARA tronquée (limite mémoire) — certains matchs peuvent manquer.");
                }

                // Log les erreurs/avertissements YARA capturés depuis stderr
                var stderrContent = stderrLines.ToString().Trim();
                if (!string.IsNullOrEmpty(stderrContent))
                    AppLogger.Warn("YARA/stderr", stderrContent);

                // Format sortie YARA : "RuleName FilePath"
                foreach (var line in cap.Builder.ToString()
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    // Ignorer les lignes qui commencent par 0x (hex dump des strings)
                    if (line.StartsWith("0x")) continue;

                    var spaceIdx = line.IndexOf(' ');
                    if (spaceIdx > 0)
                    {
                        var ruleName = line[..spaceIdx].Trim();
                        if (!string.IsNullOrEmpty(ruleName))
                            matches.Add(new YaraMatch { RuleName = ruleName, FilePath = filePath });
                    }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Error("YARA", "Scan", ex);
            }

            return matches;
        }

        // ── Invalidation du cache compilé ─────────────────────────────────────────

        /// <summary>Supprime le fichier de règles compilées (force recompilation).</summary>
        public void InvalidateCompiledRules()
        {
            try
            {
                if (File.Exists(_compiledRulesPath))
                    File.Delete(_compiledRulesPath);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("YaraEngine", "InvalidateCompiledRules (.yarc)", ex);
            }
            try
            {
                if (File.Exists(_rulesCountCachePath))
                    File.Delete(_rulesCountCachePath);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("YaraEngine", "InvalidateCompiledRules (cache comptage)", ex);
            }
            try
            {
                if (File.Exists(_compiledStampPath))
                    File.Delete(_compiledStampPath);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("YaraEngine", "InvalidateCompiledRules (stamp)", ex);
            }
        }
    }

    /// <summary>Un match YARA (règle + fichier).</summary>
    public class YaraMatch
    {
        public string RuleName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
    }
}
