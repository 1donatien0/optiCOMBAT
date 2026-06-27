using optiCombat.Models;
using System.Linq;
using System.IO;
using System.Runtime.Versioning;
using System.Text;

namespace optiCombat.Services
{
    /// <summary>
    /// Gère l'historique des scans et des nettoyages système et le journal texte.
    ///
    /// Persistance sécurisée :
    ///   - <c>scan_history.dat</c>  / <c>clean_history.dat</c> — chiffrés DPAPI + HMAC-SHA256
    ///     (même format que UserPreferences et ExclusionSettings).
    ///   - Migration transparente depuis les anciens <c>.json</c> en clair au premier chargement ;
    ///     le fichier clair est renommé en <c>.legacy</c> après migration réussie.
    ///
    /// Sessions scan récentes : liste <see cref="Models.ThreatInfo"/> (chemin + nom) ;
    /// entrées anciennes : compteur de menaces sans chemins persistés.
    ///
    /// Rétention implicite (scans et nettoyages) : la liste regrosse jusqu'à 100 entrées,
    /// puis les 50 plus anciennes sont supprimées (50 restantes), et le cycle reprend.
    ///
    /// <c>optiCombat.log</c> : journal texte volontairement non chiffré ; les lignes de détail scan
    /// utilisent <see cref="PathRedaction.RedactPath"/> (pas de chemins complets à l'écriture).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class ScanLogManager
    {
        /// <summary>Seuil : au-delà, on retire les entrées les plus anciennes par lot.</summary>
        private const int HistoryHighWaterMark = 100;

        /// <summary>Nombre d'entrées conservées après purge (les 50 plus récentes restent).</summary>
        private const int HistoryRetainCount = 50;

        private readonly string _logDir;

        // Nouveaux chemins chiffrés
        private readonly string _historyPath;
        private readonly string _cleanHistoryPath;

        // Anciens chemins JSON en clair (migration uniquement)
        private readonly string _historyLegacyPath;
        private readonly string _cleanHistoryLegacyPath;

        private readonly string _textLogPath;

        private List<ScanSession> _history;
        private List<CleanSession> _cleanHistory;
        private ActivityLogService? _activityLog;

        public ScanLogManager(string? logDir = null)
        {
            _logDir = logDir
                ?? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "optiCombat", "Logs");

            _historyPath      = Path.Combine(_logDir, "scan_history.dat");
            _cleanHistoryPath = Path.Combine(_logDir, "clean_history.dat");
            _historyLegacyPath      = Path.Combine(_logDir, "scan_history.json");
            _cleanHistoryLegacyPath = Path.Combine(_logDir, "clean_history.json");
            _textLogPath = Path.Combine(_logDir, "optiCombat.log");

            EnsureDirectory(_logDir);
            _history = LoadHistory();
            _cleanHistory = LoadCleanHistory();
        }

        public void BindActivityLog(ActivityLogService activityLog) => _activityLog = activityLog;

        // ── Historique des scans ────────────────────────────────────────────────

        /// <summary>
        /// Sauvegarde un ScanResult terminé dans l'historique.
        /// </summary>
        public void SaveScanResult(ScanResult result)
        {
            var session = ScanSession.FromResult(result);
            _history.Insert(0, session); // plus récent en premier
            TrimNewestFirstList(_history);
            PersistHistory();
            _activityLog?.RecordScanCompleted(session);

            WriteToLog(FormatScanDetail(result));
        }

        /// <summary>
        /// Retourne l'historique complet (plus récent en premier).
        /// </summary>
        public IReadOnlyList<ScanSession> GetHistory() => _history.AsReadOnly();

        /// <summary>
        /// Retire une menace traitée d'une session persistée (quarantaine, suppression, exclusion).
        /// </summary>
        public bool TryRemoveThreatFromSession(Guid sessionId, string filePath)
        {
            if (sessionId == Guid.Empty || string.IsNullOrWhiteSpace(filePath))
                return false;

            var session = _history.FirstOrDefault(s => s.SessionId == sessionId);
            if (session == null)
                return false;

            var removed = session.Threats.RemoveAll(t =>
                string.Equals(t.FilePath, filePath, StringComparison.OrdinalIgnoreCase));
            if (removed == 0)
                return false;

            session.ThreatsFound = session.Threats.Count;
            PersistHistory();
            return true;
        }

        /// <summary>
        /// Retire des sessions persistées les menaces déjà isolées en quarantaine (même chemin d'origine).
        /// </summary>
        public int ReconcileQuarantinedThreats(IEnumerable<QuarantineEntry> quarantineEntries)
        {
            var paths = quarantineEntries
                .Select(e => e.OriginalPath)
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (paths.Count == 0)
                return 0;

            int removed = 0;
            foreach (var session in _history)
            {
                int n = session.Threats.RemoveAll(t => paths.Contains(t.FilePath));
                if (n == 0) continue;
                session.ThreatsFound = session.Threats.Count;
                removed += n;
            }

            if (removed > 0)
                PersistHistory();
            return removed;
        }

        // ── Historique des nettoyages système (vue Historique → Nettoyages) ───────

        /// <summary>Enregistre un nettoyage terminé (plus récent en tête ; rotation 100 → 50).</summary>
        public void SaveCleanSession(CleanSession session)
        {
            _cleanHistory.Insert(0, session);
            TrimNewestFirstList(_cleanHistory);
            PersistCleanHistory();
            _activityLog?.RecordCleanCompleted(session);
            WriteToLog($"Nettoyage système — {session.BytesDisplay} libéré(s) — {session.TargetsSummary}");
        }

        public IReadOnlyList<CleanSession> GetCleanHistory() => _cleanHistory.AsReadOnly();

        /// <summary>
        /// Efface tout l'historique.
        /// </summary>
        public void ClearHistory()
        {
            _history.Clear();
            PersistHistory();
            WriteToLog("Historique effacé par l'utilisateur.");
        }

        /// <summary>
        /// Liste triée « plus récent en premier » : à partir de <see cref="HistoryHighWaterMark"/>
        /// entrées, supprime les <see cref="HistoryRetainCount"/> plus anciennes (il en reste 50),
        /// puis la liste peut regrossir jusqu'à 100 avant une nouvelle purge.
        /// </summary>
        private static void TrimNewestFirstList<T>(List<T> list)
        {
            if (list.Count < HistoryHighWaterMark) return;
            list.RemoveRange(HistoryRetainCount, list.Count - HistoryRetainCount);
        }

        // ── Journal texte ───────────────────────────────────────────────────────

        /// <summary>
        /// Écrit une ligne horodatée dans le journal texte (append-only, non atomique).
        /// En cas de crash brutal, seule la dernière écriture peut être tronquée ;
        /// les lignes précédentes restent intactes.
        /// </summary>
        public void WriteToLog(string message)
        {
            try
            {
                EnsureDirectory(_logDir);
                var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
                File.AppendAllText(_textLogPath, line + Environment.NewLine, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScanLogManager", "WriteToLog", ex);
            }
        }

        /// <summary>
        /// Retourne les N dernières lignes du journal texte.
        /// </summary>
        public string[] ReadLastLogLines(int count = 200)
        {
            if (!File.Exists(_textLogPath)) return Array.Empty<string>();
            try
            {
                var lines = File.ReadAllLines(_textLogPath, Encoding.UTF8);
                int start = Math.Max(0, lines.Length - count);
                var result = new string[lines.Length - start];
                Array.Copy(lines, start, result, 0, result.Length);
                return result;
            }
            catch { return Array.Empty<string>(); }
        }

        /// <summary>Chemin du fichier journal texte.</summary>
        public string TextLogPath => _textLogPath;

        /// <summary>Chemin du dossier de logs.</summary>
        public string LogDirectory => _logDir;

        // ── Helpers ─────────────────────────────────────────────────────────────

        /// <summary>Texte détaillé d'une session (menaces, statut, erreurs) — affiché dans Historique et journal fichier.</summary>
        public static string FormatScanDetail(ScanResult result) =>
            FormatScanDetailCore(
                result.TypeDisplay,
                result.TargetPath,
                result.StartedAt,
                result.FinishedAt,
                result.FilesScanned,
                result.FilesSkipped,
                result.ThreatsFound,
                result.Status.ToString(),
                result.ErrorMessage,
                result.Threats);

        /// <summary>Texte détaillé à partir d'une entrée d'historique persistée.</summary>
        public static string FormatScanDetail(ScanSession session) =>
            FormatScanDetailCore(
                session.TypeDisplay,
                session.TargetPath,
                session.StartedAt,
                session.FinishedAt,
                session.FilesScanned,
                session.FilesSkipped,
                session.ThreatsFound,
                session.StatusDisplay,
                session.ErrorMessage,
                session.Threats);

        private static string FormatScanDetailCore(
            string typeDisplay,
            string targetPath,
            DateTime startedAt,
            DateTime? finishedAt,
            int filesScanned,
            int filesSkipped,
            int threatsFound,
            string status,
            string? errorMessage,
            IReadOnlyList<ThreatInfo> threats)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"--- Scan {typeDisplay} ---");
            sb.AppendLine($"  Cible      : {PathRedaction.RedactPath(targetPath)}");
            sb.AppendLine($"  Démarré    : {startedAt:dd/MM/yyyy HH:mm:ss}");
            sb.AppendLine($"  Terminé    : {finishedAt?.ToString("dd/MM/yyyy HH:mm:ss") ?? "N/A"}");
            sb.AppendLine($"  Fichiers   : {filesScanned}");
            if (filesSkipped > 0)
                sb.AppendLine($"  Ignorés    : {filesSkipped}");
            sb.AppendLine($"  Menaces    : {threatsFound}");
            sb.AppendLine($"  Statut     : {status}");
            if (!string.IsNullOrWhiteSpace(errorMessage))
                sb.AppendLine($"  Erreur     : {errorMessage}");

            if (threats.Count > 0)
            {
                sb.AppendLine("  Détails menaces :");
                foreach (var t in threats)
                    sb.AppendLine($"    • {PathRedaction.RedactPath(t.FilePath)} → {t.VirusName}");
            }

            return sb.ToString().TrimEnd();
        }

        private List<ScanSession> LoadHistory()
        {
            // 1. Fichier chiffré présent → chargement direct
            if (File.Exists(_historyPath))
            {
                var loaded = SecureStore.Load<List<ScanSession>>(_historyPath);
                if (loaded != null) return loaded;
            }

            // 2. Migration depuis le JSON en clair (une seule fois)
            if (File.Exists(_historyLegacyPath))
            {
                var migrated = SecureStore.MigrateFromPlaintext<List<ScanSession>>(
                    _historyLegacyPath, _historyPath);
                if (migrated != null)
                {
                    AppLogger.Info("ScanLogManager", "scan_history.json migré vers format chiffré");
                    return migrated;
                }
            }

            return new List<ScanSession>();
        }

        private void PersistHistory()
        {
            try
            {
                SecureStore.Save(_historyPath, _history);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScanLogManager", "PersistHistory", ex);
            }
        }

        private List<CleanSession> LoadCleanHistory()
        {
            // 1. Fichier chiffré présent → chargement direct
            if (File.Exists(_cleanHistoryPath))
            {
                var loaded = SecureStore.Load<List<CleanSession>>(_cleanHistoryPath);
                if (loaded != null) return loaded;
            }

            // 2. Migration depuis le JSON en clair (une seule fois)
            if (File.Exists(_cleanHistoryLegacyPath))
            {
                var migrated = SecureStore.MigrateFromPlaintext<List<CleanSession>>(
                    _cleanHistoryLegacyPath, _cleanHistoryPath);
                if (migrated != null)
                {
                    AppLogger.Info("ScanLogManager", "clean_history.json migré vers format chiffré");
                    return migrated;
                }
            }

            return new List<CleanSession>();
        }

        private void PersistCleanHistory()
        {
            try
            {
                SecureStore.Save(_cleanHistoryPath, _cleanHistory);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ScanLogManager", "PersistCleanHistory", ex);
            }
        }

        private static void EnsureDirectory(string dir)
        {
            if (!Directory.Exists(dir))
                Directory.CreateDirectory(dir);
        }
    }
}
