using System.IO;
using System.Text;

namespace optiCombat.Services
{
    /// <summary>
    /// Logger applicatif léger — sink console (Debug.WriteLine) + fichier rolling.
    ///
    /// Pourquoi pas Serilog : ajouter une dépendance NuGet impose à l'utilisateur
    /// un dotnet restore et risque de péter la build. Cette implémentation maison
    /// couvre les besoins de base (niveaux, rolling quotidien, thread-safe,
    /// format structuré) sans nouvelle dépendance.
    ///
    /// Format de ligne :
    ///   2026-05-08 14:32:17.123 | ERROR | QuarantineManager | Quarantine ({path}): {message}
    ///
    /// Le fichier vit dans %LOCALAPPDATA%\optiCombat\Logs\opticombat-YYYY-MM-DD.log
    /// avec rotation quotidienne et nettoyage automatique au-delà de 30 jours.
    /// </summary>
    public static class AppLogger
    {
        public enum Level { Debug, Info, Warn, Error, Fatal }

        /// <summary>Seuil minimal écrit sur disque. Les niveaux inférieurs vont seulement dans Debug.WriteLine.</summary>
        public static Level MinimumFileLevel { get; set; } = Level.Info;

        private static readonly string LogDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiCombat", "Logs");

        private static readonly object _writeLock = new();
        private static readonly string LastCleanupMarkerPath = Path.Combine(LogDir, ".lastcleanup");
        private static DateTime _lastCleanup = LoadLastCleanupUtc();

        // ── API publique ─────────────────────────────────────────────────────────

        /// <summary>Journalise un message de niveau DEBUG (console uniquement, non écrit sur disque par défaut).</summary>
        public static void Debug(string component, string message) =>
            Write(Level.Debug, component, message, null);

        /// <summary>Journalise un message informatif.</summary>
        public static void Info(string component, string message) =>
            Write(Level.Info, component, message, null);

        /// <summary>Journalise un avertissement, avec exception optionnelle.</summary>
        public static void Warn(string component, string message, Exception? ex = null) =>
            Write(Level.Warn, component, message, ex);

        /// <summary>Journalise une erreur récupérable avec sa stack trace complète.</summary>
        public static void Error(string component, string message, Exception? ex = null) =>
            Write(Level.Error, component, message, ex);

        /// <summary>Journalise une erreur fatale (non récupérable).</summary>
        public static void Fatal(string component, string message, Exception? ex = null) =>
            Write(Level.Fatal, component, message, ex);

        // ── Implémentation ───────────────────────────────────────────────────────

        private static void Write(Level level, string component, string message, Exception? ex)
        {
            var line = FormatLine(level, component, message, ex);

            // Console / Debug : toujours, peu importe le niveau (utile en dev).
            try { System.Diagnostics.Debug.WriteLine(line); } catch { }

            // Fichier : seulement si le niveau est >= seuil.
            if (level < MinimumFileLevel) return;

            try
            {
                var path = Path.Combine(LogDir, $"opticombat-{DateTime.Now:yyyy-MM-dd}.log");
                lock (_writeLock)
                {
                    if (!Directory.Exists(LogDir)) Directory.CreateDirectory(LogDir);
                    File.AppendAllText(path, line + Environment.NewLine, Encoding.UTF8);
                    MaybeCleanupOldLogs();
                }
            }
            catch
            {
                // Last resort : un échec de logging ne doit JAMAIS faire crasher l'app.
                // On laisse Debug.WriteLine qui a déjà capturé la ligne.
            }
        }

        private static string FormatLine(Level level, string component, string message, Exception? ex)
        {
            var lvl = level switch
            {
                Level.Debug => "DEBUG",
                Level.Info => "INFO ",
                Level.Warn => "WARN ",
                Level.Error => "ERROR",
                Level.Fatal => "FATAL",
                _ => "?????",
            };
            var sb = new StringBuilder(256);
            sb.Append(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"));
            sb.Append(" | ").Append(lvl);
            // Pad puis tronquer à 20 colonnes (PadRight seul casse sur composants courts).
            var comp = component.Length > 20 ? component[..20] : component;
            sb.Append(" | ").Append(comp.PadRight(20));
            sb.Append(" | ").Append(message);
            if (ex != null)
            {
                sb.Append(" | EXC=").Append(ex.GetType().Name);
                sb.Append(": ").Append(ex.Message);
                if (level >= Level.Error)
                    sb.Append(Environment.NewLine).Append("  ").Append(ex.StackTrace);
            }
            return sb.ToString();
        }

        /// <summary>Supprime les logs de plus de 30 jours, max une fois par jour (persisté entre sessions).</summary>
        private static void MaybeCleanupOldLogs()
        {
            if ((DateTime.UtcNow - _lastCleanup).TotalHours < 24) return;
            _lastCleanup = DateTime.UtcNow;
            PersistLastCleanupUtc(_lastCleanup);

            try
            {
                var threshold = DateTime.Now.AddDays(-30);
                foreach (var f in Directory.EnumerateFiles(LogDir, "opticombat-*.log"))
                {
                    try
                    {
                        if (File.GetLastWriteTime(f) < threshold)
                            File.Delete(f);
                    }
                    catch { /* fichier verrouillé → tant pis, on le verra demain */ }
                }
            }
            catch { /* best effort */ }
        }

        private static DateTime LoadLastCleanupUtc()
        {
            try
            {
                if (!File.Exists(LastCleanupMarkerPath)) return DateTime.MinValue;
                var text = File.ReadAllText(LastCleanupMarkerPath, Encoding.UTF8).Trim();
                if (DateTime.TryParse(text, null, System.Globalization.DateTimeStyles.RoundtripKind, out var dt))
                    return dt.Kind == DateTimeKind.Utc ? dt : dt.ToUniversalTime();
            }
            catch { /* premier lancement ou fichier corrompu */ }
            return DateTime.MinValue;
        }

        private static void PersistLastCleanupUtc(DateTime utc)
        {
            try
            {
                if (!Directory.Exists(LogDir)) Directory.CreateDirectory(LogDir);
                File.WriteAllText(LastCleanupMarkerPath, utc.ToString("o"), Encoding.UTF8);
            }
            catch { /* best effort */ }
        }
    }
}
