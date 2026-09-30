using optiCombat.Models;
using System.IO;
using System.Runtime.Versioning;

namespace optiCombat.Services
{
    /// <summary>
    /// Journal d'activité immuable : source unique de la timeline Historique.
    /// Scans et nettoyages restent aussi dans <see cref="ScanLogManager"/> pour le détail live.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class ActivityLogService
    {
        private const int MaxActivityEvents = 150;

        private readonly string _logPath;
        private readonly ScanLogManager _logger;
        private List<ActivityEventRecord> _events = new();
        private bool _migrationDone;

        public ActivityLogService(ScanLogManager logger, string? logDir = null)
        {
            _logger = logger;
            var dir = logDir
                ?? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "optiCombat", "Logs");
            Directory.CreateDirectory(dir);
            _logPath = Path.Combine(dir, "activity_log.dat");
            _events = SecureStore.Load<List<ActivityEventRecord>>(_logPath) ?? new List<ActivityEventRecord>();
        }

        /// <summary>Migration unique depuis scan/clean history + quarantaine actuelle.</summary>
        public void EnsureMigrated(QuarantineManager quarantine)
        {
            if (_migrationDone || _events.Count > 0)
            {
                _migrationDone = true;
                return;
            }

            foreach (var session in _logger.GetHistory())
                AppendInternal(CreateScanEvent(session), persist: false);

            foreach (var clean in _logger.GetCleanHistory())
                AppendInternal(CreateCleanEvent(clean), persist: false);

            foreach (var q in quarantine.GetEntries())
            {
                AppendInternal(new ActivityEventRecord
                {
                    Kind = ActivityEventKind.ThreatQuarantined,
                    OccurredAt = q.QuarantinedAt,
                    ScanSessionId = q.SourceSessionId ?? Guid.Empty,
                    QuarantineId = q.Id,
                    FilePath = q.OriginalPath,
                    VirusName = q.VirusName,
                    TargetSummary = q.FileName,
                    DetailSummary = q.SizeDisplay,
                }, persist: false);
            }

            Persist();
            _migrationDone = true;
            AppLogger.Info("ActivityLogService", $"Migration legacy → {_events.Count} événement(s)");
        }

        public void RecordScanCompleted(ScanSession session) =>
            AppendInternal(CreateScanEvent(session), persist: true);

        public void RecordCleanCompleted(CleanSession session) =>
            AppendInternal(CreateCleanEvent(session), persist: true);

        public void RecordThreatQuarantined(QuarantineEntry entry, Guid sourceSessionId = default)
        {
            AppendInternal(new ActivityEventRecord
            {
                Kind = ActivityEventKind.ThreatQuarantined,
                OccurredAt = entry.QuarantinedAt,
                ScanSessionId = sourceSessionId != Guid.Empty ? sourceSessionId : (entry.SourceSessionId ?? Guid.Empty),
                QuarantineId = entry.Id,
                FilePath = entry.OriginalPath,
                VirusName = entry.VirusName,
                TargetSummary = entry.FileName,
                DetailSummary = entry.SizeDisplay,
            }, persist: true);
        }

        public void RecordThreatRestored(QuarantineEntry entry)
        {
            AppendInternal(new ActivityEventRecord
            {
                Kind = ActivityEventKind.ThreatRestored,
                OccurredAt = DateTime.Now,
                ScanSessionId = entry.SourceSessionId ?? Guid.Empty,
                QuarantineId = entry.Id,
                FilePath = entry.OriginalPath,
                VirusName = entry.VirusName,
                TargetSummary = entry.FileName,
                DetailSummary = entry.SizeDisplay,
            }, persist: true);
        }

        public void RecordQuarantineDeleted(QuarantineEntry entry)
        {
            AppendInternal(new ActivityEventRecord
            {
                Kind = ActivityEventKind.QuarantineDeleted,
                OccurredAt = DateTime.Now,
                ScanSessionId = entry.SourceSessionId ?? Guid.Empty,
                QuarantineId = entry.Id,
                FilePath = entry.OriginalPath,
                VirusName = entry.VirusName,
                TargetSummary = entry.FileName,
                DetailSummary = entry.SizeDisplay,
            }, persist: true);
        }

        /// <summary>Timeline Historique — événements triés, résolution scan live via <see cref="ScanLogManager"/>.</summary>
        public IReadOnlyList<ActivityEntry> GetActivityFeed(QuarantineManager quarantine)
        {
            var scans = _logger.GetHistory().ToDictionary(s => s.SessionId);
            var activeIds = quarantine.GetEntries().Select(e => e.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var list = new List<ActivityEntry>(_events.Count);
            foreach (var ev in _events.OrderByDescending(e => e.OccurredAt))
            {
                var mapped = ActivityEntry.FromEvent(ev, scans, activeIds);
                if (mapped != null)
                    list.Add(mapped);
            }
            return list.AsReadOnly();
        }

        private static ActivityEventRecord CreateScanEvent(ScanSession session) => new()
        {
            Kind = ActivityEventKind.ScanCompleted,
            OccurredAt = session.StartedAt,
            ScanSessionId = session.SessionId,
            TargetSummary = session.TargetPath,
            DetailSummary = session.DurationDisplay,
            ResultSummary = session.ThreatsFound > 0
                ? session.ThreatsFound.ToString()
                : string.Empty,
        };

        private static ActivityEventRecord CreateCleanEvent(CleanSession session) => new()
        {
            Kind = ActivityEventKind.CleanCompleted,
            OccurredAt = session.StartedAt,
            TargetSummary = session.TargetsSummary ?? string.Empty,
            DetailSummary = session.DurationDisplay,
            ResultSummary = session.BytesDisplay ?? string.Empty,
            CleanSnapshot = session,
        };

        private void AppendInternal(ActivityEventRecord record, bool persist)
        {
            _events.Insert(0, record);
            Trim();
            if (persist)
                Persist();
        }

        /// <summary>
        /// Liste « plus récent en premier » : au-delà de <see cref="MaxActivityEvents"/>,
        /// supprime les entrées les plus anciennes (fin de liste), jamais les plus récentes.
        /// </summary>
        private void Trim()
        {
            if (_events.Count <= MaxActivityEvents) return;
            _events.RemoveRange(MaxActivityEvents, _events.Count - MaxActivityEvents);
        }

        private void Persist()
        {
            try
            {
                SecureStore.Save(_logPath, _events);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ActivityLogService", "Persist", ex);
            }
        }
    }
}
