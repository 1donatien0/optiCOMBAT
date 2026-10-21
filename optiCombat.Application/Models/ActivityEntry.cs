using optiCombat.Localization;
using optiCombat.Services;
using System.Globalization;
using System.IO;

namespace optiCombat.Models
{
    public enum ActivityKind { Scan, Clean, Quarantine }

    /// <summary>
    /// Entree unifiee de la timeline Historique, materialisee depuis le journal d'activite.
    /// </summary>
    public sealed class ActivityEntry
    {
        public Guid EventId { get; init; }
        public ActivityKind Kind { get; init; }
        public ActivityEventKind? EventKind { get; init; }
        public DateTime StartedAt { get; init; }
        public DateTime? FinishedAt { get; init; }
        public string TypeDisplay { get; init; } = string.Empty;
        public string TargetDisplay { get; init; } = string.Empty;
        public string DetailDisplay { get; init; } = string.Empty;
        public string ResultSummary { get; init; } = string.Empty;
        public bool HasThreats { get; init; }
        /// <summary>Menaces encore actionnables dans la session (liste non vide).</summary>
        public bool HasPendingThreats { get; init; }
        public bool IsClean => Kind == ActivityKind.Scan && !HasThreats;
        public string DurationDisplay => DetailDisplay;
        public ScanSession? ScanSession { get; init; }
        public CleanSession? CleanSession { get; init; }
        public QuarantineEntry? QuarantineEntry { get; init; }
        /// <summary>Quarantaine live si le fichier est encore isole.</summary>
        public bool IsStillQuarantined { get; init; }

        public IReadOnlyList<ThreatInfo> Threats =>
            ScanSession?.Threats is { Count: > 0 } t ? t : Array.Empty<ThreatInfo>();
        public int ThreatsFound => ScanSession?.ThreatsFound ?? 0;
        public Guid ScanSessionId => ScanSession?.SessionId ?? Guid.Empty;

        public static ActivityEntry? FromEvent(
            ActivityEventRecord ev,
            IReadOnlyDictionary<Guid, ScanSession> scansById,
            IReadOnlySet<string>? activeQuarantineIds = null)
        {
            var entry = ev.Kind switch
            {
                ActivityEventKind.ScanCompleted => FromScanEvent(ev, scansById),
                ActivityEventKind.CleanCompleted => FromCleanEvent(ev),
                ActivityEventKind.ThreatQuarantined => FromQuarantineEvent(ev, "Hist_ChipQuarantine"),
                ActivityEventKind.ThreatRestored => FromQuarantineEvent(ev, "Hist_EventRestored"),
                ActivityEventKind.QuarantineDeleted => FromQuarantineEvent(ev, "Hist_EventQuarantineDeleted"),
                _ => null,
            };

            if (entry?.QuarantineEntry == null || activeQuarantineIds == null)
                return entry;

            if (entry.EventKind == ActivityEventKind.ThreatQuarantined)
            {
                return new ActivityEntry
                {
                    EventId = entry.EventId,
                    Kind = entry.Kind,
                    EventKind = entry.EventKind,
                    StartedAt = entry.StartedAt,
                    FinishedAt = entry.FinishedAt,
                    TypeDisplay = entry.TypeDisplay,
                    TargetDisplay = entry.TargetDisplay,
                    DetailDisplay = entry.DetailDisplay,
                    ResultSummary = entry.ResultSummary,
                    QuarantineEntry = entry.QuarantineEntry,
                    IsStillQuarantined = activeQuarantineIds.Contains(entry.QuarantineEntry.Id),
                };
            }

            return entry;
        }

        private static ActivityEntry? FromScanEvent(
            ActivityEventRecord ev,
            IReadOnlyDictionary<Guid, ScanSession> scansById)
        {
            if (ev.ScanSessionId == Guid.Empty || !scansById.TryGetValue(ev.ScanSessionId, out var session))
                return null;

            return FromScan(session, ev.EventId);
        }

        private static ActivityEntry FromCleanEvent(ActivityEventRecord ev)
        {
            var session = ev.CleanSnapshot;
            if (session != null)
                return FromClean(session, ev.EventId);

            return new ActivityEntry
            {
                EventId = ev.EventId,
                Kind = ActivityKind.Clean,
                EventKind = ActivityEventKind.CleanCompleted,
                StartedAt = ev.OccurredAt,
                FinishedAt = ev.OccurredAt,
                TypeDisplay = LocalizationService.GetString("Hist_TabCleans"),
                TargetDisplay = ev.TargetSummary,
                DetailDisplay = ev.DetailSummary,
                ResultSummary = ev.ResultSummary,
            };
        }

        private static ActivityEntry FromQuarantineEvent(ActivityEventRecord ev, string typeKey)
        {
            var stub = new QuarantineEntry
            {
                Id = ev.QuarantineId,
                OriginalPath = ev.FilePath,
                VirusName = ev.VirusName,
                QuarantinedAt = ev.OccurredAt,
                SourceSessionId = ev.ScanSessionId != Guid.Empty ? ev.ScanSessionId : null,
            };

            return new ActivityEntry
            {
                EventId = ev.EventId,
                Kind = ActivityKind.Quarantine,
                EventKind = ev.Kind,
                StartedAt = ev.OccurredAt,
                FinishedAt = ev.OccurredAt,
                TypeDisplay = LocalizationService.GetString(typeKey),
                TargetDisplay = string.IsNullOrWhiteSpace(ev.TargetSummary)
                    ? Path.GetFileName(ev.FilePath)
                    : ev.TargetSummary,
                DetailDisplay = ev.DetailSummary,
                ResultSummary = QuarantineResultSummary(ev),
                QuarantineEntry = stub,
                IsStillQuarantined = ev.Kind == ActivityEventKind.ThreatQuarantined,
            };
        }

        public static ActivityEntry FromScan(ScanSession session, Guid eventId = default)
        {
            string result = session.ThreatsFound > 0
                ? LocalizationService.Format("Hist_InfoThreats", session.ThreatsFound)
                : LocalizationService.GetString("Hist_InfoClean");

            var pending = session.Threats.Count > 0;

            return new ActivityEntry
            {
                EventId = eventId == Guid.Empty ? session.SessionId : eventId,
                Kind = ActivityKind.Scan,
                EventKind = ActivityEventKind.ScanCompleted,
                StartedAt = session.StartedAt,
                FinishedAt = session.FinishedAt,
                TypeDisplay = session.TypeDisplay,
                TargetDisplay = session.TargetPath,
                DetailDisplay = session.DurationDisplay,
                ResultSummary = result,
                HasThreats = session.ThreatsFound > 0,
                HasPendingThreats = pending,
                ScanSession = session,
            };
        }

        public static ActivityEntry FromClean(CleanSession session, Guid eventId = default)
        {
            return new ActivityEntry
            {
                EventId = eventId == Guid.Empty ? Guid.NewGuid() : eventId,
                Kind = ActivityKind.Clean,
                EventKind = ActivityEventKind.CleanCompleted,
                StartedAt = session.StartedAt,
                FinishedAt = session.FinishedAt,
                TypeDisplay = LocalizationService.GetString("Hist_TabCleans"),
                TargetDisplay = session.TargetsSummary ?? string.Empty,
                DetailDisplay = session.DurationDisplay,
                ResultSummary = session.BytesDisplay,
                CleanSession = session,
            };
        }

        public string IconKind => Kind switch
        {
            ActivityKind.Clean => "Broom",
            ActivityKind.Quarantine when EventKind == ActivityEventKind.ThreatRestored => "BackupRestore",
            ActivityKind.Quarantine when EventKind == ActivityEventKind.QuarantineDeleted => "TrashCanOutline",
            ActivityKind.Quarantine => "ShieldLock",
            _ when HasThreats => "ShieldAlert",
            _ => "ShieldCheck",
        };

        public string IconBrushKey => Kind switch
        {
            ActivityKind.Clean => "TextAccent",
            ActivityKind.Quarantine when EventKind == ActivityEventKind.ThreatRestored => "SuccessGreen",
            ActivityKind.Quarantine when EventKind == ActivityEventKind.QuarantineDeleted => "DangerRed",
            ActivityKind.Quarantine => "WarningOrange",
            _ when HasThreats => "DangerRed",
            _ => "SuccessGreen",
        };

        public string DateDisplay =>
            StartedAt.ToString("dd/MM/yyyy HH:mm", CultureInfo.CurrentCulture);

        private static string QuarantineResultSummary(ActivityEventRecord ev)
        {
            var fileName = Path.GetFileName(ev.FilePath);
            if (!string.IsNullOrWhiteSpace(ev.ResultSummary))
                return ev.ResultSummary;

            return ev.Kind switch
            {
                ActivityEventKind.ThreatRestored =>
                    LocalizationService.Format("Hist_InfoRestored", fileName),
                ActivityEventKind.QuarantineDeleted =>
                    LocalizationService.Format("Hist_InfoQuarantineDeleted", fileName),
                _ => LocalizationService.Format("Hist_InfoQuarantined", ev.VirusName, fileName),
            };
        }
    }
}
