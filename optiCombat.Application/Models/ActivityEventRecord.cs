namespace optiCombat.Models
{
    /// <summary>Événement persisté du journal d'activité unifié (Historique).</summary>
    public sealed class ActivityEventRecord
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public ActivityEventKind Kind { get; set; }
        public DateTime OccurredAt { get; set; }

        /// <summary>Scan source pour menaces / quarantaine.</summary>
        public Guid ScanSessionId { get; set; }

        /// <summary>Identifiant quarantaine (ThreatQuarantined / Restored / Deleted).</summary>
        public string QuarantineId { get; set; } = string.Empty;

        public string FilePath { get; set; } = string.Empty;
        public string VirusName { get; set; } = string.Empty;
        public string TargetSummary { get; set; } = string.Empty;
        public string DetailSummary { get; set; } = string.Empty;
        public string ResultSummary { get; set; } = string.Empty;

        /// <summary>Snapshot nettoyage (détail panneau bas).</summary>
        public CleanSession? CleanSnapshot { get; set; }
    }
}
