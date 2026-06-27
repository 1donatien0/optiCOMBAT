namespace optiCombat.Models
{
    /// <summary>Type d'événement immuable enregistré dans <see cref="Services.ActivityLogService"/>.</summary>
    public enum ActivityEventKind
    {
        ScanCompleted = 0,
        CleanCompleted = 1,
        ThreatQuarantined = 2,
        ThreatRestored = 3,
        QuarantineDeleted = 4,
    }
}
