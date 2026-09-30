using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ActivityEntryTests
{
    [Fact]
    public void FromScan_sets_target_and_pending_threats()
    {
        var session = new ScanSession
        {
            SessionId = Guid.NewGuid(),
            StartedAt = DateTime.Now,
            ScanTypeValue = ScanType.QuickScan,
            TargetPath = @"C:\Users",
            ThreatsFound = 1,
            Threats = { ThreatInfo.FromClamAv(@"C:\bad.exe", "X", 1) },
        };

        var entry = ActivityEntry.FromScan(session);
        Assert.Equal(@"C:\Users", entry.TargetDisplay);
        Assert.True(entry.HasPendingThreats);
    }

    [Fact]
    public void FromEvent_quarantine_event_maps_type_display()
    {
        var ev = new ActivityEventRecord
        {
            EventId = Guid.NewGuid(),
            Kind = ActivityEventKind.ThreatRestored,
            OccurredAt = DateTime.Now,
            FilePath = @"C:\f.dll",
            VirusName = "T",
            TargetSummary = "f.dll",
            DetailSummary = "1 Ko",
        };

        var entry = ActivityEntry.FromEvent(ev, new Dictionary<Guid, ScanSession>());
        Assert.NotNull(entry);
        Assert.Equal(ActivityKind.Quarantine, entry!.Kind);
        Assert.Contains("f.dll", entry.ResultSummary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FromEvent_without_active_ids_leaves_quarantined_stub_as_still_quarantined()
    {
        var quarantineId = "q-stub-1";
        var ev = new ActivityEventRecord
        {
            EventId = Guid.NewGuid(),
            Kind = ActivityEventKind.ThreatQuarantined,
            OccurredAt = DateTime.Now,
            QuarantineId = quarantineId,
            FilePath = @"C:\bad.exe",
            VirusName = "T",
            TargetSummary = "bad.exe",
        };

        var entry = ActivityEntry.FromEvent(ev, new Dictionary<Guid, ScanSession>());
        Assert.NotNull(entry);
        Assert.True(entry!.IsStillQuarantined);
    }

    [Fact]
    public void FromEvent_with_active_ids_reflects_live_quarantine_state()
    {
        var quarantineId = "q-live-1";
        var ev = new ActivityEventRecord
        {
            EventId = Guid.NewGuid(),
            Kind = ActivityEventKind.ThreatQuarantined,
            OccurredAt = DateTime.Now,
            QuarantineId = quarantineId,
            FilePath = @"C:\bad.exe",
            VirusName = "T",
            TargetSummary = "bad.exe",
        };
        var activeIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { quarantineId };

        var stillThere = ActivityEntry.FromEvent(ev, new Dictionary<Guid, ScanSession>(), activeIds);
        Assert.NotNull(stillThere);
        Assert.True(stillThere!.IsStillQuarantined);

        var removed = ActivityEntry.FromEvent(
            ev,
            new Dictionary<Guid, ScanSession>(),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        Assert.NotNull(removed);
        Assert.False(removed!.IsStillQuarantined);
    }
}
