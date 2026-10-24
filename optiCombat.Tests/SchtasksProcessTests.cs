using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary>Tâches planifiées (scan quotidien, watchdog) contre un « schtasks » factice.</summary>
public sealed class SchtasksProcessTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "oc_sch_" + Guid.NewGuid().ToString("N"));
    private readonly string _schtasks;

    public SchtasksProcessTests() => _schtasks = FakeTools.Install(_dir, "schtasks.exe");

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private ScheduledScanService Scheduled() => new(_schtasks, Path.Combine(_dir, "optiCombat.exe"));

    [Fact]
    public void CreateDailyScan_deletes_then_creates_a_limited_daily_task()
    {
        FakeTools.Script(_schtasks);
        Assert.True(Scheduled().CreateDailyScan(new TimeSpan(3, 5, 0)));

        var calls = FakeTools.Calls(_schtasks);
        Assert.Equal(new[] { "/Delete", "/Create" }, calls.Select(c => c[0]).ToArray());
        var create = calls[1];
        Assert.Contains("03:05", create);
        Assert.Contains("LIMITED", create);
        Assert.Contains(create, a => a.EndsWith("--fullscan --quiet", StringComparison.Ordinal));
    }

    [Fact]
    public void Failing_schtasks_is_reported()
    {
        FakeTools.Script(_schtasks, exit: 1, stderr: "ERREUR : accès refusé");
        var svc = Scheduled();
        Assert.False(svc.CreateDailyScan());
        Assert.False(svc.IsTaskExists());
        Assert.False(svc.RunNow());
        Assert.True(svc.DeleteTask()); // la suppression est best effort
    }

    [Fact]
    public void Next_run_is_read_from_task_xml()
    {
        FakeTools.Script(_schtasks, "1"); // /Query : la tâche existe
        FakeTools.Script(_schtasks, "2", stdout:
            "<?xml version=\"1.0\"?><Task><Triggers><CalendarTrigger><StartBoundary>2026-01-01T04:30:00</StartBoundary></CalendarTrigger></Triggers></Task>");
        var next = Scheduled().GetNextRunTime();
        Assert.NotNull(next);
        Assert.Equal(new TimeSpan(4, 30, 0), next!.Value.TimeOfDay);
    }

    [Fact]
    public void Next_run_falls_back_to_list_output_then_memory()
    {
        FakeTools.Script(_schtasks, "1");
        FakeTools.Script(_schtasks, "2", exit: 1);
        FakeTools.Script(_schtasks, "3", stdout: "Nom de la tâche: \\optiCombat_DailyScan\nNext Run Time: N/A\nNext Run Time: 12/31/2030 6:15:00 AM\n");
        var fromList = Scheduled().GetNextRunTime();
        Assert.NotNull(fromList);

        // Tâche absente : heure retenue en mémoire (02:00 par défaut).
        File.Delete(_schtasks + ".args");
        foreach (var f in Directory.GetFiles(_dir, "schtasks.exe.fake*"))
            File.Delete(f);
        FakeTools.Script(_schtasks, exit: 1);
        var fallback = Scheduled().GetNextRunTime();
        Assert.Equal(new TimeSpan(2, 0, 0), fallback!.Value.TimeOfDay);
        Assert.True(fallback > DateTime.Now);
    }

    [Fact]
    public void Missing_schtasks_never_throws()
    {
        var svc = new ScheduledScanService(Path.Combine(_dir, "absent.exe"), "x");
        Assert.False(svc.CreateDailyScan());
        Assert.False(svc.DeleteTask());
        Assert.False(svc.IsTaskExists());
        Assert.False(svc.RunNow());
        Assert.NotNull(svc.GetNextRunTime());
    }

    [Fact]
    public void Watchdog_task_follows_the_preference()
    {
        FakeTools.Script(_schtasks);
        var prefs = new UserPreferences { TamperProtectionEnabled = true };
        var tamper = new TamperProtectionService(new FixedPreferencesAccessor(prefs), new FixedExclusionsAccessor(new ExclusionSettings()))
        {
            SchtasksPath = _schtasks,
        };

        Assert.True(tamper.EnsureWatchdogTask());
        var calls = FakeTools.Calls(_schtasks);
        Assert.Equal(new[] { "/Delete", "/Create" }, calls.Select(c => c[0]).ToArray());
        Assert.Contains("MINUTE", calls[1]);
        Assert.Contains(calls[1], a => a.EndsWith("--watchdog --quiet", StringComparison.Ordinal));

        prefs.TamperProtectionEnabled = false;
        Assert.True(tamper.EnsureWatchdogTask()); // désactivé : suppression seule
        Assert.Equal("/Delete", FakeTools.Calls(_schtasks)[^1][0]);

        prefs.TamperProtectionEnabled = true;
        FakeTools.Script(_schtasks, exit: 1);
        Assert.False(tamper.EnsureWatchdogTask());

        tamper.SchtasksPath = Path.Combine(_dir, "absent.exe");
        Assert.False(tamper.EnsureWatchdogTask());
        Assert.False(tamper.DeleteWatchdogTask());
    }
}

public sealed class DefenderExclusionParsingTests
{
    [Theory]
    [InlineData(0, "OK:3", "Added", 3)]
    [InlineData(0, "OK:0", "AlreadyConfigured", 0)]
    [InlineData(0, "", "AlreadyConfigured", 0)]
    [InlineData(2, "DEFENDER_DISABLED", "DefenderUnavailable", 0)]
    [InlineData(3, "PREF_READ_FAILED", "AccessDenied", 0)]
    [InlineData(4, "bruit\nPARTIAL:PATH:C:\\x;ADDED=2", "PartialFailure", 2)]
    [InlineData(4, "PARTIAL:PROC:y", "PartialFailure", 0)]
    [InlineData(9, "inattendu", "PartialFailure", 0)]
    public void ParseResult_maps_script_output(int exit, string output, string status, int added)
    {
        var r = WindowsDefenderExclusionService.ParseResult(exit, output);
        Assert.Equal(status, r.Status.ToString());
        Assert.Equal(added, r.AddedCount);
    }

    [Fact]
    public void Ensure_is_not_applicable_off_windows()
    {
        // Jamais sous Windows : l'appel modifierait réellement les exclusions Defender du poste.
        if (OperatingSystem.IsWindows())
            return;
        Assert.Equal("NotApplicable", WindowsDefenderExclusionService.EnsureOpticombatExclusions().Status.ToString());
    }
}
