using Moq;
using optiCombat.Coordinators;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;
using optiCombat.ViewModels;

namespace optiCombat.Tests;

[Collection("OpticombatPrefs")]
public sealed class HistoryRemediationMoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "oc_histm_" + Guid.NewGuid().ToString("N"));
    private readonly QuarantineManager _q;
    private readonly ScanLogManager _logger;
    private readonly Mock<IHistoryServices> _history = new();
    private readonly ExclusionSettings _excl = new();
    private int _refreshes;

    public HistoryRemediationMoreTests()
    {
        Directory.CreateDirectory(_root);
        OpticombatDataRoots.TestRootOverride = _root;
        _q = new QuarantineManager(Path.Combine(_root, "q"), new FixedPreferencesAccessor(new UserPreferences()));
        _logger = new ScanLogManager(Path.Combine(_root, "log"));
        _history.SetupGet(h => h.Quarantine).Returns(_q);
        _history.SetupGet(h => h.Logger).Returns(_logger);
        _history.SetupGet(h => h.Actions).Returns(new AntivirusActions(_q, exclusions: new FixedExclusionsAccessor(_excl)));
    }

    public void Dispose()
    {
        OpticombatDataRoots.TestRootOverride = TestDataRoot.Session;
        try { Directory.Delete(_root, true); } catch { }
    }

    private string Sample(string name)
    {
        var p = Path.Combine(_root, name);
        File.WriteAllText(p, "x");
        return p;
    }

    private ScanSession Session(params string[] files)
    {
        var id = Guid.NewGuid();
        _logger.SaveScanResult(new ScanResult
        {
            SessionId = id,
            Type = ScanType.Folder,
            TargetPath = _root,
            Status = ScanStatus.Completed,
            Threats = files.Select(f => new ThreatInfo { FilePath = f, VirusName = "T" }).ToList(),
        });
        return _logger.GetHistory().Single(s => s.SessionId == id);
    }

    private HistoryViewModel Vm() => new(_history.Object);

    [Fact]
    public void QuarantineAll_skips_missing_files_and_refreshes_once()
    {
        var a = Sample("a.exe");
        var b = Sample("b.exe");
        var session = Session(a, b, Path.Combine(_root, "absent.exe"));

        HistoryThreatRemediationCoordinator.QuarantineAllThreats(_history.Object, Vm(), session, () => _refreshes++);

        Assert.Equal(1, _refreshes);
        Assert.Equal(2, _q.GetEntries().Count);
        Assert.False(File.Exists(a));

        var empty = Session();
        HistoryThreatRemediationCoordinator.QuarantineAllThreats(_history.Object, Vm(), empty, () => _refreshes++);
        Assert.Equal(1, _refreshes);
    }

    [Fact]
    public void Already_quarantined_file_is_just_removed_from_the_session()
    {
        var a = Sample("q.exe");
        var session = Session(a);
        HistoryThreatRemediationCoordinator.QuarantineThreat(_history.Object, Vm(), session, a, () => _refreshes++);
        Assert.Equal(1, _refreshes);

        var again = Session(a);
        HistoryThreatRemediationCoordinator.QuarantineThreat(_history.Object, Vm(), again, a, () => _refreshes++);
        Assert.Equal(2, _refreshes);
        Assert.Single(_q.GetEntries());
    }

    [Fact]
    public void Dismiss_ignore_and_delete_with_confirmation()
    {
        var a = Sample("d.exe");
        var b = Sample("i.exe");
        var c = Sample("del.exe");
        var session = Session(a, b, c);

        HistoryThreatRemediationCoordinator.DismissThreat(_history.Object, session, a, () => _refreshes++);
        HistoryThreatRemediationCoordinator.IgnoreThreat(_history.Object, session, b, () => _refreshes++);
        Assert.True(_excl.IsFileExcluded(b));

        var confirm = new RecordingConfirmService { Answer = false };
        HistoryThreatRemediationCoordinator.DeleteThreat(_history.Object, session, c, () => _refreshes++, confirm);
        Assert.True(File.Exists(c));
        confirm.Answer = true;
        HistoryThreatRemediationCoordinator.DeleteThreat(_history.Object, session, c, () => _refreshes++, confirm);
        Assert.False(File.Exists(c));
        Assert.Equal(3, _refreshes);
        Assert.Equal(2, confirm.Questions.Count);
    }
}
