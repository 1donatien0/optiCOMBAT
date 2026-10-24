using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

[Collection("OpticombatPrefs")]
public sealed class AntivirusActionsMoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "oc_actm_" + Guid.NewGuid().ToString("N"));
    private readonly ExclusionSettings _excl = new();
    private readonly QuarantineManager _q;
    private readonly Canceller _fresh = new();
    private readonly Canceller _rules = new();

    public AntivirusActionsMoreTests()
    {
        Directory.CreateDirectory(_root);
        OpticombatDataRoots.TestRootOverride = _root; // ExclusionSettings.Save() reste dans le dossier de test
        _q = new QuarantineManager(Path.Combine(_root, "q"), new FixedPreferencesAccessor(new UserPreferences()));
    }

    public void Dispose()
    {
        OpticombatDataRoots.TestRootOverride = TestDataRoot.Session;
        try { Directory.Delete(_root, true); } catch { }
    }

    private AntivirusActions Create(Func<string, ThreatInfo?>? lookup = null) =>
        new(_q, _fresh, _rules, lookup, new FixedExclusionsAccessor(_excl));

    private string Sample(string name)
    {
        var p = Path.Combine(_root, name);
        File.WriteAllText(p, "payload");
        return p;
    }

    [Fact]
    public void Quarantine_uses_known_threat_then_reports_already_quarantined()
    {
        var file = Sample("known.exe");
        var actions = Create(p => new ThreatInfo { FilePath = p, VirusName = "Known.Sig", FileSize = -1 });
        var results = new List<ActionResult>();
        actions.ActionCompleted += (_, r) => results.Add(r);

        Assert.True(actions.QuarantineThreat(file).Success);
        Assert.Equal("Known.Sig", Assert.Single(_q.GetEntries()).VirusName);

        File.WriteAllText(file, "recréé");
        var again = actions.QuarantineThreat(file);
        Assert.True(again.Success);
        Assert.True(again.IsWarning);
        Assert.Equal(2, results.Count);
    }

    [Fact]
    public void Quarantine_rejects_empty_and_missing_paths()
    {
        var actions = Create();
        Assert.True(actions.QuarantineThreat(new ThreatInfo { FilePath = "" }).IsError);
        var missing = actions.QuarantineThreat(Path.Combine(_root, "absent.exe"));
        Assert.False(missing.Success);
        Assert.True(missing.IsError);
    }

    [Fact]
    public void Quarantine_fills_default_name_and_size()
    {
        var file = Sample("unnamed.bin");
        var threat = new ThreatInfo { FilePath = file, VirusName = " ", FileSize = -1 };
        Assert.True(Create().QuarantineThreat(threat).Success);
        Assert.Equal(7, threat.FileSize);
        Assert.False(string.IsNullOrWhiteSpace(threat.VirusName));
    }

    [Fact]
    public void Ignore_adds_an_exclusion_once()
    {
        var file = Sample("ignore.exe");
        var actions = Create();
        Assert.True(actions.IgnoreThreat(file).Success);
        Assert.True(_excl.IsFileExcluded(file));
        var again = actions.IgnoreThreat(file);
        Assert.True(again.Success);
        Assert.True(again.IsWarning);
        Assert.True(actions.IgnoreThreat("  ").IsError);
    }

    [Fact]
    public void Delete_clears_read_only_attribute_and_reports_missing_file()
    {
        var file = Sample("ro.exe");
        File.SetAttributes(file, FileAttributes.ReadOnly);
        var actions = Create();
        Assert.True(actions.DeleteThreatFile(file).Success);
        Assert.False(File.Exists(file));
        Assert.False(actions.DeleteThreatFile(Path.Combine(_root, "absent.exe")).Success);
    }

    private sealed class Canceller : ISignatureUpdateCanceller
    {
        public int Cancels { get; private set; }

        public void CancelUpdate() => Cancels++;
    }
}
