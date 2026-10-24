using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

public sealed class ServiceHostThreatHandlerMoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "oc_shth_" + Guid.NewGuid().ToString("N"));
    private readonly ScanLogManager _logger;
    private readonly QuarantineManager _q;

    public ServiceHostThreatHandlerMoreTests()
    {
        Directory.CreateDirectory(_root);
        _logger = new ScanLogManager(Path.Combine(_root, "logs"));
        _q = new QuarantineManager(Path.Combine(_root, "q"), new FixedPreferencesAccessor(new UserPreferences()));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, true); } catch { }
    }

    private ServiceHostThreatHandler Create(string? cloudSummary, bool autoQuarantine = true) =>
        new(new Context(_q, _logger, new CloudThreatIntelService(new Reputation(cloudSummary))),
            new FixedExclusionsAccessor(new ExclusionSettings { AutoQuarantineEnabled = autoQuarantine }),
            new FixedPreferencesAccessor(new UserPreferences { BackupBeforeQuarantine = false }));

    [Fact]
    public void Auto_quarantine_remediates()
    {
        var file = Path.Combine(_root, "evil.exe");
        File.WriteAllText(file, "payload");

        Create("12/70 malveillants").OnThreatDetected(this, new ThreatInfo { FilePath = file, VirusName = "Test.Evil", FileSize = 7 });

        Assert.Single(_q.GetEntries());
        Assert.False(File.Exists(file));
        Assert.Contains(_logger.ReadLastLogLines(), l => l.Contains("Remédiation", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Without_auto_quarantine_the_cloud_reputation_is_logged()
    {
        var file = Path.Combine(_root, "kept.exe");
        File.WriteAllText(file, "payload");

        Create("12/70 malveillants", autoQuarantine: false)
            .OnThreatDetected(this, new ThreatInfo { FilePath = file, VirusName = "Test.Kept" });

        Assert.True(File.Exists(file));
        await Eventually.TrueAsync(() => _logger.ReadLastLogLines().Any(l => l.Contains("12/70", StringComparison.Ordinal)));
    }

    [Fact]
    public void Failed_quarantine_is_logged_and_empty_reputation_is_silent()
    {
        var missing = Path.Combine(_root, "absent.exe");
        Create(null).OnThreatDetected(this, new ThreatInfo { FilePath = missing, VirusName = "X" });
        Assert.Empty(_q.GetEntries());
        Assert.Contains(_logger.ReadLastLogLines(), l => l.Contains("Remédiation", StringComparison.Ordinal));
        Assert.DoesNotContain(_logger.ReadLastLogLines(), l => l.Contains("Réputation cloud", StringComparison.Ordinal));
    }

    [Fact]
    public void Repair_without_preferences_uses_defaults_and_defender_scan_handles_absence()
    {
        var r = ThreatRepairService.TryRemediate(new ThreatInfo { FilePath = Path.Combine(_root, "none.exe") }, _q,
            new FixedPreferencesAccessor(new UserPreferences()));
        Assert.False(r.Success);
        if (!OperatingSystem.IsWindows())
            Assert.False(ThreatRepairService.TryDefenderTargetedScan(Path.Combine(_root, "none.exe")).Success);
    }

    private sealed class Context(QuarantineManager q, ScanLogManager logger, CloudThreatIntelService cloud) : IServiceHostThreatContext
    {
        public QuarantineManager Quarantine { get; } = q;

        public ScanLogManager Logger { get; } = logger;

        public CloudThreatIntelService CloudThreatIntel { get; } = cloud;
    }

    private sealed class Reputation(string? summary) : IThreatReputationService
    {
        public Task<ThreatReputationService.ReputationResult> LookupFileAsync(string filePath, CancellationToken ct = default) =>
            Task.FromResult(new ThreatReputationService.ReputationResult { Success = summary != null, Summary = summary ?? "" });
    }
}
