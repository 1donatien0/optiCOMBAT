using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ServiceHostThreatHandlerTests
{
    [Fact]
    public void OnThreatDetected_logs_when_auto_quarantine_disabled()
    {
        var root = Path.Combine(Path.GetTempPath(), "opticombat_threat_" + Guid.NewGuid().ToString("N"));
        var logger = new ScanLogManager(Path.Combine(root, "logs"));
        var context = new FakeThreatContext(
            new QuarantineManager(Path.Combine(root, "q")),
            logger,
            new CloudThreatIntelService(new FakeReputation()));

        var handler = new ServiceHostThreatHandler(
            context,
            new DefaultExclusionSettingsAccessor(),
            new DefaultUserPreferencesAccessor());
        var auto = ExclusionSettings.Current.AutoQuarantineEnabled;
        try
        {
            ExclusionSettings.Current.AutoQuarantineEnabled = false;
            handler.OnThreatDetected(this, new ThreatInfo
            {
                FilePath = @"C:\temp\evil.exe",
                VirusName = "Test.Evil",
            });
            Assert.Contains(logger.ReadLastLogLines(), line => line.Contains("ServiceHost") && line.Contains("Test.Evil"));
        }
        finally
        {
            ExclusionSettings.Current.AutoQuarantineEnabled = auto;
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    private sealed class FakeThreatContext(
        QuarantineManager quarantine,
        ScanLogManager logger,
        CloudThreatIntelService cloud) : IServiceHostThreatContext
    {
        public QuarantineManager Quarantine { get; } = quarantine;
        public ScanLogManager Logger { get; } = logger;
        public CloudThreatIntelService CloudThreatIntel { get; } = cloud;
    }

    private sealed class FakeReputation : IThreatReputationService
    {
        public Task<ThreatReputationService.ReputationResult> LookupFileAsync(string filePath, CancellationToken ct = default) =>
            Task.FromResult(new ThreatReputationService.ReputationResult());
    }
}
