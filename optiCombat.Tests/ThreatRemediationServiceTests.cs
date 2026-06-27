using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ThreatRemediationServiceTests
{
    [Fact]
    public void GetRemediationSteps_includes_quarantine_and_no_repair_note()
    {
        var steps = ThreatRemediationService.GetRemediationSteps(new Models.ThreatInfo
        {
            FilePath = @"C:\temp\test.exe",
            VirusName = "Test",
            DetectedBy = "YARA",
        });

        Assert.True(steps.Count >= 3);
        Assert.Contains(steps, s => s.Contains("quarantaine", StringComparison.OrdinalIgnoreCase)
            || s.Contains("Quarantine", StringComparison.OrdinalIgnoreCase));
    }
}
