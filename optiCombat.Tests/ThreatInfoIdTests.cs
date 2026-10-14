using optiCombat.Models;

namespace optiCombat.Tests;

public class ThreatInfoIdTests
{
    [Fact]
    public void Id_IsDeterministic_ForSameThreatFields()
    {
        var at = new DateTime(2026, 5, 22, 14, 30, 0);
        var a = new ThreatInfo
        {
            FilePath = @"C:\temp\evil.exe",
            VirusName = "Win.Test",
            DetectedAt = at,
            DetectedBy = "ClamAV",
        };
        var otherPath = new ThreatInfo
        {
            FilePath = @"C:\temp\other.exe",
            VirusName = "Win.Test",
            DetectedAt = at,
        };

        Assert.Equal(a.Id, new ThreatInfo
        {
            FilePath = a.FilePath,
            VirusName = a.VirusName,
            DetectedAt = a.DetectedAt,
        }.Id);
        Assert.NotEqual(a.Id, otherPath.Id);
        Assert.Equal(16, a.Id.Length);
    }
}
