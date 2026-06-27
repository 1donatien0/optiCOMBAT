using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ScanUserDisplayTests
{
    public ScanUserDisplayTests()
    {
        LocalizationService.ApplyCulture("fr-FR");
    }

    [Theory]
    [InlineData("[ClamAV] ClamAV : 120 fichiers analysés…", "120 fichiers analysés…")]
    [InlineData("[YARA] YARA — scan récursif de Temp", "Analyse en cours…")]
    [InlineData("Cible 2/5 : C:\\Users", "Zone 2/5 : C:\\Users")]
    public void ForProgressMessage_hides_engine_branding(string raw, string expected)
    {
        Assert.Equal(expected, ScanUserDisplay.ForProgressMessage(raw));
    }

    [Fact]
    public void SyncFileCountInMessage_replaces_local_count_with_cumulative()
    {
        var msg = ScanUserDisplay.SyncFileCountInMessage("50 fichiers analysés.", 12_120);
        Assert.Contains("12", msg);
        Assert.Contains("parcourus", msg, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ScanStarting_never_mentions_engine_names()
    {
        var msg = ScanUserDisplay.ScanStarting(ScanType.QuickScan);
        Assert.DoesNotContain("ClamAV", msg, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("YARA", msg, StringComparison.OrdinalIgnoreCase);
    }
}
