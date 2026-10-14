using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

[Collection("Localization")]
public sealed class OverviewProtectionStatsFormatterTests
{
    public OverviewProtectionStatsFormatterTests() => LocalizationService.ApplyCulture("fr-FR");
    private static ScanSession Session(int daysAgo, int threats = 0, int files = 100) =>
        new()
        {
            StartedAt = DateTime.Now.AddDays(-daysAgo),
            ThreatsFound = threats,
            FilesScanned = files,
        };

    [Fact]
    public void Format_no_history_suggests_antivirus_scan()
    {
        var text = OverviewProtectionStatsFormatter.Format(Array.Empty<ScanSession>(), 0, DateTime.Now);

        Assert.Contains("Antivirus", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Historique", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Format_threats_in_30_days_includes_treat_hint()
    {
        var history = new[] { Session(daysAgo: 3, threats: 2) };
        var text = OverviewProtectionStatsFormatter.Format(history, 1, DateTime.Now);

        Assert.Contains("2", text);
        Assert.Contains("Historique", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Format_old_scans_only_uses_none30_message()
    {
        var history = new[] { Session(daysAgo: 60, threats: 5) };
        var text = OverviewProtectionStatsFormatter.Format(history, 1, DateTime.Now);

        Assert.DoesNotContain("menace", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("30", text);
    }
}
