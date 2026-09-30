using optiCombat.Localization;
using optiCombat.Models;

namespace optiCombat.Tests;

/// <summary>
/// Vérifie que ScanDisplayFormatter.FormatDuration retourne les unités
/// correctes selon la culture UI active.
/// </summary>
public sealed class ScanDisplayFormatterTests : IDisposable
{
    public ScanDisplayFormatterTests()
    {
        LocalizationService.ApplyCulture("fr-FR");
    }

    public void Dispose()
    {
        LocalizationService.ApplyCulture("fr-FR");
    }

    // ── FR ────────────────────────────────────────────────────────────────────

    [Fact]
    public void FormatDuration_fr_less_than_one_second()
    {
        LocalizationService.ApplyCulture("fr-FR");
        var result = ScanDisplayFormatter.FormatDuration(TimeSpan.FromMilliseconds(500));
        Assert.Equal("moins d'1 s", result);
    }

    [Fact]
    public void FormatDuration_fr_seconds_only()
    {
        LocalizationService.ApplyCulture("fr-FR");
        var result = ScanDisplayFormatter.FormatDuration(TimeSpan.FromSeconds(45));
        Assert.Equal("45 s", result);
    }

    [Fact]
    public void FormatDuration_fr_minutes_and_seconds()
    {
        LocalizationService.ApplyCulture("fr-FR");
        var result = ScanDisplayFormatter.FormatDuration(TimeSpan.FromSeconds(125));
        Assert.Equal("2 min 5 s", result);
    }

    [Fact]
    public void FormatDuration_fr_hours_minutes_seconds()
    {
        LocalizationService.ApplyCulture("fr-FR");
        var result = ScanDisplayFormatter.FormatDuration(TimeSpan.FromSeconds(3723));
        Assert.Equal("1 h 2 min 3 s", result);
    }

    // ── EN ────────────────────────────────────────────────────────────────────

    [Fact]
    public void FormatDuration_en_less_than_one_second()
    {
        LocalizationService.ApplyCulture("en-US");
        var result = ScanDisplayFormatter.FormatDuration(TimeSpan.FromMilliseconds(500));
        Assert.Equal("< 1 s", result);
    }

    [Fact]
    public void FormatDuration_en_seconds_only()
    {
        LocalizationService.ApplyCulture("en-US");
        var result = ScanDisplayFormatter.FormatDuration(TimeSpan.FromSeconds(45));
        Assert.Equal("45 s", result);
    }

    [Fact]
    public void FormatDuration_en_minutes_and_seconds()
    {
        LocalizationService.ApplyCulture("en-US");
        var result = ScanDisplayFormatter.FormatDuration(TimeSpan.FromSeconds(125));
        Assert.Equal("2 min 5 s", result);
    }

    [Fact]
    public void FormatDuration_en_hours_minutes_seconds()
    {
        LocalizationService.ApplyCulture("en-US");
        var result = ScanDisplayFormatter.FormatDuration(TimeSpan.FromSeconds(3723));
        Assert.Equal("1 h 2 min 3 s", result);
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    [Fact]
    public void FormatDuration_negative_treated_as_zero()
    {
        LocalizationService.ApplyCulture("fr-FR");
        var result = ScanDisplayFormatter.FormatDuration(TimeSpan.FromSeconds(-10));
        Assert.Equal("moins d'1 s", result);
    }

    [Fact]
    public void FormatDuration_exact_minute()
    {
        LocalizationService.ApplyCulture("fr-FR");
        var result = ScanDisplayFormatter.FormatDuration(TimeSpan.FromMinutes(3));
        Assert.Equal("3 min", result);
    }

    [Fact]
    public void FormatDuration_exact_hour()
    {
        LocalizationService.ApplyCulture("fr-FR");
        var result = ScanDisplayFormatter.FormatDuration(TimeSpan.FromHours(2));
        Assert.Equal("2 h", result);
    }
}
