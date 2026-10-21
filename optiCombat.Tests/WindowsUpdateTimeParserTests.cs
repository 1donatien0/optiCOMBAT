namespace optiCombat.Tests;

public sealed class WindowsUpdateTimeParserTests
{
    [Fact]
    public void TryParseWmiUtc14_parses_registry_style_timestamp()
    {
        var ok = optiCombat.Services.WindowsUpdateTimeParser.TryParseWmiUtc14(
            "20250315143000.000000+000",
            out var utc);

        Assert.True(ok);
        Assert.Equal(2025, utc.Year);
        Assert.Equal(3, utc.Month);
        Assert.Equal(15, utc.Day);
        Assert.Equal(DateTimeKind.Utc, utc.Kind);
    }
}
