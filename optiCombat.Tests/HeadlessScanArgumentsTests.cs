using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class HeadlessScanArgumentsTests
{
    [Theory]
    [InlineData(new[] { "--fullscan" }, HeadlessScanArguments.Mode.FullScan)]
    [InlineData(new[] { "--FULLSCAN", "--quiet" }, HeadlessScanArguments.Mode.FullScan)]
    [InlineData(new[] { "--quickscan" }, HeadlessScanArguments.Mode.QuickScan)]
    [InlineData(new[] { "--service-host" }, HeadlessScanArguments.Mode.ServiceHost)]
    [InlineData(new[] { "--guard" }, HeadlessScanArguments.Mode.Guard)]
    [InlineData(new string[0], HeadlessScanArguments.Mode.None)]
    public void ParseMode_returns_expected(string[] args, HeadlessScanArguments.Mode expected) =>
        Assert.Equal(expected, HeadlessScanArguments.ParseMode(args));

    [Fact]
    public void IsQuiet_detects_flag() =>
        Assert.True(HeadlessScanArguments.IsQuiet(new[] { "--fullscan", "--quiet" }));
}
