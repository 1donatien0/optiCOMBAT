using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ClamdEngineErrorLineTests
{
    [Theory]
    [InlineData(@"C:\Windows\locked.sys: Can't open file or directory ERROR")]
    [InlineData(@"C:\data\x.bin: lstat() failed: No such file or directory. ERROR")]
    [InlineData("UNKNOWN COMMAND")]
    [InlineData("COMMAND READ TIMED OUT")]
    public void IsClamdErrorLine_detects_errors(string line)
        => Assert.True(ClamdEngine.IsClamdErrorLine(line));

    [Theory]
    [InlineData(@"C:\temp\file.exe: OK")]
    [InlineData(@"C:\temp\eicar.com: Win.Test.EICAR_HDB-1 FOUND")]
    [InlineData(@"C:\temp\ERROR.txt: OK")]
    public void IsClamdErrorLine_ignores_verdicts(string line)
        => Assert.False(ClamdEngine.IsClamdErrorLine(line));
}
