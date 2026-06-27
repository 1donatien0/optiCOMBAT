using optiCombat.Platform;

namespace optiCombat.Tests;

public sealed class ProtectionPipeShutdownTokenTests
{
    [Fact]
    public void Validate_rejects_mismatch()
    {
        Assert.False(ProtectionPipeShutdownToken.Validate("abc", "xyz"));
        Assert.False(ProtectionPipeShutdownToken.Validate("abc", null));
    }

    [Fact]
    public void Validate_accepts_matching_token()
    {
        var token = ProtectionPipeShutdownToken.Generate();
        Assert.True(ProtectionPipeShutdownToken.Validate(token, token));
    }
}
