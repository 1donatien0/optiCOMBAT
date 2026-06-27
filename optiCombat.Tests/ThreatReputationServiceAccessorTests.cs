using Moq;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ThreatReputationServiceAccessorTests
{
    [Fact]
    public async Task LookupFileAsync_without_api_key_returns_config_error()
    {
        var userPrefs = new UserPreferences { VirusTotalApiKey = string.Empty };
        var prefs = new Mock<IUserPreferencesAccessor>();
        prefs.SetupGet(p => p.Current).Returns(userPrefs);

        var service = new ThreatReputationService(preferences: prefs.Object);
        var result = await service.LookupFileAsync(@"C:\nonexistent\file.bin");

        Assert.False(result.Success);
        Assert.True(result.IsError);
    }
}
