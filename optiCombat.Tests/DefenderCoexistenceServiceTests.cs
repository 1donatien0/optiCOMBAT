using Moq;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class DefenderCoexistenceServiceTests
{
  [Theory]
  [InlineData(true, false)]
  [InlineData(false, true)]
  public void Apply_toggles_realtime_and_process_monitor(bool complement, bool expectedProtection)
  {
    var prefs = new UserPreferences();
    var accessor = new Mock<IUserPreferencesAccessor>();
    accessor.SetupGet(a => a.Current).Returns(prefs);
    bool? rtp = null, monitor = null;

    DefenderCoexistenceService.Apply(complement, accessor.Object, v => rtp = v, v => monitor = v);

    Assert.Equal(complement, prefs.DefenderComplementModeEnabled);
    Assert.Equal(expectedProtection, rtp);
    Assert.Equal(expectedProtection, monitor);
  }

  [Fact]
  public void Complement_mode_is_off_by_default()
  {
    Assert.False(new UserPreferences().DefenderComplementModeEnabled);
  }
}
