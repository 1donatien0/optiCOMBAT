using optiCombat.Services;

namespace optiCombat.Tests;

[Collection("OpticombatPrefs")]
public sealed class DistractionFreeMonitorTests
{
    [Fact]
    public void ShouldSuppressNotifications_false_when_game_mode_disabled()
    {
        var prev = UserPreferences.Current.GameModeAutoEnabled;
        try
        {
            UserPreferences.Current.GameModeAutoEnabled = false;
            DistractionFreeMonitor.ResetForTests(active: true);

            Assert.False(DistractionFreeMonitor.ShouldSuppressNotifications());
        }
        finally
        {
            UserPreferences.Current.GameModeAutoEnabled = prev;
            UserPreferences.Current.Save();
            DistractionFreeMonitor.ResetForTests();
        }
    }

    [Fact]
    public void ShouldSuppressNotifications_true_when_active_and_enabled()
    {
        var prev = UserPreferences.Current.GameModeAutoEnabled;
        try
        {
            UserPreferences.Current.GameModeAutoEnabled = true;
            DistractionFreeMonitor.ResetForTests(active: true);

            Assert.True(DistractionFreeMonitor.ShouldSuppressNotifications());
        }
        finally
        {
            UserPreferences.Current.GameModeAutoEnabled = prev;
            UserPreferences.Current.Save();
            DistractionFreeMonitor.ResetForTests();
        }
    }

    [Theory]
    [InlineData("steam", true)]
    [InlineData("valorant-win64-shipping", true)]
    [InlineData("notepad", false)]
    [InlineData("GameBar", false)]
    public void IsKnownGameProcessName_matches_allowlist_only(string name, bool expected)
    {
        Assert.Equal(expected, DistractionFreeMonitor.IsKnownGameProcessName(name));
    }

    [Fact]
    public void Stop_clears_active_state()
    {
        DistractionFreeMonitor.ResetForTests(active: true);
        Assert.True(DistractionFreeMonitor.IsActive);

        DistractionFreeMonitor.Stop();
        Assert.False(DistractionFreeMonitor.IsActive);
    }
}
