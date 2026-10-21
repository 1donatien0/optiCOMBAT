using optiCombat.Services;

namespace optiCombat.Tests;

[Collection("OpticombatPrefs")]
public sealed class NotificationServiceTests
{
    [Fact]
    public void ResetActivationHookForTests_allows_second_instance_hook_semantics()
    {
        NotificationService.ResetActivationHookForTests();
        var first = new NotificationService();
        NotificationService.ResetActivationHookForTests();
        var second = new NotificationService();
        Assert.NotNull(first);
        Assert.NotNull(second);
    }

    [Fact]
    public void ShouldShowToast_respects_game_mode_suppression()
    {
        var prevGame = UserPreferences.Current.GameModeAutoEnabled;
        try
        {
            var svc = new NotificationService { IsEnabled = true };
            UserPreferences.Current.GameModeAutoEnabled = true;
            DistractionFreeMonitor.ResetForTests(active: true);

            Assert.False(svc.ShouldShowToast());
        }
        finally
        {
            UserPreferences.Current.GameModeAutoEnabled = prevGame;
            UserPreferences.Current.Save();
            DistractionFreeMonitor.ResetForTests();
        }
    }
}
