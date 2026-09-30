using optiCombat.Platform;

namespace optiCombat.Tests;

public sealed class ServiceHostRestartPolicyTests
{
  [Fact]
  public void Backoff_grows_with_consecutive_failures()
  {
    var policy = new ServiceHostRestartPolicy();
    var d0 = policy.GetBackoffDelay();
    policy.OnHostExit();
    var d1 = policy.GetBackoffDelay();
    policy.OnHostExit();
    var d2 = policy.GetBackoffDelay();

    Assert.True(d1 > d0);
    Assert.True(d2 >= d1);
    Assert.True(d2 <= TimeSpan.FromSeconds(ServiceHostRestartPolicy.MaxBackoffSeconds));
  }

  [Fact]
  public void OnHostHealthy_resets_consecutive_failures()
  {
    var policy = new ServiceHostRestartPolicy();
    policy.OnHostExit();
    policy.OnHostExit();
    policy.OnHostHealthy();

    Assert.Equal(0, policy.ConsecutiveFailures);
  }

  [Fact]
  public void CanRestart_false_after_max_restarts_per_hour()
  {
    var policy = new ServiceHostRestartPolicy();
    for (var i = 0; i < ServiceHostRestartPolicy.MaxRestartsPerHour; i++)
      policy.OnHostExit();

    Assert.False(policy.CanRestart());
  }
}
