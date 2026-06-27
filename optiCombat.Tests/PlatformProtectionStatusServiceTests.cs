using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class PlatformProtectionStatusServiceTests
{
  [Fact]
  public void Evaluate_returns_platform_components()
  {
    var report = PlatformProtectionStatusService.Evaluate();

    Assert.NotEmpty(report.Components);
    Assert.Contains(report.Components, c => c.LabelKey.StartsWith("Platform_", StringComparison.Ordinal));
    if (!PlatformProtectionFeatureGate.IsUserActivatable)
    {
      Assert.Single(report.Components);
      Assert.Equal("Platform_PlannedUnavailable", report.Components[0].LabelKey);
      Assert.False(report.HasWarnings);
    }
  }

  [Fact]
  public void IsAmsiProviderRegistered_false_when_key_missing()
  {
    var path = Path.Combine(Path.GetTempPath(), "missing_amsi.dll");
    Assert.False(PlatformProtectionStatusService.IsAmsiProviderRegistered(path));
  }
}
