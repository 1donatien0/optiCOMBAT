using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class PlatformProtectionFeatureGateTests
{
    [Fact]
    public void IsUserActivatable_is_false_while_driver_signing_pending()
    {
        Assert.False(PlatformProtectionFeatureGate.IsUserActivatable);
    }

    [Fact]
    public void NormalizePreferences_clears_platform_flag_when_not_activatable()
    {
        var dir = Path.Combine(Path.GetTempPath(), "opticombat_gate_" + Guid.NewGuid().ToString("N"));
        var securePath = Path.Combine(dir, "preferences.dat");
        try
        {
            var prefs = new UserPreferences { UsePlatformProtectionService = true };
            UserPreferences.SaveToStorage(securePath, prefs);

            var loaded = UserPreferences.LoadFromStorage(securePath, Path.Combine(dir, "legacy.json"));

            Assert.False(loaded.UsePlatformProtectionService);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }
}
