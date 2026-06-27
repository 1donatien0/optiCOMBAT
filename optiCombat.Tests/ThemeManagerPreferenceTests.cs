using optiCombat;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ThemeManagerPreferenceTests
{
    [Theory]
    [InlineData(false, true, true, true)]
    [InlineData(false, false, false, true)]
    [InlineData(true, true, true, false)]
    [InlineData(false, true, false, false)]
    public void TryMigrateToWindowsThemeSync_only_when_legacy_manual_matches_windows(
        bool syncWindows, bool storedDark, bool windowsDark, bool expectedMigrate)
    {
        var prefs = new UserPreferences { SyncWindowsTheme = syncWindows, DarkTheme = storedDark };

        bool migrated = ThemeManager.TryMigrateToWindowsThemeSync(prefs, windowsDark);

        Assert.Equal(expectedMigrate, migrated);
        if (expectedMigrate)
            Assert.True(prefs.SyncWindowsTheme);
    }
}
