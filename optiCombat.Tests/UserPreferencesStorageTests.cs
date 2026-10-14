using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

[CollectionDefinition(nameof(UserPreferencesStorageTests), DisableParallelization = true)]
public sealed class UserPreferencesStorageTestsCollection;

[Collection(nameof(UserPreferencesStorageTests))]
public sealed class UserPreferencesStorageTests : IDisposable
{
    private readonly string _dir;
    private readonly string _dat;
    private readonly string _legacy;

    public UserPreferencesStorageTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "opticombat_prefs_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _dat = Path.Combine(_dir, "preferences.dat");
        _legacy = Path.Combine(_dir, "preferences.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    [Fact]
    public void LoadFromStorage_migrates_legacy_plaintext_json()
    {
        var legacy = new UserPreferences
        {
            TotalScansCount = 7,
            FavoriteScanType = ScanType.FullScan,
            DarkTheme = true
        };
        File.WriteAllText(_legacy, System.Text.Json.JsonSerializer.Serialize(legacy));

        var loaded = UserPreferences.LoadFromStorage(_dat, _legacy);

        Assert.Equal(7, loaded.TotalScansCount);
        Assert.Equal(ScanType.FullScan, loaded.FavoriteScanType);
        Assert.True(loaded.DarkTheme);
        Assert.True(File.Exists(_dat));
        Assert.True(File.Exists(_legacy + ".legacy") || !File.Exists(_legacy));
    }

    [Fact]
    public void SaveToStorage_concurrent_writes_do_not_throw()
    {
        var prefs = new UserPreferences { TotalScansCount = 1 };
        var errors = 0;
        Parallel.For(0, 8, _ =>
        {
            try
            {
                prefs.TotalScansCount++;
                UserPreferences.SaveToStorage(_dat, prefs);
            }
            catch
            {
                Interlocked.Increment(ref errors);
            }
        });

        Assert.Equal(0, errors);
        var loaded = UserPreferences.LoadFromStorage(_dat, _legacy);
        Assert.True(loaded.TotalScansCount >= 1);
    }
}
