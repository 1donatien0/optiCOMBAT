using optiCombat.Localization;
using optiCombat.Services;

namespace optiCombat.Tests;

[CollectionDefinition(nameof(UserPreferencesStorageTests), DisableParallelization = true)]
public sealed class LocalizationServiceTestsCollection;

[Collection(nameof(UserPreferencesStorageTests))]
public sealed class LocalizationServiceTests : IDisposable
{
    private readonly string _dir;
    private readonly string _dat;
    private readonly string _legacy;

    public LocalizationServiceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "opticombat_loc_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _dat = Path.Combine(_dir, "preferences.dat");
        _legacy = Path.Combine(_dir, "preferences.json");
        LocalizationService.ApplyCulture("fr-FR");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
        LocalizationService.ApplyCulture("fr-FR");
    }

    [Fact]
    public void English_culture_returns_english_nav_labels()
    {
        LocalizationService.ApplyCulture("en-US");
        Assert.Equal("Home", LocalizationService.GetString("Nav_Home"));
        Assert.Equal("Antivirus", LocalizationService.GetString("Nav_Antivirus"));
        Assert.True(LocalizationService.IsEnglish);
    }

    [Fact]
    public void French_culture_returns_french_nav_labels()
    {
        LocalizationService.ApplyCulture("fr-FR");
        Assert.Equal("Accueil", LocalizationService.GetString("Nav_Home"));
        Assert.False(LocalizationService.IsEnglish);
    }

    [Fact]
    public void NormalizeCulture_maps_short_names()
    {
        LocalizationService.ApplyCulture("en");
        Assert.True(LocalizationService.IsEnglish);
        LocalizationService.ApplyCulture("fr");
        Assert.False(LocalizationService.IsEnglish);
    }

    [Fact]
    public void Resx_FR_and_EN_have_same_keys()
    {
        // Charge les deux fichiers resx et vérifie la parité des clés.
        var assembly = typeof(LocalizationService).Assembly;

        var frKeys  = GetResxKeys(assembly, "optiCombat.Resources.UiStrings",    "fr-FR");
        var enKeys  = GetResxKeys(assembly, "optiCombat.Resources.UiStrings",    "en-US");

        var missingInEn = frKeys.Except(enKeys).OrderBy(k => k).ToList();
        var missingInFr = enKeys.Except(frKeys).OrderBy(k => k).ToList();

        Assert.True(missingInEn.Count == 0,
            $"Clés présentes en FR mais absentes en EN ({missingInEn.Count}) :\n{string.Join("\n", missingInEn)}");
        Assert.True(missingInFr.Count == 0,
            $"Clés présentes en EN mais absentes en FR ({missingInFr.Count}) :\n{string.Join("\n", missingInFr)}");
    }

    private static HashSet<string> GetResxKeys(System.Reflection.Assembly asm, string baseName, string culture)
    {
        var rm = new System.Resources.ResourceManager(baseName, asm);
        var ci = System.Globalization.CultureInfo.GetCultureInfo(culture);
        using var rs = rm.GetResourceSet(ci, createIfNotExists: true, tryParents: false);
        if (rs == null) return new HashSet<string>();

        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (System.Collections.DictionaryEntry entry in rs)
            keys.Add((string)entry.Key);
        return keys;
    }
}
