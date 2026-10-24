using System.Globalization;
using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary>Langue au démarrage : choix de l'installateur, préférences, puis langue de Windows.</summary>
[Collection("OpticombatPrefs")]
public sealed class InstallerCultureTests : IDisposable
{
    private const string Key = @"Software\optiCombat";
    private readonly IsolatedServices _iso = new();
    private readonly RecordingShell _shell = RecordingShell.Install();

    public InstallerCultureTests()
    {
        _iso.Prefs.UiCulture = string.Empty; // premier lancement : aucune langue enregistrée
        LocalizationService.ConfigurePreferencesAccessor(_iso.PrefsAccessor);
    }

    public void Dispose()
    {
        LocalizationService.SystemUiCultureOverride = null;
        _shell.Dispose();
        _iso.Dispose();
        LocalizationService.ApplyCulture("fr-FR");
    }

    private void Installer(string culture, bool pending)
    {
        _shell.CurrentUser[RecordingShell.Key(Key, "UiCulture")] = culture;
        if (pending)
            _shell.CurrentUser[RecordingShell.Key(Key, "UiCulturePending")] = 1;
    }

    [Fact]
    public void Reinstalling_in_english_overrides_the_saved_french_preference_once()
    {
        _iso.Prefs.UiCulture = "fr-FR";
        Installer("en-US", pending: true);

        Assert.Equal("en-US", LocalizationService.ResolveCultureName());
        Assert.Equal("en-US", _iso.Prefs.UiCulture);
        Assert.False(_shell.CurrentUser.ContainsKey(RecordingShell.Key(Key, "UiCulturePending")));

        // Ensuite, un changement fait dans l'application est respecté.
        _iso.Prefs.UiCulture = "fr-FR";
        Assert.Equal("fr-FR", LocalizationService.ResolveCultureName());
    }

    [Fact]
    public void Saved_preference_wins_over_an_old_installer_value()
    {
        _iso.Prefs.UiCulture = "fr-FR";
        Installer("en-US", pending: false);
        Assert.Equal("fr-FR", LocalizationService.ResolveCultureName());
    }

    [Fact]
    public void First_launch_uses_the_installer_language()
    {
        Installer("en-US", pending: false);
        Assert.Equal("en-US", LocalizationService.ResolveCultureName());
    }

    [Theory]
    [InlineData("fr-CA", "fr-FR")]
    [InlineData("fr-FR", "fr-FR")]
    [InlineData("en-GB", "en-US")]
    [InlineData("de-DE", "en-US")]
    [InlineData("es-ES", "en-US")]
    public void Without_preference_or_installer_the_windows_language_decides(string windows, string expected)
    {
        LocalizationService.SystemUiCultureOverride = CultureInfo.GetCultureInfo(windows);
        Assert.Equal(expected, LocalizationService.ResolveCultureName());
    }

    [Fact]
    public void Pending_marker_without_a_culture_is_ignored()
    {
        _shell.CurrentUser[RecordingShell.Key(Key, "UiCulturePending")] = 1;
        LocalizationService.SystemUiCultureOverride = CultureInfo.GetCultureInfo("fr-FR");
        Assert.Equal("fr-FR", LocalizationService.ResolveCultureName());
    }

    [Fact]
    public void Initialize_applies_and_persists_the_resolved_culture()
    {
        Installer("en-US", pending: true);

        LocalizationService.Initialize();

        Assert.True(LocalizationService.IsEnglish);
        Assert.Equal("en-US", _iso.Prefs.UiCulture);
    }
}
