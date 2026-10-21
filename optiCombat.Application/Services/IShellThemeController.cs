namespace optiCombat.Services;

/// <summary>
/// Pilotage du thème du shell (clair / sombre, contraste, accent), découplé de WinUI
/// pour que <c>OptionsViewModel</c> soit testable hors interface graphique.
/// </summary>
public interface IShellThemeController
{
    /// <summary>Thème sombre effectivement demandé (après suivi éventuel de Windows).</summary>
    bool IsDarkTheme { get; }

    void ApplyExplicit(bool dark);

    void SetSyncWithWindows(bool sync);

    void SetHighContrast(bool enabled);

    void SetThemePreset(string presetId);

    void SetCustomAccentColor(string? hexColor);
}
