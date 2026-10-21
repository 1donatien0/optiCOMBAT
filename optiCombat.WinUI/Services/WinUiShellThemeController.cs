using optiCombat.Services;

namespace optiCombat.WinUI.Services;

/// <summary>Adaptateur <see cref="IShellThemeController"/> → <see cref="WinUiThemeManager"/>.</summary>
public sealed class WinUiShellThemeController : IShellThemeController
{
    public static WinUiShellThemeController Instance { get; } = new();

    private WinUiShellThemeController()
    {
    }

    public bool IsDarkTheme => WinUiThemeManager.IsDarkTheme;

    public void ApplyExplicit(bool dark) => WinUiThemeManager.ApplyExplicit(dark);

    public void SetSyncWithWindows(bool sync) => WinUiThemeManager.SetSyncWithWindows(sync);

    public void SetHighContrast(bool enabled) => WinUiThemeManager.SetHighContrast(enabled);

    public void SetThemePreset(string presetId) => WinUiThemeManager.SetThemePreset(presetId);

    public void SetCustomAccentColor(string? hexColor) => WinUiThemeManager.SetCustomAccentColor(hexColor);
}
