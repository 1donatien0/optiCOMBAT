namespace optiCombat.WinUI.Services;

/// <summary>Presets d'accent Combat Aqua + variantes importées de SCAN/win.</summary>
public static class WinUiThemePacks
{
    public sealed record ThemePack(string Id, string NameKey, string LightAccent, string DarkAccent);

    public static IReadOnlyList<ThemePack> All { get; } =
    [
        new("combat", "ThemePack_Combat", "#0F9F8F", "#2DD4BF"),
        new("midnight", "ThemePack_Midnight", "#1E3A5F", "#6AAAE8"),
        new("ocean", "ThemePack_Ocean", "#0D7377", "#2BB8BD"),
        new("ember", "ThemePack_Ember", "#B45309", "#F59E0B"),
    ];

    public static ThemePack Get(string? id)
    {
        var key = string.IsNullOrWhiteSpace(id) ? "combat" : id.Trim();
        return All.FirstOrDefault(p => p.Id.Equals(key, StringComparison.OrdinalIgnoreCase)) ?? All[0];
    }
}
