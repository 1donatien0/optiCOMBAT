using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Microsoft.Win32;
using optiCombat.Services;
using Windows.UI.ViewManagement;
using WinUiApp = Microsoft.UI.Xaml.Application;

namespace optiCombat.WinUI.Services;

/// <summary>
/// Thème Donaby Combat Aqua : clair / sombre / suivi de Windows et contraste renforcé.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>Les brosses de marque vivent dans <c>Themes/Combat.Light|Dark.xaml</c> (dictionnaires de thème d'App.xaml).</item>
/// <item>Le contraste renforcé fusionne <c>Themes/Combat.HighContrast.xaml</c> en DERNIER dans le dictionnaire
/// « Light » (le dernier dictionnaire fusionné gagne) et force le thème clair.</item>
/// <item>L'accent Combat Aqua est injecté dans <c>SystemAccentColor*</c> de chaque thème : les contrôles WinUI
/// (boutons d'accent, interrupteurs, sélection) suivent la marque au lieu de la couleur d'accent de Windows.</item>
/// <item>Dans le code-behind, utiliser <see cref="GetBrush"/> plutôt que <c>Application.Current.Resources[key]</c>,
/// qui suit le thème de Windows et non celui de l'application.</item>
/// </list>
/// </remarks>
public static class WinUiThemeManager
{
    private const string LightKey = "Light";
    private const string DarkKey = "Dark";
    private const string LightAccentHex = "#0F9F8F";
    private const string DarkAccentHex = "#2DD4BF";
    private const string HighContrastAccentHex = "#00564C";

    private static IUserPreferencesAccessor _prefs = new DefaultUserPreferencesAccessor();
    private static WeakReference<FrameworkElement>? _root;
    private static ResourceDictionary? _hcOverlay;
    private static AccessibilitySettings? _accessibility;

    /// <summary>Levé après chaque changement effectif (argument : thème sombre effectif).</summary>
    public static event EventHandler<bool>? ThemeChanged;

    public static bool IsDarkTheme { get; private set; }

    public static bool HighContrast { get; private set; }

    /// <summary>Thème réellement affiché : le contraste renforcé force le clair.</summary>
    public static bool IsEffectiveDark => IsDarkTheme && !HighContrast;

    public static bool SyncWithWindows => _prefs.Current.SyncWindowsTheme;

    /// <summary>À appeler une fois, quand la racine visuelle de la fenêtre existe.</summary>
    public static void Initialize(IUserPreferencesAccessor preferences, FrameworkElement root)
    {
        _prefs = preferences;
        _root = new WeakReference<FrameworkElement>(root);
        var prefs = preferences.Current;
        IsDarkTheme = prefs.SyncWindowsTheme ? IsWindowsAppsDarkTheme() : prefs.DarkTheme;
        SetHighContrastOverlay(prefs.HighContrastEnabled || IsSystemHighContrast());
        ApplyAccentColors();
        ApplyToRoot(forceRefresh: true);
    }

    /// <summary>Choix explicite clair / sombre (désactive le suivi de Windows).</summary>
    public static void ApplyExplicit(bool dark)
    {
        var prefs = _prefs.Current;
        prefs.SyncWindowsTheme = false;
        prefs.DarkTheme = dark;
        prefs.Save();
        IsDarkTheme = dark;
        ApplyToRoot(forceRefresh: false);
    }

    /// <summary>Suivre (ou non) le mode clair / sombre des applications Windows.</summary>
    public static void SetSyncWithWindows(bool sync)
    {
        var prefs = _prefs.Current;
        prefs.SyncWindowsTheme = sync;
        if (sync)
            prefs.DarkTheme = IsWindowsAppsDarkTheme();
        prefs.Save();
        IsDarkTheme = prefs.DarkTheme;
        ApplyToRoot(forceRefresh: false);
    }

    public static void SetHighContrast(bool enabled)
    {
        var prefs = _prefs.Current;
        prefs.HighContrastEnabled = enabled;
        prefs.Save();
        SetHighContrastOverlay(enabled || IsSystemHighContrast());
        ApplyAccentColors();
        ApplyToRoot(forceRefresh: true);
    }

    /// <summary>Brosse du thème effectivement affiché ; repli gris si la clé est absente.</summary>
    public static Brush GetBrush(string key)
    {
        var resources = WinUiApp.Current?.Resources;
        if (resources != null)
        {
            if (HighContrast && _hcOverlay != null && _hcOverlay.TryGetValue(key, out var hc) && hc is Brush hcBrush)
                return hcBrush;

            if (resources.ThemeDictionaries.TryGetValue(IsEffectiveDark ? DarkKey : LightKey, out var td)
                && td is ResourceDictionary themeDict
                && themeDict.TryGetValue(key, out var themed)
                && themed is Brush themedBrush)
                return themedBrush;

            if (resources.TryGetValue(key, out var v) && v is Brush brush)
                return brush;
        }

        return new SolidColorBrush(Colors.Gray);
    }

    public static bool IsWindowsAppsDarkTheme()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", writable: false);
            return key?.GetValue("AppsUseLightTheme") switch
            {
                int light => light == 0,
                _ => false,
            };
        }
        catch (Exception ex)
        {
            AppLogger.Warn("WinUiThemeManager", "IsWindowsAppsDarkTheme", ex);
            return false;
        }
    }

    public static bool IsSystemHighContrast()
    {
        try
        {
            _accessibility ??= new AccessibilitySettings();
            return _accessibility.HighContrast;
        }
        catch (Exception ex)
        {
            AppLogger.Warn("WinUiThemeManager", "IsSystemHighContrast", ex);
            return false;
        }
    }

    private static void ApplyToRoot(bool forceRefresh)
    {
        if (_root == null || !_root.TryGetTarget(out var root))
            return;

        var target = IsEffectiveDark ? ElementTheme.Dark : ElementTheme.Light;
        if (forceRefresh)
        {
            // Aller-retour de thème : force la réévaluation des {ThemeResource} après fusion / surcharge.
            root.RequestedTheme = target == ElementTheme.Dark ? ElementTheme.Light : ElementTheme.Dark;
        }

        root.RequestedTheme = target;
        ThemeChanged?.Invoke(null, IsEffectiveDark);
    }

    private static void SetHighContrastOverlay(bool enable)
    {
        HighContrast = enable;
        var light = GetThemeDictionary(LightKey);
        if (light == null)
            return;

        if (_hcOverlay != null)
        {
            light.MergedDictionaries.Remove(_hcOverlay);
            _hcOverlay = null;
        }

        if (!enable)
            return;

        _hcOverlay = new ResourceDictionary { Source = new Uri("ms-appx:///Themes/Combat.HighContrast.xaml") };
        light.MergedDictionaries.Add(_hcOverlay);
    }

    private static void ApplyAccentColors()
    {
        SetAccent(LightKey, HighContrast ? HighContrastAccentHex : LightAccentHex);
        SetAccent(DarkKey, DarkAccentHex);
    }

    private static void SetAccent(string themeKey, string hex)
    {
        var dict = GetThemeDictionary(themeKey);
        if (dict == null || !TryParseColor(hex, out var color))
            return;

        dict["SystemAccentColor"] = color;
        dict["SystemAccentColorLight1"] = Mix(color, 255, 0.15);
        dict["SystemAccentColorLight2"] = Mix(color, 255, 0.30);
        dict["SystemAccentColorLight3"] = Mix(color, 255, 0.45);
        dict["SystemAccentColorDark1"] = Mix(color, 0, 0.15);
        dict["SystemAccentColorDark2"] = Mix(color, 0, 0.30);
        dict["SystemAccentColorDark3"] = Mix(color, 0, 0.45);
    }

    internal static Windows.UI.Color Mix(Windows.UI.Color c, byte target, double amount)
    {
        static byte Lerp(byte from, byte to, double t) => (byte)Math.Round(from + (to - from) * t);
        return Windows.UI.Color.FromArgb(255, Lerp(c.R, target, amount), Lerp(c.G, target, amount), Lerp(c.B, target, amount));
    }

    internal static bool TryParseColor(string hex, out Windows.UI.Color color)
    {
        color = default;
        var h = hex.Trim().TrimStart('#');
        if (h.Length != 6)
            return false;
        try
        {
            color = Windows.UI.Color.FromArgb(
                255,
                Convert.ToByte(h[..2], 16),
                Convert.ToByte(h.Substring(2, 2), 16),
                Convert.ToByte(h.Substring(4, 2), 16));
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static ResourceDictionary? GetThemeDictionary(string themeKey)
    {
        var resources = WinUiApp.Current?.Resources;
        return resources != null && resources.ThemeDictionaries.TryGetValue(themeKey, out var d)
            ? d as ResourceDictionary
            : null;
    }
}
