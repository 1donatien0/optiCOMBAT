using MaterialDesignThemes.Wpf;
using Microsoft.Win32;
using optiCombat.Services;
using System.Windows;
using WpfApp = System.Windows.Application;

namespace optiCombat
{
    /// <summary>
    /// Gestionnaire de thèmes unifié.
    /// Permute MaterialDesign ET le dictionnaire Donaby personnalisé.
    /// Persistance via UserPreferences (JSON).
    /// Détection automatique du thème Windows via SystemEvents (sans polling).
    /// Détection automatique du mode Contraste Renforcé système.
    /// </summary>
    public static class ThemeManager
    {
        private static bool _isDarkTheme = false;
        private static bool _highContrast;
        private static bool _watchingSystemEvents;
        private static bool? _lastWindowsDarkTheme;
        private static IUserPreferencesAccessor _prefs = new DefaultUserPreferencesAccessor();

        public static event EventHandler<bool>? ThemeChanged;

        public static bool HighContrast => _highContrast;

        public static bool IsDarkTheme
        {
            get => _isDarkTheme;
            private set
            {
                if (_isDarkTheme != value)
                {
                    _isDarkTheme = value;
                    ApplyTheme(value);
                    ThemeChanged?.Invoke(null, value);
                }
            }
        }

        /// <summary>
        /// Charge et applique le thème sauvegardé dans UserPreferences.
        /// À appeler une seule fois au démarrage (thread UI).
        /// </summary>
        public static void Initialize(IUserPreferencesAccessor? preferences = null)
        {
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            var prefs = _prefs.Current;

            bool systemHc = SystemParameters.HighContrast;
            _highContrast = systemHc || prefs.HighContrastEnabled;

            bool windowsDark = IsWindowsAppsDarkTheme();
            _lastWindowsDarkTheme = windowsDark;

            if (TryMigrateToWindowsThemeSync(prefs, windowsDark))
                prefs.Save();

            if (prefs.SyncWindowsTheme)
            {
                _isDarkTheme = windowsDark;
                ApplyTheme(windowsDark);
                if (prefs.DarkTheme != windowsDark)
                {
                    prefs.DarkTheme = windowsDark;
                    prefs.Save();
                }
            }
            else
            {
                _isDarkTheme = prefs.DarkTheme;
                ApplyTheme(prefs.DarkTheme);
            }

            StartSystemEventsWatcher();
        }

        /// <summary>
        /// Ancien défaut <c>SyncWindowsTheme=false</c> : si le thème stocké = Windows, activer le suivi.
        /// </summary>
        internal static bool TryMigrateToWindowsThemeSync(UserPreferences prefs, bool windowsDark)
        {
            if (prefs.SyncWindowsTheme || prefs.DarkTheme != windowsDark)
                return false;
            prefs.SyncWindowsTheme = true;
            return true;
        }

        /// <summary>Indique si Windows est en mode applications sombres (registre Personalize).</summary>
        public static bool IsWindowsAppsDarkTheme()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", writable: false);
                var v = key?.GetValue("AppsUseLightTheme");
                if (v is int light)
                    return light == 0;
                if (v is uint u)
                    return u == 0;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ThemeManager", "IsWindowsAppsDarkTheme", ex);
            }
            return false;
        }

        /// <summary>Active ou désactive le thème à contraste renforcé.</summary>
        public static void SetHighContrast(bool enabled)
        {
            var prefs = _prefs.Current;
            prefs.HighContrastEnabled = enabled;
            prefs.Save();
            _highContrast = enabled || SystemParameters.HighContrast;
            ApplyTheme(_isDarkTheme);
        }

        /// <summary>Thème différent du mode Windows (case Options cochée).</summary>
        public static bool IsAlternateThemeEnabled =>
            !_prefs.Current.SyncWindowsTheme;

        /// <summary>Active ou repasse au suivi du thème Windows (case Options décochée).</summary>
        public static void SetAlternateThemeEnabled(bool enabled)
        {
            if (enabled)
            {
                var prefs = _prefs.Current;
                prefs.SyncWindowsTheme = false;
                prefs.Save();
                Apply(!IsWindowsAppsDarkTheme());
            }
            else
                SetSyncWithWindows(true);
        }

        /// <summary>
        /// Barre latérale : si suivi Windows, passe au thème opposé ; sinon bascule clair/sombre en dérogation.
        /// </summary>
        public static void Toggle()
        {
            if (_prefs.Current.SyncWindowsTheme)
                SetAlternateThemeEnabled(true);
            else
                Apply(!IsDarkTheme);
        }

        /// <summary>Applique un thème en dérogation (ne suit plus Windows).</summary>
        public static void Apply(bool dark)
        {
            var prefs = _prefs.Current;
            prefs.SyncWindowsTheme = false;
            prefs.DarkTheme = dark;
            prefs.Save();
            IsDarkTheme = dark;
        }

        /// <summary>Active ou désactive le suivi du thème Windows.</summary>
        public static void SetSyncWithWindows(bool sync)
        {
            var prefs = _prefs.Current;
            prefs.SyncWindowsTheme = sync;
            if (sync)
            {
                bool dark = IsWindowsAppsDarkTheme();
                _lastWindowsDarkTheme = dark;
                prefs.DarkTheme = dark;
                prefs.Save();
                if (_isDarkTheme != dark)
                    IsDarkTheme = dark;
                else
                    ApplyTheme(dark);
            }
            else
                Apply(prefs.DarkTheme);
        }

        // ── Abonnement à SystemEvents (zéro polling) ──────────────────────

        private static void StartSystemEventsWatcher()
        {
            if (_watchingSystemEvents)
                return;
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
            _watchingSystemEvents = true;
        }

        private static void StopSystemEventsWatcher()
        {
            if (!_watchingSystemEvents)
                return;
            SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
            _watchingSystemEvents = false;
            _lastWindowsDarkTheme = null;
        }

        /// <summary>
        /// Déclenché par Windows lors d'un changement de préférences utilisateur
        /// (thème, couleurs, contraste renforcé). Exécuté sur un thread arbitraire
        /// → dispatch vers le thread UI.
        /// </summary>
        private static void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
        {
            if (e.Category != UserPreferenceCategory.General
                && e.Category != UserPreferenceCategory.Color
                && e.Category != UserPreferenceCategory.Accessibility)
                return;

            var dispatcher = WpfApp.Current?.Dispatcher;
            if (dispatcher == null)
                return;

            _ = dispatcher.InvokeAsync(() =>
            {
                // 1. Contraste Renforcé système (priorité) — même sans SyncWindowsTheme
                bool systemHc = SystemParameters.HighContrast;
                bool newHc = systemHc || _prefs.Current.HighContrastEnabled;
                bool hcChanged = _highContrast != newHc;
                if (hcChanged)
                {
                    _highContrast = newHc;
                    ApplyTheme(_isDarkTheme);
                }

                // 2. Thème clair/sombre
                if (!_prefs.Current.SyncWindowsTheme)
                {
                    // Thème affiché inchangé ; rafraîchir Options (libellé Thème clair / sombre).
                    ThemeChanged?.Invoke(null, _isDarkTheme);
                    return;
                }

                bool dark = IsWindowsAppsDarkTheme();
                if (_lastWindowsDarkTheme.HasValue && _lastWindowsDarkTheme.Value == dark && !hcChanged)
                    return;

                _lastWindowsDarkTheme = dark;
                IsDarkTheme = dark;
                var prefs = _prefs.Current;
                prefs.DarkTheme = dark;
                prefs.Save();
            });
        }

        private static void ApplyTheme(bool isDark)
        {
            try
            {
                // 1. Material Design base (sombre/clair)
                var paletteHelper = new PaletteHelper();
                var theme = paletteHelper.GetTheme();
                theme.SetBaseTheme(isDark ? BaseTheme.Dark : BaseTheme.Light);
                paletteHelper.SetTheme(theme);

                // 2. Permuter le dictionnaire Donaby personnalisé
                SwapDonabyTheme(isDark);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ThemeManager", "ApplyTheme", ex);
            }
        }

        /// <summary>
        /// Remplace le ResourceDictionary Donaby.*.xaml chargé dans App.Resources
        /// par la variante clair, sombre ou contraste renforcé.
        /// </summary>
        private static void SwapDonabyTheme(bool isDark)
        {
            if (WpfApp.Current?.Resources?.MergedDictionaries == null)
                return;

            var merged = WpfApp.Current.Resources.MergedDictionaries;

            Uri uri;
            if (_highContrast)
                uri = new Uri("/Themes/Donaby.HighContrast.xaml", UriKind.Relative);
            else
                uri = isDark
                    ? new Uri("/Themes/Donaby.Dark.xaml", UriKind.Relative)
                    : new Uri("/Themes/Donaby.Light.xaml", UriKind.Relative);

            var existing = merged.FirstOrDefault(d =>
                d.Source?.OriginalString.Contains("Donaby.", StringComparison.OrdinalIgnoreCase) == true);

            if (existing != null)
            {
                int idx = merged.IndexOf(existing);
                merged.Remove(existing);
                merged.Insert(idx, new ResourceDictionary { Source = uri });
                return;
            }

            // PaletteHelper.SetTheme peut retirer Donaby.* des merged dicts — réinsérer avant Controls.xaml.
            int insertIdx = merged.Count;
            for (int i = 0; i < merged.Count; i++)
            {
                var src = merged[i].Source?.OriginalString ?? string.Empty;
                if (src.Contains("Controls.xaml", StringComparison.OrdinalIgnoreCase))
                {
                    insertIdx = i;
                    break;
                }
            }

            merged.Insert(insertIdx, new ResourceDictionary { Source = uri });
        }
    }
}
