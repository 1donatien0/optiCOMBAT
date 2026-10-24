using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Resources;
using Microsoft.Win32;
using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Localization
{
    /// <summary>
    /// Culture UI (fr-FR / en-US). Ordre de résolution au démarrage :
    /// <list type="number">
    /// <item>langue que l'installateur vient de choisir (<c>UiCulturePending</c> posé avec
    /// <c>HKCU\Software\optiCombat\UiCulture</c>) — elle remplace celle des préférences,
    /// pour qu'une réinstallation dans une autre langue soit prise en compte ;</item>
    /// <item>langue des préférences ;</item>
    /// <item>langue écrite par l'installateur (<c>UiCulture</c>) ;</item>
    /// <item>langue de Windows : français si Windows est en français, anglais sinon.</item>
    /// </list>
    /// </summary>
    public static class LocalizationService
    {
        private const string RegistryPath = @"Software\optiCombat";
        private const string CultureValueName = "UiCulture";
        private const string PendingValueName = "UiCulturePending";

        /// <summary>Tests uniquement : langue de Windows simulée.</summary>
        internal static CultureInfo? SystemUiCultureOverride { get; set; }

        private static readonly ResourceManager ResourceManager = new(
            "optiCombat.Resources.UiStrings",
            typeof(LocalizationService).Assembly);

        private static IUserPreferencesAccessor _prefs = new DefaultUserPreferencesAccessor();

        public static CultureInfo CurrentCulture { get; private set; } = CultureInfo.GetCultureInfo("fr-FR");

        public static bool IsEnglish =>
            CurrentCulture.TwoLetterISOLanguageName.Equals("en", StringComparison.OrdinalIgnoreCase);

        public static void Initialize()
        {
            var cultureName = ResolveCultureName();
            ApplyCulture(cultureName);
            PersistCultureIfNeeded(cultureName);
            ShellContextMenuSupport.ApplyForCurrentCulture();
        }

        /// <summary>Branche l'accesseur DI (appelé depuis <see cref="ServiceContainer"/>).</summary>
        public static void ConfigurePreferencesAccessor(IUserPreferencesAccessor preferences)
        {
            _prefs = preferences;
        }

        public static string GetString(string key)
        {
            if (string.IsNullOrEmpty(key)) return string.Empty;
            return ResourceManager.GetString(key, CurrentCulture) ?? key;
        }

        public static string Format(string key, params object[] args)
        {
            var template = GetString(key);
            try { return string.Format(CurrentCulture, template, args); }
            catch { return template; }
        }

        /// <summary>Levé après <see cref="ApplyCulture"/> quand la culture change (réapplication des libellés UI).</summary>
        public static event EventHandler? CultureChanged;

        public static void ApplyCulture(string cultureName)
        {
            var culture = CultureInfo.GetCultureInfo(NormalizeCultureName(cultureName));
            var changed = !Equals(CurrentCulture, culture);
            CurrentCulture = culture;
            CultureInfo.DefaultThreadCurrentCulture = culture;
            CultureInfo.DefaultThreadCurrentUICulture = culture;
            Thread.CurrentThread.CurrentCulture = culture;
            Thread.CurrentThread.CurrentUICulture = culture;
            if (changed)
                CultureChanged?.Invoke(null, EventArgs.Empty);
        }

        /// <summary>Enregistre la langue choisie (préférences + registre, comme l'installateur).</summary>
        public static void SetUserCulture(string cultureName)
        {
            var normalized = NormalizeCultureName(cultureName);
            try
            {
                var prefs = _prefs.Current;
                prefs.UiCulture = normalized;
                prefs.Save();
            }
            catch (Exception ex)
            {
                AppLogger.Warn("LocalizationService", "SetUserCulture prefs", ex);
            }

            WriteRegistryCulture(normalized);
            ShellContextMenuSupport.ApplyForCurrentCulture();
        }

        /// <summary>Relance optiCombat pour appliquer une nouvelle langue à toute l'interface.</summary>
        public static void RestartApplication()
        {
            var shell = SystemShell.Current;
            var path = RestartExecutableOverride ?? Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(path))
                path = Process.GetCurrentProcess().MainModule?.FileName;

            if (!string.IsNullOrWhiteSpace(path))
            {
                shell.Run(new ProcessStartInfo
                {
                    FileName = path,
                    UseShellExecute = true,
                    WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory,
                }, timeoutMs: null);
            }

            shell.ExitProcess(0);
        }

        /// <summary>Tests uniquement : exécutable relancé après changement de langue.</summary>
        internal static string? RestartExecutableOverride { get; set; }

        private static void WriteRegistryCulture(string normalized)
        {
            try
            {
                SystemShell.Current.SetCurrentUserValue(RegistryPath, CultureValueName, normalized, RegistryValueKind.String);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("LocalizationService", "WriteRegistryCulture", ex);
            }
        }

        internal static string ResolveCultureName()
        {
            var fromInstaller = ReadRegistryCulture();
            if (ConsumeInstallerChoice() && !string.IsNullOrWhiteSpace(fromInstaller))
            {
                var chosen = NormalizeCultureName(fromInstaller);
                try
                {
                    var prefs = _prefs.Current;
                    prefs.UiCulture = chosen;
                    prefs.Save();
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("LocalizationService", "Langue de l'installateur", ex);
                }
                return chosen;
            }

            try
            {
                var prefs = _prefs.Current;
                if (!string.IsNullOrWhiteSpace(prefs.UiCulture))
                    return prefs.UiCulture;
            }
            catch
            {
                /* premier lancement avant prefs */
            }

            if (!string.IsNullOrWhiteSpace(fromInstaller))
                return fromInstaller;

            // Ni préférence ni installateur (copie portable, build de dev) : langue de Windows.
            var system = SystemUiCultureOverride ?? CultureInfo.InstalledUICulture;
            return system.TwoLetterISOLanguageName.Equals("fr", StringComparison.OrdinalIgnoreCase) ? "fr-FR" : "en-US";
        }

        /// <summary>Vrai (une seule fois) si l'installateur vient de choisir la langue ; efface le marqueur.</summary>
        private static bool ConsumeInstallerChoice()
        {
            try
            {
                var shell = SystemShell.Current;
                if (shell.GetCurrentUserValue(RegistryPath, PendingValueName) is not int pending || pending == 0)
                    return false;
                shell.DeleteCurrentUserValue(RegistryPath, PendingValueName);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("LocalizationService", "UiCulturePending", ex);
                return false;
            }
        }

        private static void PersistCultureIfNeeded(string cultureName)
        {
            try
            {
                var prefs = _prefs.Current;
                if (string.IsNullOrWhiteSpace(prefs.UiCulture))
                {
                    prefs.UiCulture = NormalizeCultureName(cultureName);
                    prefs.Save();
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("LocalizationService", "PersistCultureIfNeeded", ex);
            }
        }

        private static string? ReadRegistryCulture()
        {
            try
            {
                return SystemShell.Current.GetCurrentUserValue(RegistryPath, CultureValueName) as string;
            }
            catch
            {
                return null;
            }
        }

        private static string NormalizeCultureName(string name) =>
            name.StartsWith("en", StringComparison.OrdinalIgnoreCase) ? "en-US" : "fr-FR";

        // ── Scan & modèles ───────────────────────────────────────────────────

        public static string ScanTypeDisplay(ScanType type) => type switch
        {
            ScanType.File => GetString("ScanType_File"),
            ScanType.Folder => GetString("ScanType_Folder"),
            ScanType.FullScan => GetString("ScanType_Full"),
            ScanType.QuickScan => GetString("ScanType_Quick"),
            ScanType.RemovableDrive => GetString("ScanType_Removable"),
            ScanType.RealTime => GetString("ScanType_RealTime"),
            _ => GetString("ScanType_Default"),
        };

        public static string ScanSummaryDisplay(
            ScanStatus status,
            int filesScanned,
            int threatsFound,
            TimeSpan duration,
            string? errorMessage)
        {
            return status switch
            {
                ScanStatus.Running => Format("ScanSummary_Running", filesScanned),
                ScanStatus.Completed when threatsFound == 0 =>
                    Format("ScanSummary_Clean", filesScanned, ScanDisplayFormatter.FormatDuration(duration)),
                ScanStatus.Completed =>
                    Format("ScanSummary_Threats", threatsFound, filesScanned),
                ScanStatus.Cancelled => Format("ScanSummary_Cancelled", filesScanned),
                ScanStatus.Error => Format("ScanSummary_Error", errorMessage ?? GetString("Common_Unknown")),
                _ => GetString("ScanSummary_Unknown"),
            };
        }

        public static string RecentTargetLabel(ScanType scanType, string displayName) => scanType switch
        {
            ScanType.QuickScan => GetString("Recent_QuickScan"),
            ScanType.FullScan => GetString("Recent_FullScan"),
            ScanType.Folder => Format("Recent_Folder", displayName),
            ScanType.File => Format("Recent_File", displayName),
            _ => displayName,
        };
    }
}
