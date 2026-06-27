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
    /// Culture UI (fr-FR / en-US). Au premier lancement, reprend la langue
    /// choisie dans l'installateur (HKCU\Software\optiCombat\UiCulture).
    /// </summary>
    public static class LocalizationService
    {
        private const string RegistryPath = @"Software\optiCombat";
        private const string CultureValueName = "UiCulture";

        private static readonly ResourceManager ResourceManager = new(
            "optiCombat.Resources.UiStrings",
            Assembly.GetExecutingAssembly());

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

        public static void ApplyCulture(string cultureName)
        {
            var culture = CultureInfo.GetCultureInfo(NormalizeCultureName(cultureName));
            CurrentCulture = culture;
            CultureInfo.DefaultThreadCurrentCulture = culture;
            CultureInfo.DefaultThreadCurrentUICulture = culture;
            Thread.CurrentThread.CurrentCulture = culture;
            Thread.CurrentThread.CurrentUICulture = culture;
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
            var path = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(path))
                path = Process.GetCurrentProcess().MainModule?.FileName;

            if (!string.IsNullOrWhiteSpace(path))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = path,
                    UseShellExecute = true,
                    WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory,
                });
            }

            if (System.Windows.Application.Current != null)
                System.Windows.Application.Current.Shutdown();
        }

        private static void WriteRegistryCulture(string normalized)
        {
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(RegistryPath);
                key?.SetValue(CultureValueName, normalized);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("LocalizationService", "WriteRegistryCulture", ex);
            }
        }

        private static string ResolveCultureName()
        {
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

            var fromInstaller = ReadRegistryCulture();
            if (!string.IsNullOrWhiteSpace(fromInstaller))
                return fromInstaller;

            return "fr-FR";
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
                using var key = Registry.CurrentUser.OpenSubKey(RegistryPath, writable: false);
                return key?.GetValue(CultureValueName) as string;
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
