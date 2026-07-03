using Microsoft.Win32;
using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Strings;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using WinForms = System.Windows.Forms;
using WpfButton = System.Windows.Controls.Button;
using WpfCheckBox = System.Windows.Controls.CheckBox;

namespace optiCombat.Views
{
    /// <summary>
    /// Vue Options — exclusions, protection temps réel, scans planifiés, thème et préférences utilisateur.
    /// </summary>
    public partial class OptionsControl : System.Windows.Controls.UserControl
    {
        private readonly ObservableCollection<string> _exclusions = new();
        private IOptionsServices? _services;
        private bool _suppressPreferenceEvents;
        private string? _languageTagBeforeDropDown;
        private int _favoriteScanIndexBeforeDropDown;

        private IUserPreferencesAccessor Prefs =>
            (_services?.UserPreferencesAccessor ?? new DefaultUserPreferencesAccessor());

        private IExclusionSettingsAccessor Excl =>
            (_services?.ExclusionSettingsAccessor ?? new DefaultExclusionSettingsAccessor());

        public OptionsControl()
        {
            // XAML définit IsChecked sur plusieurs cases : sans ce garde-fou, Checked/Unchecked
            // appellent CheckOption_Changed avant MainWindow.Bind() → Services lève une exception.
            // Prevent preference event handlers from running while XAML/controls are initializing.
            _suppressPreferenceEvents = true;
            InitializeComponent();
            lstExclusions.ItemsSource = _exclusions;
            InitScheduleTimeComboBoxes();
            LoadPreferences();
            Loaded += (_, _) =>
            {
                ThemeManager.ThemeChanged += SurChangementTheme;
                SyncThemeControls();
            };
            Unloaded += (_, _) => ThemeManager.ThemeChanged -= SurChangementTheme;
            IsVisibleChanged += (_, _) =>
            {
                if (IsVisible)
                    SyncThemeControls();
            };
        }

        private IOptionsServices Services => _services ?? throw new InvalidOperationException("OptionsControl.Bind() must be called before use.");
        private IScheduledScanService ScheduledScan => Services.ScheduledScan;

        public void Bind(IOptionsServices services)
        {
            _services = services;
            _ = LoadScheduledTaskStateAsync();
        }

        private void SurChangementTheme(object? sender, bool isDark) => SyncThemeControls();

        private void InitScheduleTimeComboBoxes()
        {
            if (cmbScheduleHour == null || cmbScheduleMinute == null) return;
            for (int h = 0; h < 24; h++)
                cmbScheduleHour.Items.Add(h.ToString("00", CultureInfo.InvariantCulture));
            for (int m = 0; m < 60; m += 15)
                cmbScheduleMinute.Items.Add(m.ToString("00", CultureInfo.InvariantCulture));
            cmbScheduleHour.SelectedIndex = 2;
            cmbScheduleMinute.SelectedIndex = 0;
        }

        private TimeSpan GetSelectedScheduleTime()
        {
            int h = cmbScheduleHour?.SelectedIndex ?? 2;
            int m = 0;
            if (cmbScheduleMinute?.SelectedItem is string ms && int.TryParse(ms, out var parsed))
                m = parsed;
            return new TimeSpan(h, m, 0);
        }

        /// <summary>Synchronise les cases thème avec ThemeManager et UserPreferences.</summary>
        public void SyncThemeControls() => SyncThemeControls(ThemeManager.IsDarkTheme);

        /// <summary>Alias conservé pour MainWindow.</summary>
        public void SyncDarkThemeCheckbox(bool isDark) => SyncThemeControls(isDark);

        private void SyncThemeControls(bool isDark)
        {
            _suppressPreferenceEvents = true;
            try
            {
                UpdateAlternateThemeLabels();
                if (chkAlternateTheme != null)
                    chkAlternateTheme.IsChecked = ThemeManager.IsAlternateThemeEnabled;
            }
            finally
            {
                _suppressPreferenceEvents = false;
            }
        }

        private void UpdateAlternateThemeLabels()
        {
            bool windowsDark = ThemeManager.IsWindowsAppsDarkTheme();
            if (txtAlternateThemeTitle != null)
                txtAlternateThemeTitle.Text = LocalizationService.GetString(
                    windowsDark ? "Opt_ThemeLight" : "Opt_ThemeDark");
            if (txtAlternateThemeSub != null)
                txtAlternateThemeSub.Text = LocalizationService.GetString(
                    windowsDark ? "Opt_ThemeLightSub" : "Opt_ThemeDarkSub");
        }

        private void LoadPreferences()
        {
            _suppressPreferenceEvents = true;
            try
            {
                var prefs = Prefs.Current;
                if (chkNotifications != null)
                    chkNotifications.IsChecked = prefs.ActionNotificationsEnabled;
                if (chkAutoStart != null)
                    chkAutoStart.IsChecked = IsAutoStartRegistered();

                if (cmbUiLanguage != null)
                    SelectUiLanguageCombo(Prefs.Current.UiCulture);

                if (cmbFavoriteScan != null)
                {
                    cmbFavoriteScan.SelectedIndex = prefs.FavoriteScanType switch
                    {
                        ScanType.FullScan => 1,
                        ScanType.Folder => 2,
                        ScanType.File => 3,
                        _ => 0
                    };
                }

                var ex = Excl.Current;
                if (chkRealtimeProtection != null)
                    chkRealtimeProtection.IsChecked = ex.RealTimeEnabled;
                if (chkProcessMonitor != null)
                    chkProcessMonitor.IsChecked = prefs.ProcessMonitorEnabled;
                if (chkTamperProtection != null)
                    chkTamperProtection.IsChecked = prefs.TamperProtectionEnabled;
                ConfigurePlatformProtectionUi(prefs);
                if (chkRemovableDriveScan != null)
                    chkRemovableDriveScan.IsChecked = prefs.RemovableDriveScanEnabled;
                if (chkRemovableDriveDetailed != null)
                    chkRemovableDriveDetailed.IsChecked = prefs.RemovableDriveScanDetailed;
                if (chkIncludeRemovableFullScan != null)
                    chkIncludeRemovableFullScan.IsChecked = prefs.IncludeRemovableInFullScan;

                if (chkAutoQuarantine != null)
                    chkAutoQuarantine.IsChecked = ex.AutoQuarantineEnabled;
                if (chkBackupBeforeQuarantine != null)
                    chkBackupBeforeQuarantine.IsChecked = prefs.BackupBeforeQuarantine;

                if (chkAutoUpdate != null)
                    chkAutoUpdate.IsChecked = prefs.SignatureAutoUpdateEnabled;
                if (chkAggressiveSignatures != null)
                    chkAggressiveSignatures.IsChecked = prefs.AggressiveSignatureUpdates;

                if (chkUseClamd != null)
                    chkUseClamd.IsChecked = prefs.UseClamdEngine;
                if (chkGameMode != null)
                    chkGameMode.IsChecked = prefs.GameModeAutoEnabled;
                if (pwdVirusTotalApiKey != null)
                    pwdVirusTotalApiKey.Password = prefs.VirusTotalApiKey ?? string.Empty;

                if (txtCleanThreshold != null)
                    txtCleanThreshold.Text = prefs.CleanSuggestThresholdDays.ToString();
                if (txtSigThreshold != null)
                    txtSigThreshold.Text = prefs.SignatureStaleThresholdDays.ToString();

                _exclusions.Clear();
                foreach (var path in ex.ExcludedFolders)
                    _exclusions.Add(path);

                if (txtScheduledNextRun != null)
                    txtScheduledNextRun.Text = LocalizationService.GetString("Opt_SchedLoading");
            }
            finally
            {
                _suppressPreferenceEvents = false;
            }
        }

        private async System.Threading.Tasks.Task LoadScheduledTaskStateAsync()
        {
            if (chkScheduledScan == null) return;
            chkScheduledScan.IsEnabled = false;
            try
            {
                bool exists = await System.Threading.Tasks.Task.Run(() => ScheduledScan.IsTaskExists());
                _suppressPreferenceEvents = true;
                try { chkScheduledScan.IsChecked = exists; }
                finally { _suppressPreferenceEvents = false; }
                await RefreshScheduledStatusAsync();
            }
            finally
            {
                chkScheduledScan.IsEnabled = true;
            }
        }

        private async System.Threading.Tasks.Task RefreshScheduledStatusAsync()
        {
            if (txtScheduledNextRun == null) return;

            bool exists = await System.Threading.Tasks.Task.Run(() => ScheduledScan.IsTaskExists());
            if (!exists)
            {
                txtScheduledNextRun.Text = LocalizationService.GetString("Opt_SchedNone");
                if (btnScheduledRunNow != null) btnScheduledRunNow.IsEnabled = false;
                if (pnlScheduleTime != null) pnlScheduleTime.IsEnabled = true;
                return;
            }

            if (btnScheduledRunNow != null) btnScheduledRunNow.IsEnabled = true;
            if (pnlScheduleTime != null) pnlScheduleTime.IsEnabled = false;
            var next = await System.Threading.Tasks.Task.Run(() => ScheduledScan.GetNextRunTime());
            txtScheduledNextRun.Text = next.HasValue
                ? LocalizationService.Format("Opt_SchedNextRun", next.Value.ToString("f", LocalizationService.CurrentCulture))
                : LocalizationService.GetString("Opt_SchedActiveUnknown");
        }

        private static bool IsAutoStartRegistered()
        {
            const string regKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
            const string appName = "optiCombat";
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regKey, writable: false);
                return key?.GetValue(appName) != null;
            }
            catch { return false; }
        }

        private void ConfigurePlatformProtectionUi(UserPreferences prefs)
        {
            if (chkPlatformProtection == null)
                return;

            var activatable = PlatformProtectionFeatureGate.IsUserActivatable;
            chkPlatformProtection.IsEnabled = activatable;
            chkPlatformProtection.IsChecked = activatable && prefs.UsePlatformProtectionService;

            if (pnlPlatformProtection != null)
                pnlPlatformProtection.Opacity = activatable ? 1.0 : 0.55;
        }

        private void CheckOption_Changed(object sender, RoutedEventArgs e)
        {
            if (_suppressPreferenceEvents || _services == null) return;
            if (sender is not WpfCheckBox cb) return;
            bool isOn = cb.IsChecked == true;
            var prefs = Prefs.Current;
            var c = Services;

            switch (cb.Tag as string)
            {
                case "Notifications":
                    prefs.ActionNotificationsEnabled = isOn;
                    prefs.Save();
                    c.Notifications.IsEnabled = isOn;
                    break;

                case "AutoStart":
                    SetAutoStart(isOn);
                    break;

                case "AutoUpdate":
                    c.ApplySignatureAutoUpdate(isOn);
                    break;

                case "UseClamd":
                    prefs.UseClamdEngine = isOn;
                    prefs.Save();
                    if (isOn)
                    {
                        _ = Task.Run(async () =>
                        {
                            try { await ClamdHost.Shared.EnsureRunningAsync(); }
                            catch (Exception ex) { AppLogger.Warn("Options", "clamd", ex); }
                        });
                    }
                    else
                        ClamdHost.Shared.Stop();
                    break;

                case "GameMode":
                    prefs.GameModeAutoEnabled = isOn;
                    prefs.Save();
                    if (isOn) DistractionFreeMonitor.Start();
                    else DistractionFreeMonitor.Stop();
                    break;

                case "RealtimeProtection":
                    c.ApplyRealtimeProtection(isOn);
                    break;

                case "ProcessMonitor":
                    c.ApplyProcessMonitor(isOn);
                    break;

                case "TamperProtection":
                    c.ApplyTamperProtection(isOn);
                    break;

                case "PlatformProtection":
                    if (!PlatformProtectionFeatureGate.IsUserActivatable)
                        break;
                    c.ApplyPlatformProtectionService(isOn);
                    break;

                case "BackupBeforeQuarantine":
                    prefs.BackupBeforeQuarantine = isOn;
                    prefs.Save();
                    break;

                case "AggressiveSignatures":
                    prefs.AggressiveSignatureUpdates = isOn;
                    prefs.Save();
                    if (prefs.SignatureAutoUpdateEnabled)
                        c.ApplySignatureAutoUpdate(true);
                    break;

                case "RemovableDriveScan":
                    c.ApplyRemovableDriveScan(isOn);
                    break;

                case "RemovableDriveDetailed":
                    prefs.RemovableDriveScanDetailed = isOn;
                    prefs.Save();
                    break;

                case "IncludeRemovableFullScan":
                    prefs.IncludeRemovableInFullScan = isOn;
                    prefs.Save();
                    break;

                case "AutoQuarantine":
                    c.ApplyAutoQuarantine(isOn);
                    break;

                case "AlternateTheme":
                    ThemeManager.SetAlternateThemeEnabled(isOn);
                    SyncThemeControls();
                    break;

                case "ScheduledScan":
                    // schtasks peut prendre jusqu'à ~15 s : on déporte en Task.Run
                    // pour ne pas geler le thread UI, et on désactive la case pendant ce temps.
                    if (chkScheduledScan != null) chkScheduledScan.IsEnabled = false;
                    if (pnlScheduleTime != null) pnlScheduleTime.IsEnabled = false;
                    if (btnScheduledRunNow != null) btnScheduledRunNow.IsEnabled = false;
                    var schedTime = GetSelectedScheduleTime();
                    _ = ApplyScheduledScanAsync(isOn, schedTime);
                    break;
            }
        }

        /// <summary>
        /// Crée ou supprime la tâche planifiée hors thread UI (schtasks peut prendre ~15 s).
        /// Réactive les contrôles et affiche le statut une fois terminé.
        /// </summary>
        private async System.Threading.Tasks.Task ApplyScheduledScanAsync(bool enable, TimeSpan? schedTime)
        {
            try
            {
                bool ok = await System.Threading.Tasks.Task.Run(() =>
                    ScheduledScanApply.SetEnabled(enable, schedTime, ScheduledScan));

                if (enable && !ok)
                    System.Windows.MessageBox.Show(
                        LocalizationService.GetString("Opt_SchedTaskFailed"),
                        LocalizationService.GetString("Opt_SchedTaskTitle"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
            }
            finally
            {
                // Toujours sur le thread UI.
                _suppressPreferenceEvents = true;
                try
                {
                    bool exists = await System.Threading.Tasks.Task.Run(() => ScheduledScan.IsTaskExists());
                    if (chkScheduledScan != null)
                    {
                        chkScheduledScan.IsChecked = exists;
                        chkScheduledScan.IsEnabled = true;
                    }
                }
                finally { _suppressPreferenceEvents = false; }
                await RefreshScheduledStatusAsync();
            }
        }

        private void SelectUiLanguageCombo(string? culture)
        {
            if (cmbUiLanguage == null) return;

            var normalized = string.IsNullOrWhiteSpace(culture)
                ? LocalizationService.CurrentCulture.Name
                : culture;

            var wantEn = normalized.StartsWith("en", StringComparison.OrdinalIgnoreCase);
            cmbUiLanguage.SelectedIndex = wantEn ? 1 : 0;
        }

        private void ComboBox_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (sender is not System.Windows.Controls.ComboBox cb || cb.IsDropDownOpen)
                return;

            cb.Focus();
            cb.IsDropDownOpen = true;
            e.Handled = true;
        }

        private void ComboBox_DropDownOpened(object sender, EventArgs e)
        {
            if (sender == cmbUiLanguage)
            {
                _languageTagBeforeDropDown = GetSelectedLanguageTag();
            }
            else if (sender == cmbFavoriteScan)
            {
                _favoriteScanIndexBeforeDropDown = cmbFavoriteScan?.SelectedIndex ?? -1;
            }
        }

        private string? GetSelectedLanguageTag()
        {
            if (cmbUiLanguage?.SelectedItem is System.Windows.Controls.ComboBoxItem item)
                return item.Tag as string;
            return null;
        }

        private void CmbUiLanguage_DropDownClosed(object sender, EventArgs e)
        {
            if (_suppressPreferenceEvents)
                return;

            var tag = GetSelectedLanguageTag();
            if (string.IsNullOrWhiteSpace(tag))
                return;

            if (string.Equals(tag, _languageTagBeforeDropDown, StringComparison.OrdinalIgnoreCase))
                return;

            var selected = tag.StartsWith("en", StringComparison.OrdinalIgnoreCase) ? "en-US" : "fr-FR";
            var currentNormalized = LocalizationService.IsEnglish ? "en-US" : "fr-FR";

            if (string.Equals(selected, currentNormalized, StringComparison.OrdinalIgnoreCase))
                return;

            var confirm = System.Windows.MessageBox.Show(
                LocalizationService.GetString("Opt_LangRestartMessage"),
                LocalizationService.GetString("Opt_LangRestartTitle"),
                MessageBoxButton.OKCancel,
                MessageBoxImage.Information);

            if (confirm != MessageBoxResult.OK)
            {
                _suppressPreferenceEvents = true;
                try { SelectUiLanguageCombo(currentNormalized); }
                finally { _suppressPreferenceEvents = false; }
                return;
            }

            LocalizationService.SetUserCulture(selected);
            LocalizationService.RestartApplication();
        }

        private void CmbFavoriteScan_DropDownClosed(object sender, EventArgs e)
        {
            if (_suppressPreferenceEvents || cmbFavoriteScan == null)
                return;

            if (cmbFavoriteScan.SelectedIndex == _favoriteScanIndexBeforeDropDown)
                return;

            var prefs = Prefs.Current;
            prefs.FavoriteScanType = cmbFavoriteScan.SelectedIndex switch
            {
                1 => ScanType.FullScan,
                2 => ScanType.Folder,
                3 => ScanType.File,
                _ => ScanType.QuickScan
            };
            prefs.Save();
        }

        private async void BtnScheduledRunNow_Click(object sender, RoutedEventArgs e)
        {
            bool exists = await System.Threading.Tasks.Task.Run(() => ScheduledScan.IsTaskExists());
            if (!exists)
            {
                System.Windows.MessageBox.Show(LocalizationService.GetString("Opt_SchedEnableFirst"), LocalizationService.GetString("App_TitleShort"), MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (btnScheduledRunNow != null) btnScheduledRunNow.IsEnabled = false;
            try
            {
                bool ok = await System.Threading.Tasks.Task.Run(() => ScheduledScan.RunNow());
                if (!ok)
                {
                    System.Windows.MessageBox.Show(LocalizationService.GetString("Opt_SchedRunFailed"), LocalizationService.GetString("App_TitleShort"),
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                System.Windows.MessageBox.Show(
                    LocalizationService.GetString("Opt_SchedRunOk"),
                    LocalizationService.GetString("App_TitleShort"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                await RefreshScheduledStatusAsync();
            }
            finally
            {
                if (btnScheduledRunNow != null) btnScheduledRunNow.IsEnabled = true;
            }
        }

        private static void SetAutoStart(bool enable)
        {
            const string regKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
            const string appName = "optiCombat";
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regKey, writable: true);
                if (key == null) return;
                if (enable)
                    key.SetValue(appName, $"\"{System.Reflection.Assembly.GetExecutingAssembly().Location}\"");
                else
                    key.DeleteValue(appName, throwOnMissingValue: false);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("OptionsControl", "SetAutoStart", ex);
            }
        }

        private void BtnAddTypedExclusion_Click(object sender, RoutedEventArgs e)
        {
            var path = txtNewExclusion?.Text?.Trim() ?? string.Empty;
            if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            {
                System.Windows.MessageBox.Show(LocalizationService.GetString("Opt_ExclNeedFolder"), LocalizationService.GetString("App_TitleShort"), MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            if (Excl.Current.AddFolder(path) && !_exclusions.Contains(path))
                _exclusions.Add(path);
            if (txtNewExclusion != null) txtNewExclusion.Text = string.Empty;
        }

        private async void BtnCheckAppUpdate_Click(object sender, RoutedEventArgs e)
        {
            AppUpdateCheckResult result;
            try
            {
                result = await new UpdateService().CheckForUpdatesAsync().ConfigureAwait(true);
            }
            catch (Exception ex)
            {
                AppLogger.Error("OptionsControl", "CheckForUpdatesAsync", ex);
                result = new AppUpdateCheckResult
                {
                    Status = AppUpdateChannelStatus.StagingError,
                    CurrentVersion = ProductVersionInfo.SemVer,
                    ReleaseLabel = ProductVersionInfo.ReleaseLabel,
                    UserMessage = LocalizationService.Format("Opt_AppUpdateCheckError", ex.Message),
                };
            }

            System.Windows.MessageBox.Show(
                result.UserMessage,
                LocalizationService.GetString("Opt_AppUpdateTitle"),
                MessageBoxButton.OK,
                result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }

        private async void BtnOpenSourceForge_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = OpticombatStrings.Urls.OpticombatSourceForge,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                AppLogger.Warn("OptionsControl", "Navigate SourceForge", ex);
            }
            await Task.CompletedTask;
        }

        private void BtnAddExclusion_Click(object sender, RoutedEventArgs e)
        {
            using var dlg = new WinForms.FolderBrowserDialog
            {
                Description = LocalizationService.GetString("Opt_ExclFolderPickerDesc")
            };

            if (dlg.ShowDialog() == WinForms.DialogResult.OK)
            {
                var path = dlg.SelectedPath;
                if (!_exclusions.Contains(path))
                {
                    _exclusions.Add(path);
                    Excl.Current.AddFolder(path);
                }
            }
        }

        private void BtnRemoveExclusion_Click(object sender, RoutedEventArgs e)
        {
            if (sender is WpfButton btn && btn.Tag is string path)
            {
                if (ExclusionSettings.IsMandatoryExcludedFolder(path))
                    return;

                _exclusions.Remove(path);
                Excl.Current.RemoveFolder(path);
            }
        }

        private void PwdVirusTotalApiKey_Changed(object sender, RoutedEventArgs e)
        {
            if (_suppressPreferenceEvents) return;
            Prefs.Current.VirusTotalApiKey = pwdVirusTotalApiKey?.Password ?? string.Empty;
            Prefs.Current.Save();
        }

        /// <summary>N'autorise que les chiffres dans les TextBox de seuils.</summary>
        private void NumericOnly_PreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e)
        {
            e.Handled = !e.Text.All(char.IsDigit);
        }

        /// <summary>Sauvegarde la valeur d'un seuil quand le TextBox perd le focus.</summary>
        private void ThresholdBox_LostFocus(object sender, RoutedEventArgs e)
        {
            if (_suppressPreferenceEvents) return;
            if (sender is not System.Windows.Controls.TextBox box) return;

            if (!int.TryParse(box.Text, out int value) || value < 1 || value > 365)
            {
                // Valeur invalide : réinitialiser au défaut
                var tag = box.Tag as string;
                value = tag == "CleanThreshold"
                    ? RecommendationThresholds.CleanSuggestThresholdDays
                    : RecommendationThresholds.SignatureStaleThresholdDays;
                box.Text = value.ToString();
            }

            var prefs = Prefs.Current;
            switch (box.Tag as string)
            {
                case "CleanThreshold":
                    prefs.CleanSuggestThresholdDays = value;
                    break;
                case "SigThreshold":
                    prefs.SignatureStaleThresholdDays = value;
                    break;
            }
            prefs.Save();
        }
    }
}
