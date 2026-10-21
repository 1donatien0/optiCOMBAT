using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using optiCombat.Localization;
using optiCombat.WinUI.Services;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.WinUI.Views;

public sealed partial class OptionsPage : UserControl
{
    private bool _syncing;

    public OptionsViewModel ViewModel { get; }

    public OptionsPage(OptionsViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        ExclusionsList.ItemsSource = ViewModel.Exclusions;
        InitThemePresetCombo();
        Loaded += (_, _) => SyncFromViewModel();
    }

    private void InitThemePresetCombo()
    {
        ThemePresetCombo.Items.Clear();
        foreach (var pack in WinUiThemePacks.All)
        {
            ThemePresetCombo.Items.Add(new ComboBoxItem
            {
                Content = LocalizationService.GetString(pack.NameKey),
                Tag = pack.Id,
            });
        }
    }

    private void SyncFromViewModel()
    {
        _syncing = true;
        TglNotifications.IsOn = ViewModel.NotificationsEnabled;
        TglAutoStart.IsOn = ViewModel.AutoStart;
        TglDarkTheme.IsOn = ViewModel.DarkTheme;
        TglSyncTheme.IsOn = ViewModel.SyncWindowsTheme;
        TglDefenderComplement.IsOn = ViewModel.DefenderComplementMode;
        TglDefenderComplement.IsEnabled = ViewModel.DefenderActive || ViewModel.DefenderComplementMode;
        DefenderComplementCaption.Text = ViewModel.DefenderComplementCaption;
        TglHighContrast.IsOn = ViewModel.HighContrast;
        ThemeAccentBox.Text = ViewModel.ThemeAccentColor;
        SelectThemePresetCombo(ViewModel.ThemePresetId);
        TglGameMode.IsOn = ViewModel.GameMode;
        TglRtp.IsOn = ViewModel.RealtimeProtection;
        TglAutoQuarantine.IsOn = ViewModel.AutoQuarantine;
        TglBackupQuarantine.IsOn = ViewModel.BackupBeforeQuarantine;
        TglAutoUpdate.IsOn = ViewModel.AutoUpdateSignatures;
        TglAggressiveSig.IsOn = ViewModel.AggressiveSignatureUpdates;
        TglProcessMonitor.IsOn = ViewModel.ProcessMonitor;
        TglTamper.IsOn = ViewModel.TamperProtection;
        TglRemovableDrive.IsOn = ViewModel.RemovableDriveScan;
        TglRemovableDetailed.IsOn = ViewModel.RemovableDriveDetailed;
        TglRemovableFullScan.IsOn = ViewModel.IncludeRemovableInFullScan;
        TglClamd.IsOn = ViewModel.UseClamd;
        TglNativeEngine.IsOn = ViewModel.UseNativeEngine;
        CleanThresholdBox.Value = ViewModel.CleanThresholdDays;
        SignatureStaleBox.Value = ViewModel.SignatureStaleDays;
        ScheduleHourBox.Value = ViewModel.ScheduledHour;
        ScheduleMinuteBox.Value = ViewModel.ScheduledMinute;
        ScheduledStatusText.Text = ViewModel.ScheduledStatus;
        AppVersionText.Text = ViewModel.AppVersionLabel;
        UpdateStatusText.Text = ViewModel.UpdateStatusMessage;
        VirusTotalBox.Password = ViewModel.VirusTotalApiKey;
        FavoriteScanCombo.SelectedIndex = ViewModel.FavoriteScanIndex;

        for (int i = 0; i < LanguageCombo.Items.Count; i++)
        {
            if (LanguageCombo.Items[i] is ComboBoxItem item
                && item.Tag as string == ViewModel.UiCulture)
            {
                LanguageCombo.SelectedIndex = i;
                break;
            }
        }

        _syncing = false;
    }

    private void Notifications_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveNotifications(TglNotifications.IsOn);
    }

    private void AutoStart_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveAutoStart(TglAutoStart.IsOn);
    }

    private void DarkTheme_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.ApplyTheme(TglDarkTheme.IsOn);
        _syncing = true;
        TglSyncTheme.IsOn = false;
        _syncing = false;
    }

    private void SyncTheme_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveSyncWindowsTheme(TglSyncTheme.IsOn);
        _syncing = true;
        TglDarkTheme.IsOn = ViewModel.DarkTheme;
        _syncing = false;
    }

    private void DefenderComplement_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveDefenderComplementMode(TglDefenderComplement.IsOn);
        _syncing = true;
        TglRtp.IsOn = ViewModel.RealtimeProtection;
        TglProcessMonitor.IsOn = ViewModel.ProcessMonitor;
        _syncing = false;
    }

    private void HighContrast_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveHighContrast(TglHighContrast.IsOn);
    }

    private void SelectThemePresetCombo(string presetId)
    {
        for (int i = 0; i < ThemePresetCombo.Items.Count; i++)
        {
            if (ThemePresetCombo.Items[i] is ComboBoxItem item
                && string.Equals(item.Tag as string, presetId, StringComparison.OrdinalIgnoreCase))
            {
                ThemePresetCombo.SelectedIndex = i;
                return;
            }
        }
    }

    private void ThemePreset_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || ThemePresetCombo.SelectedItem is not ComboBoxItem item || item.Tag is not string id)
            return;
        ViewModel.SetThemePreset(id);
    }

    private void ThemeAccent_LostFocus(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;

        var text = ThemeAccentBox.Text.Trim();
        if (text.Length > 0)
        {
            if (!WinUiThemeManager.TryParseColor(text, out var color))
            {
                // Saisie invalide : on rétablit la valeur enregistrée.
                ThemeAccentBox.Text = ViewModel.ThemeAccentColor;
                return;
            }
            text = $"#{color.R:X2}{color.G:X2}{color.B:X2}";
            ThemeAccentBox.Text = text;
        }

        if (string.Equals(text, ViewModel.ThemeAccentColor, StringComparison.OrdinalIgnoreCase))
            return;
        ViewModel.SetThemeAccentColor(text);
    }

    private void GameMode_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveGameMode(TglGameMode.IsOn);
    }

    private void Rtp_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveRealtimeProtection(TglRtp.IsOn);
    }

    private void AutoQuarantine_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveAutoQuarantine(TglAutoQuarantine.IsOn);
    }

    private void BackupQuarantine_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveBackupBeforeQuarantine(TglBackupQuarantine.IsOn);
    }

    private void AutoUpdate_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveAutoUpdate(TglAutoUpdate.IsOn);
    }

    private void AggressiveSig_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveAggressiveSignatures(TglAggressiveSig.IsOn);
    }

    private void ProcessMonitor_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveProcessMonitor(TglProcessMonitor.IsOn);
    }

    private void Tamper_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveTamperProtection(TglTamper.IsOn);
    }

    private void RemovableDrive_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveRemovableDriveScan(TglRemovableDrive.IsOn);
    }

    private void RemovableDetailed_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveRemovableDriveDetailed(TglRemovableDetailed.IsOn);
    }

    private void RemovableFullScan_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveIncludeRemovableInFullScan(TglRemovableFullScan.IsOn);
    }

    private void Clamd_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveUseClamd(TglClamd.IsOn);
    }

    private void NativeEngine_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveUseNativeEngine(TglNativeEngine.IsOn);
    }

    private async void ScheduledScan_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.ScheduledHour = (int)ScheduleHourBox.Value;
        ViewModel.ScheduledMinute = (int)ScheduleMinuteBox.Value;
        await ViewModel.ToggleScheduledScanAsync(TglScheduledScan.IsOn);
        ScheduledStatusText.Text = ViewModel.ScheduledStatus;
    }

    private void Language_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing || LanguageCombo.SelectedItem is not ComboBoxItem item || item.Tag is not string culture)
            return;
        ViewModel.SaveUiCulture(culture);
    }

    private void FavoriteScan_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveFavoriteScan(FavoriteScanCombo.SelectedIndex);
    }

    private void VirusTotal_Changed(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        ViewModel.SaveVirusTotalKey(VirusTotalBox.Password);
    }

    private async void BrowseExclusion_Click(object sender, RoutedEventArgs e)
    {
        var path = await PickFolderAsync();
        if (!string.IsNullOrWhiteSpace(path))
            ExclusionInput.Text = path;
    }

    private async void AddExclusion_Click(object sender, RoutedEventArgs e)
    {
        var path = ExclusionInput.Text?.Trim();
        if (string.IsNullOrWhiteSpace(path))
        {
            path = await PickFolderAsync();
            if (string.IsNullOrWhiteSpace(path))
                return;
        }

        ViewModel.AddExclusion(path);
        ExclusionInput.Text = string.Empty;
    }

    private void RemoveExclusion_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string path)
            ViewModel.RemoveExclusion(path);
    }

    private void Thresholds_Changed(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (_syncing || double.IsNaN(args.NewValue)) return;
        ViewModel.CleanThresholdDays = (int)CleanThresholdBox.Value;
        ViewModel.SignatureStaleDays = (int)SignatureStaleBox.Value;
        ViewModel.SaveThresholds();
    }

    private async void CheckUpdates_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.CheckAppUpdatesAsync();
        UpdateStatusText.Text = ViewModel.UpdateStatusMessage;
    }

    private async void RunScheduleNow_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.RunScheduleNowAsync();
        ScheduledStatusText.Text = ViewModel.ScheduledStatus;
    }

    private void OpenLogsFolder_Click(object sender, RoutedEventArgs e) => ViewModel.OpenLogsFolder();

    private void License_Click(object sender, RoutedEventArgs e) => ViewModel.OpenBundledDocument("LICENSE.txt");

    private async void DefenderExclusions_Click(object sender, RoutedEventArgs e)
    {
        DefenderExclusionButton.IsEnabled = false;
        DefenderExclusionStatusText.Text = LocalizationService.GetString("Opt_DefenderExclusionsApplying");
        try
        {
            DefenderExclusionStatusText.Text = await ViewModel.ApplyDefenderExclusionsAsync();
        }
        finally
        {
            DefenderExclusionButton.IsEnabled = true;
        }
    }

    // Sélecteur Win32 natif : le FolderPicker WinRT échoue quand l'application tourne en administrateur.
    private static Task<string?> PickFolderAsync() =>
        Task.FromResult(WinUiNativeDialogs.PickFolder(LocalizationService.GetString("Opt_PickExclusionTitle")));
}
