using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using optiCombat.WinUI.ViewModels;
using WinRT.Interop;
using Windows.Storage.Pickers;

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
        Loaded += (_, _) => SyncFromViewModel();
    }

    private void SyncFromViewModel()
    {
        _syncing = true;
        TglNotifications.IsOn = ViewModel.NotificationsEnabled;
        TglAutoStart.IsOn = ViewModel.AutoStart;
        TglDarkTheme.IsOn = ViewModel.DarkTheme;
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

    private static async Task<string?> PickFolderAsync()
    {
        var picker = new FolderPicker();
        picker.FileTypeFilter.Add("*");
        var hwnd = WindowNative.GetWindowHandle(App.MainWindowInstance);
        InitializeWithWindow.Initialize(picker, hwnd);
        var folder = await picker.PickSingleFolderAsync();
        return folder?.Path;
    }
}
