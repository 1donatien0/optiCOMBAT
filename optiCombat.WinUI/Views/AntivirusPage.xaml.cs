using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using optiCombat.Services;
using optiCombat.Views;
using optiCombat.WinUI.ViewModels;
using WinRT.Interop;
using Windows.Storage.Pickers;
using WinUiApp = Microsoft.UI.Xaml.Application;

namespace optiCombat.WinUI.Views;

public sealed partial class AntivirusPage : UserControl, IAntivirusSignaturesPanel
{
    public AntivirusViewModel ViewModel { get; }

    public AntivirusPage(AntivirusViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        DataContext = ViewModel;
        ThreatsList.ItemsSource = ViewModel.Threats;
        QuarantineList.ItemsSource = ViewModel.QuarantineEntries;
        ViewModel.PropertyChanged += (_, e) => DispatcherQueue.TryEnqueue(SyncUi);
        Loaded += async (_, _) => await ViewModel.InitializeAsync();
        SyncUi();
    }

    public void UpdateSignaturesPanel(string yaraVersion, string yaraLastMaj, string clamVersion, string clamLastMaj)
    {
        ViewModel.YaraVersion = string.IsNullOrWhiteSpace(yaraVersion) ? "—" : yaraVersion;
        ViewModel.YaraLastUpdate = string.IsNullOrWhiteSpace(yaraLastMaj) ? "—" : yaraLastMaj;
        ViewModel.ClamVersion = VersionDisplayHelper.NormalizeForDisplay(string.IsNullOrWhiteSpace(clamVersion) ? null : clamVersion);
        ViewModel.ClamLastUpdate = string.IsNullOrWhiteSpace(clamLastMaj) ? "—" : clamLastMaj;
    }

    private void SyncUi()
    {
        InitRing.IsActive = ViewModel.IsInitializing;
        InitRing.Visibility = ViewModel.IsInitializing ? Visibility.Visible : Visibility.Collapsed;

        LastScanText.Text = ViewModel.LastScanDisplay;
        BadgeText.Text = ViewModel.ProtectionBadgeText;
        BadgeDot.Fill = ViewModel.ProtectionBadgeLevel switch
        {
            ProtectionBadgeLevel.Active => (Brush)WinUiApp.Current.Resources["AccentBrush"],
            ProtectionBadgeLevel.Degraded => (Brush)WinUiApp.Current.Resources["WarningBrush"],
            _ => new SolidColorBrush(Microsoft.UI.Colors.IndianRed)
        };

        ScanHubPanel.Visibility = ViewModel.IsScanning ? Visibility.Collapsed : Visibility.Visible;
        ScanProgressPanel.Visibility = ViewModel.IsScanning ? Visibility.Visible : Visibility.Collapsed;
        ScanProgressBar.IsIndeterminate = ViewModel.IsScanning;
        ScanStatusText.Text = ViewModel.StatusMessage;
        ScanCurrentItemText.Text = ViewModel.CurrentScanItem;

        FilesScannedText.Text = $"Fichiers : {ViewModel.FilesScanned:N0}";
        ThreatsFoundText.Text = $"Menaces : {ViewModel.ThreatsFound:N0}";
        QuarantineCountText.Text = $"Quarantaine : {ViewModel.QuarantineCount:N0}";

        YaraVersionText.Text = ViewModel.YaraVersion;
        YaraUpdateText.Text = ViewModel.YaraLastUpdate;
        ClamVersionText.Text = ViewModel.ClamVersion;
        ClamUpdateText.Text = ViewModel.ClamLastUpdate;
        SignatureLogText.Text = ViewModel.SignatureLog;
    }

    private async void QuickScan_Click(object sender, RoutedEventArgs e) => await ViewModel.QuickScanAsync();
    private async void FullScan_Click(object sender, RoutedEventArgs e) => await ViewModel.FullScanAsync();
    private void StopScan_Click(object sender, RoutedEventArgs e) => ViewModel.StopScan();
    private void QuarantineAll_Click(object sender, RoutedEventArgs e) => ViewModel.QuarantineAllThreats();
    private async void UpdateSignatures_Click(object sender, RoutedEventArgs e) => await ViewModel.UpdateSignaturesAsync();

    private async void BrowseFile_Click(object sender, RoutedEventArgs e)
    {
        var path = await PickFileAsync();
        if (!string.IsNullOrWhiteSpace(path))
            await ViewModel.ScanFileAsync(path);
    }

    private async void BrowseFolder_Click(object sender, RoutedEventArgs e)
    {
        var path = await PickFolderAsync();
        if (!string.IsNullOrWhiteSpace(path))
            await ViewModel.ScanFolderAsync(path);
    }

    private void RestoreQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string id })
            ViewModel.RestoreQuarantineEntry(id);
    }

    private void DeleteQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string id })
            ViewModel.DeleteQuarantineEntry(id);
    }

    private async Task<string?> PickFileAsync()
    {
        var picker = new FileOpenPicker { ViewMode = PickerViewMode.List, SuggestedStartLocation = PickerLocationId.ComputerFolder };
        picker.FileTypeFilter.Add("*");
        InitializePicker(picker);
        var file = await picker.PickSingleFileAsync();
        return file?.Path;
    }

    private async Task<string?> PickFolderAsync()
    {
        var picker = new FolderPicker();
        picker.FileTypeFilter.Add("*");
        InitializePicker(picker);
        var folder = await picker.PickSingleFolderAsync();
        return folder?.Path;
    }

    private void InitializePicker(object picker)
    {
        var window = App.MainWindowInstance;
        if (window == null)
            return;
        var hwnd = WindowNative.GetWindowHandle(window);
        InitializeWithWindow.Initialize(picker, hwnd);
    }
}
