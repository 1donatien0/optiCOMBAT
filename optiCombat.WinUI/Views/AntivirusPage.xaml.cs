using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Views;
using optiCombat.WinUI.Services;
using optiCombat.WinUI.ViewModels;
using WinUiApp = Microsoft.UI.Xaml.Application;

namespace optiCombat.WinUI.Views;

public sealed partial class AntivirusPage : UserControl, IAntivirusSignaturesPanel
{
    public AntivirusViewModel ViewModel { get; }

    // Onglet demandé par l'appelant (accueil, toast, menu…). Conservé jusqu'à ce que le TabView soit
    // réellement chargé ET que la sélection ait été confirmée : le premier onglet porte
    // IsSelected="True" et l'application du gabarit du TabView réinitialise sinon la sélection
    // sur « Analyse » (symptôme : « Mise à jour » depuis l'accueil retombait sur l'onglet Analyse).
    private int _requestedTabIndex = -1;

    public AntivirusPage(AntivirusViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        DataContext = ViewModel;
        ThreatsList.ItemsSource = ViewModel.Threats;
        QuarantineList.ItemsSource = ViewModel.QuarantineEntries;
        RecentList.ItemsSource = ViewModel.RecentTargets;
        ViewModel.PropertyChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);
        WinUiThemeManager.ThemeChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);
        Tabs.Loaded += (_, _) => ApplyRequestedTab();
        Loaded += async (_, _) =>
        {
            ApplyRequestedTab();
            await ViewModel.InitializeAsync();
        };
        SyncUi();
    }

    /// <summary>Sélectionne l'onglet Analyse (0), Signatures (1) ou Quarantaine (2).</summary>
    public void SelectScanTab() => SelectTab(0);

    public void SelectSignaturesTab() => SelectTab(1);

    public void SelectQuarantineTab() => SelectTab(2);

    private void SelectTab(int index)
    {
        _requestedTabIndex = index;
        ApplyRequestedTab();
    }

    private void ApplyRequestedTab()
    {
        var index = _requestedTabIndex;
        if (index < 0)
            return;

        if (Tabs.IsLoaded)
            Tabs.SelectedIndex = index;

        // Le gabarit du TabView peut encore (ré)sélectionner le premier onglet juste après le
        // chargement : on confirme en fin de file d'attente UI avant d'oublier la demande.
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () =>
        {
            if (_requestedTabIndex != index)
                return; // une demande plus récente a pris le relais

            if (!Tabs.IsLoaded)
                return; // sera réappliqué par Tabs.Loaded

            if (Tabs.SelectedIndex != index)
                Tabs.SelectedIndex = index;

            _requestedTabIndex = -1;
        });
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
            ProtectionBadgeLevel.Active => WinUiThemeManager.GetBrush("AccentBrush"),
            ProtectionBadgeLevel.Degraded => WinUiThemeManager.GetBrush("WarningBrush"),
            _ => WinUiThemeManager.GetBrush("DangerBrush")
        };

        ScanHubPanel.Visibility = ViewModel.IsScanning ? Visibility.Collapsed : Visibility.Visible;
        ScanProgressPanel.Visibility = ViewModel.IsScanning ? Visibility.Visible : Visibility.Collapsed;
        ScanProgressBar.IsIndeterminate = ViewModel.IsScanning;
        ScanStatusText.Text = ViewModel.StatusMessage;
        ScanCurrentItemText.Text = ViewModel.CurrentScanItem;

        FilesScannedText.Text = LocalizationService.Format("Av_FilesCountFmt", ViewModel.FilesScanned);
        ThreatsFoundText.Text = LocalizationService.Format("Av_ThreatsCountFmt", ViewModel.ThreatsFound);
        QuarantineCountText.Text = LocalizationService.Format("Av_QuarantineCountFmt", ViewModel.QuarantineCount);

        YaraVersionText.Text = ViewModel.YaraVersion;
        YaraUpdateText.Text = ViewModel.YaraLastUpdate;
        ClamVersionText.Text = ViewModel.ClamVersion;
        ClamUpdateText.Text = ViewModel.ClamLastUpdate;
        SignatureLogText.Text = ViewModel.SignatureLog;

        RecentRow.Visibility = !ViewModel.IsScanning && ViewModel.RecentTargets.Count > 0
            ? Visibility.Visible
            : Visibility.Collapsed;

        var updating = ViewModel.IsUpdating;
        SigUpdateProgress.Visibility = updating ? Visibility.Visible : Visibility.Collapsed;
        StopUpdateButton.Visibility = updating ? Visibility.Visible : Visibility.Collapsed;
        UpdateSignaturesButton.IsEnabled = !updating;

        LoadMoreQuarantineButton.Visibility = ViewModel.QuarantineHasMore ? Visibility.Visible : Visibility.Collapsed;
        QuarantinePagingText.Text = ViewModel.QuarantinePagingStatus;
        PurgeQuarantineButton.IsEnabled = ViewModel.QuarantineTotalCount > 0;
    }

    private async void QuickScan_Click(object sender, RoutedEventArgs e) => await ViewModel.QuickScanAsync();
    private async void FullScan_Click(object sender, RoutedEventArgs e) => await ViewModel.FullScanAsync();
    private void StopScan_Click(object sender, RoutedEventArgs e) => ViewModel.StopScan();
    private void QuarantineAll_Click(object sender, RoutedEventArgs e) => ViewModel.QuarantineAllThreats();
    private async void UpdateSignatures_Click(object sender, RoutedEventArgs e) => await ViewModel.UpdateSignaturesAsync();
    private void StopUpdate_Click(object sender, RoutedEventArgs e) => ViewModel.StopSignatureUpdate();
    private void LoadMoreQuarantine_Click(object sender, RoutedEventArgs e) => ViewModel.LoadMoreQuarantine();
    private void PurgeQuarantine_Click(object sender, RoutedEventArgs e) => ViewModel.PurgeQuarantine();

    private async void RecentTarget_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: RecentScanTarget target })
            await ViewModel.ScanRecentAsync(target);
    }

    private async void Reputation_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path })
            await ViewModel.ShowReputationAsync(path);
    }

    private void IgnoreThreat_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path })
            ViewModel.IgnoreThreat(path);
    }

    private void QuarantineThreat_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path })
            ViewModel.QuarantineThreat(path);
    }

    private void DeleteThreat_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path })
            ViewModel.DeleteThreat(path);
    }

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

    // Sélecteurs Win32 natifs : les pickers WinRT échouent quand l'application tourne en administrateur.
    private static Task<string?> PickFileAsync() =>
        Task.FromResult(WinUiNativeDialogs.PickFile(LocalizationService.GetString("Av_PickFileTitle")));

    private static Task<string?> PickFolderAsync() =>
        Task.FromResult(WinUiNativeDialogs.PickFolder(LocalizationService.GetString("Av_PickFolderTitle")));
}
