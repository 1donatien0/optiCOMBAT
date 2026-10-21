using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Views;
using optiCombat.WinUI.Services;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.WinUI.Views;

public sealed partial class AntivirusPage : UserControl, IAntivirusSignaturesPanel
{
    public AntivirusViewModel ViewModel { get; }

    private SelectorBarItem? _requestedSection;
    private bool _applyingSection;
    private bool? _isNarrowLayout;

    public AntivirusPage(AntivirusViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        DataContext = ViewModel;
        ThreatsList.ItemsSource = ViewModel.Threats;
        QuarantineList.ItemsSource = ViewModel.QuarantineEntries;
        RecentList.ItemsSource = ViewModel.RecentTargets;
        ViewModel.PropertyChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);
        ViewModel.Threats.CollectionChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);
        ViewModel.RecentTargets.CollectionChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);
        ViewModel.QuarantineEntries.CollectionChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);
        WinUiThemeManager.ThemeChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);
        Loaded += async (_, _) =>
        {
            ApplyRequestedSection();
            await ViewModel.InitializeAsync();
        };
        SyncUi();
    }

    /// <summary>Sélectionne l'onglet Analyse (0), Signatures (1) ou Quarantaine (2).</summary>
    public void SelectScanTab() => SelectSection(ScanTab);

    public void SelectSignaturesTab() => SelectSection(SignaturesTab);

    public void SelectQuarantineTab()
    {
        SelectSection(QuarantineTab);
        ViewModel.LoadQuarantine(reset: true);
    }

    private void SelectSection(SelectorBarItem item)
    {
        _requestedSection = item;
        if (IsLoaded)
            ApplyRequestedSection();
    }

    /// <summary>
    /// SelectedItem seul ne déplace pas le surlignage du SelectorBar.
    /// IsSelected est posé sur chaque onglet, et rejoué au Loaded.
    /// </summary>
    private void ApplyRequestedSection()
    {
        var item = _requestedSection ?? ScanTab;
        if (_applyingSection)
            return;

        _applyingSection = true;
        try
        {
            item.IsSelected = true;
            if (!ReferenceEquals(ScanTab, item))
                ScanTab.IsSelected = false;
            if (!ReferenceEquals(SignaturesTab, item))
                SignaturesTab.IsSelected = false;
            if (!ReferenceEquals(QuarantineTab, item))
                QuarantineTab.IsSelected = false;
            MainTabs.SelectedItem = item;
            ApplySectionVisibility();
        }
        finally
        {
            _applyingSection = false;
        }
    }

    /// <summary>SelectorBar ne porte pas de contenu : on affiche le panneau de la section choisie.</summary>
    private void ApplySectionVisibility()
    {
        var selected = MainTabs.SelectedItem ?? ScanTab;
        ScanPanel.Visibility = ReferenceEquals(selected, ScanTab) ? Visibility.Visible : Visibility.Collapsed;
        SignaturesPanel.Visibility = ReferenceEquals(selected, SignaturesTab) ? Visibility.Visible : Visibility.Collapsed;
        QuarantinePanel.Visibility = ReferenceEquals(selected, QuarantineTab) ? Visibility.Visible : Visibility.Collapsed;
        ApplyScanPhase();
    }

    private bool OnScanSection => ReferenceEquals(MainTabs.SelectedItem ?? ScanTab, ScanTab);

    private void MainTabs_SelectionChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs e)
    {
        if (!_applyingSection && MainTabs.SelectedItem is SelectorBarItem selected)
            _requestedSection = selected;
        ApplySectionVisibility();
        if (ReferenceEquals(MainTabs.SelectedItem, QuarantineTab))
            ViewModel.LoadQuarantine(reset: true);
    }

    private void PageRoot_SizeChanged(object sender, SizeChangedEventArgs e) =>
        ApplyAdaptiveLayout(e.NewSize.Width);

    private void ApplyAdaptiveLayout(double width)
    {
        var narrow = width < 720;
        if (_isNarrowLayout == narrow)
            return;
        _isNarrowLayout = narrow;

        ScanHubPanel.ColumnDefinitions.Clear();
        ScanHubPanel.RowDefinitions.Clear();
        if (narrow)
        {
            ScanHubPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            ScanHubPanel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            ScanHubPanel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            ScanHubPanel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetColumn(QuickScanBtn, 0);
            Grid.SetRow(QuickScanBtn, 0);
            Grid.SetColumn(FullScanBtn, 0);
            Grid.SetRow(FullScanBtn, 1);
            Grid.SetColumn(ManualScanCol, 0);
            Grid.SetRow(ManualScanCol, 2);

            StatsThreatsGrid.ColumnDefinitions.Clear();
            StatsThreatsGrid.RowDefinitions.Clear();
            StatsThreatsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            StatsThreatsGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            StatsThreatsGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            Grid.SetColumn(StatsCard, 0);
            Grid.SetRow(StatsCard, 0);
            Grid.SetColumn(ThreatsCard, 0);
            Grid.SetRow(ThreatsCard, 1);
        }
        else
        {
            for (var i = 0; i < 3; i++)
                ScanHubPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            ScanHubPanel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetColumn(QuickScanBtn, 0);
            Grid.SetRow(QuickScanBtn, 0);
            Grid.SetColumn(FullScanBtn, 1);
            Grid.SetRow(FullScanBtn, 0);
            Grid.SetColumn(ManualScanCol, 2);
            Grid.SetRow(ManualScanCol, 0);

            StatsThreatsGrid.ColumnDefinitions.Clear();
            StatsThreatsGrid.RowDefinitions.Clear();
            StatsThreatsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(220) });
            StatsThreatsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            Grid.SetColumn(StatsCard, 0);
            Grid.SetRow(StatsCard, 0);
            Grid.SetColumn(ThreatsCard, 1);
            Grid.SetRow(ThreatsCard, 0);
        }
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

        ApplyScanPhase();
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

        RecentRow.Visibility = OnScanSection && !ViewModel.IsScanning && ViewModel.RecentTargets.Count > 0
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

    private void ApplyScanPhase() =>
        UiPhaseVisibility.ApplyAntivirusScanPhase(
            ViewModel.IsScanning,
            ViewModel.Threats.Count > 0,
            ScanHubPanel,
            ScanProgressPanel,
            ThreatsList,
            EmptyThreatsState,
            QuarantineAllButton,
            OnScanSection);

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
