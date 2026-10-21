using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using optiCombat.WinUI.Services;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.WinUI.Views;

public sealed partial class CleanPage : UserControl
{
    // Les Checked="Option_Changed" se déclenchent pendant InitializeComponent
    // (IsChecked="True" en XAML) alors que les autres cases sont encore null.
    private readonly bool _uiReady;

    public CleanViewModel ViewModel { get; }

    public CleanPage(CleanViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        UpdatesHost.Content = new UpdatesPanel(ViewModel.Updates);
        TweaksHost.Content = new TweaksPanel(ViewModel.Tweaks);
        _uiReady = true;
        SyncOptionsFromUi();
        ViewModel.PropertyChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);
        SyncUi();
    }

    private void OptimiserTabs_SelectionChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs e)
    {
        var selected = OptimiserTabs.SelectedItem ?? CleanTab;
        CleanPanel.Visibility = ReferenceEquals(selected, CleanTab) ? Visibility.Visible : Visibility.Collapsed;
        UpdatesHost.Visibility = ReferenceEquals(selected, UpdatesTab) ? Visibility.Visible : Visibility.Collapsed;
        TweaksHost.Visibility = ReferenceEquals(selected, TweaksTab) ? Visibility.Visible : Visibility.Collapsed;
    }

    private void SyncUi()
    {
        TempSizeText.Text = ViewModel.TempSize;
        BrowserSizeText.Text = ViewModel.BrowserSize;
        TotalSizeText.Text = ViewModel.TotalSize;
        LogText.Text = ViewModel.LogText;
        CopyLogButton.IsEnabled = ViewModel.HasLog;
        AnalyzeButton.IsEnabled = ViewModel.CanAnalyze;
        CleanButton.IsEnabled = ViewModel.CanClean;
        UiPhaseVisibility.ApplyCleanLogPhase(ViewModel.IsBusy, !ViewModel.HasLog, LogScroll, EmptyLogState, LogProgress);
        UiPhaseVisibility.ApplyCleanActionPhase(ViewModel.IsBusy, BusyRing);
    }

    private void SyncOptionsFromUi()
    {
        if (!_uiReady)
            return;

        ViewModel.TempWin = ChkTempWin.IsChecked == true;
        ViewModel.TempUser = ChkTempUser.IsChecked == true;
        ViewModel.Recycle = ChkRecycle.IsChecked == true;
        ViewModel.Logs = ChkLogs.IsChecked == true;
        ViewModel.Edge = ChkEdge.IsChecked == true;
        ViewModel.Chrome = ChkChrome.IsChecked == true;
        ViewModel.Firefox = ChkFirefox.IsChecked == true;
        ViewModel.Brave = ChkBrave.IsChecked == true;
        ViewModel.Opera = ChkOpera.IsChecked == true;
        ViewModel.Vivaldi = ChkVivaldi.IsChecked == true;
        ViewModel.Arc = ChkArc.IsChecked == true;
        ViewModel.WUCache = ChkWUCache.IsChecked == true;
        ViewModel.Dns = ChkDns.IsChecked == true;
        ViewModel.History = ChkHistory.IsChecked == true;
    }

    private void CopyLog_Click(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.HasLog)
            return;

        var package = new Windows.ApplicationModel.DataTransfer.DataPackage();
        package.SetText(ViewModel.LogText);
        Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(package);
    }

    private void Option_Changed(object sender, RoutedEventArgs e) => SyncOptionsFromUi();

    private async void Analyze_Click(object sender, RoutedEventArgs e)
    {
        SyncOptionsFromUi();
        await ViewModel.AnalyzeAsync();
    }

    private async void Clean_Click(object sender, RoutedEventArgs e)
    {
        SyncOptionsFromUi();
        await ViewModel.CleanAsync();
    }
}
