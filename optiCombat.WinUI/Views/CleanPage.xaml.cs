using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.WinUI.Views;

public sealed partial class CleanPage : UserControl
{
    public CleanViewModel ViewModel { get; }

    public CleanPage(CleanViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        ViewModel.PropertyChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);
        SyncUi();
    }

    private void SyncUi()
    {
        TempSizeText.Text = ViewModel.TempSize;
        BrowserSizeText.Text = ViewModel.BrowserSize;
        TotalSizeText.Text = ViewModel.TotalSize;
        LogText.Text = ViewModel.LogText;
        AnalyzeButton.IsEnabled = ViewModel.CanAnalyze;
        CleanButton.IsEnabled = ViewModel.CanClean;
        BusyRing.Visibility = ViewModel.IsBusy ? Visibility.Visible : Visibility.Collapsed;
    }

    private void SyncOptionsFromUi()
    {
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
