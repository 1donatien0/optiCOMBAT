using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.WinUI.Views;

/// <summary>Onglet « Mises à jour » du panneau Optimiser (applications via winget + Windows Update).</summary>
public sealed partial class UpdatesPanel : UserControl
{
    public UpdatesViewModel ViewModel { get; }

    public UpdatesPanel(UpdatesViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        ViewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(UpdatesViewModel.LogText))
                DispatcherQueue.TryEnqueue(() => LogScroll.ChangeView(null, LogScroll.ScrollableHeight, null));
        };
    }

    private async void Scan_Click(object sender, RoutedEventArgs e) => await ViewModel.ScanAsync();

    private async void UpdateSelected_Click(object sender, RoutedEventArgs e) => await ViewModel.UpdateSelectedAsync();

    private async void UpdateAll_Click(object sender, RoutedEventArgs e) => await ViewModel.UpdateAllAsync();

    private void WindowsUpdate_Click(object sender, RoutedEventArgs e) => ViewModel.OpenWindowsUpdate();
}
