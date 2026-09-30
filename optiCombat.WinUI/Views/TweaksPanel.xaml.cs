using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.WinUI.Views;

/// <summary>Onglet « Tweaks » du panneau Optimiser (performance, confidentialité, interface, maintenance).</summary>
public sealed partial class TweaksPanel : UserControl
{
    public TweaksViewModel ViewModel { get; }

    public TweaksPanel(TweaksViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
        ViewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(TweaksViewModel.LogText))
                DispatcherQueue.TryEnqueue(() => LogScroll.ChangeView(null, LogScroll.ScrollableHeight, null));
        };
    }

    private async void Apply_Click(object sender, RoutedEventArgs e) => await ViewModel.ApplyAsync();

    private void Startup_Click(object sender, RoutedEventArgs e) => ViewModel.OpenStartupApps();
}
