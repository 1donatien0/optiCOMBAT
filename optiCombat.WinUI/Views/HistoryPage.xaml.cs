using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using optiCombat.Coordinators;
using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.ViewModels;
using optiCombat.WinUI.Services;

namespace optiCombat.WinUI.Views;

public sealed partial class HistoryPage : UserControl
{
    private readonly ServiceContainer _container;

    public HistoryViewModel ViewModel { get; }

    public HistoryPage(HistoryViewModel viewModel)
    {
        ViewModel = viewModel;
        _container = WinUiServiceHost.Instance.Container;
        InitializeComponent();
        TimelineList.ItemsSource = ViewModel.FilteredEntries;
        ViewModel.PropertyChanged += (_, _) => DispatcherQueue.TryEnqueue(SyncUi);
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        SyncUi();
    }

    public void Refresh() => ViewModel.Refresh();

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ServiceContainer.UiEvents.ScanHistoryViewsRefreshRequested += OnExternalRefresh;
        ServiceContainer.UiEvents.ReviewHistorySessionRequested += OnReviewSession;
        ViewModel.Refresh();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        ServiceContainer.UiEvents.ScanHistoryViewsRefreshRequested -= OnExternalRefresh;
        ServiceContainer.UiEvents.ReviewHistorySessionRequested -= OnReviewSession;
    }

    private void OnExternalRefresh(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(ViewModel.Refresh);

    private void OnReviewSession(object? sender, ScanSession session)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            ViewModel.TrySelectScanSession(session.SessionId);
            SyncUi();
        });
    }

    private void SyncUi()
    {
        ChipAll.Content = ViewModel.ChipAllLabel;
        ChipThreats.Content = ViewModel.ChipThreatsLabel;
        ChipCleanScans.Content = ViewModel.ChipCleanScansLabel;
        ChipCleans.Content = ViewModel.ChipCleansLabel;
        ChipQuarantine.Content = ViewModel.ChipQuarantineLabel;

        EmptyState.Visibility = ViewModel.IsEmpty ? Visibility.Visible : Visibility.Collapsed;
        TimelineList.Visibility = ViewModel.IsEmpty ? Visibility.Collapsed : Visibility.Visible;
        EmptyTitleText.Text = ViewModel.EmptyTitle;
        EmptySubtitleText.Text = ViewModel.EmptySubtitle;

        ExportPdfButton.IsEnabled = ViewModel.CanExportPdf;
        SessionInfoText.Text = ViewModel.SessionInfoText;
        ScanActionsPanel.Visibility = ViewModel.ShowScanActions ? Visibility.Visible : Visibility.Collapsed;

        var entry = ViewModel.SelectedEntry;
        if (entry == null)
        {
            NoSelectionText.Visibility = Visibility.Visible;
            ScanDetailPanel.Visibility = Visibility.Collapsed;
            CleanDetailPanel.Visibility = Visibility.Collapsed;
            QuarantineDetailPanel.Visibility = Visibility.Collapsed;
            return;
        }

        NoSelectionText.Visibility = Visibility.Collapsed;

        if (entry.Kind == ActivityKind.Quarantine)
        {
            ScanDetailPanel.Visibility = Visibility.Collapsed;
            CleanDetailPanel.Visibility = Visibility.Collapsed;
            QuarantineDetailPanel.Visibility = Visibility.Visible;
            QuarTitleText.Text = ViewModel.QuarantineDetailTitle;
            QuarPathText.Text = ViewModel.QuarantineDetailPath;
            QuarMetaText.Text = ViewModel.QuarantineDetailMeta;
            ViewSourceScanButton.Visibility = ViewModel.HasQuarantineSourceScan
                ? Visibility.Visible : Visibility.Collapsed;
            return;
        }

        if (entry.Kind == ActivityKind.Clean)
        {
            ScanDetailPanel.Visibility = Visibility.Collapsed;
            QuarantineDetailPanel.Visibility = Visibility.Collapsed;
            CleanDetailPanel.Visibility = Visibility.Visible;
            CleanLogText.Text = ViewModel.CleanLogText;
            return;
        }

        QuarantineDetailPanel.Visibility = Visibility.Collapsed;
        CleanDetailPanel.Visibility = Visibility.Collapsed;
        ScanDetailPanel.Visibility = Visibility.Visible;
        DetailText.Text = ViewModel.DetailText;

        if (entry.HasPendingThreats && entry.ScanSession != null)
            ThreatsList.ItemsSource = ViewModel.BuildThreatRows(entry.Threats);
        else
            ThreatsList.ItemsSource = null;
    }

    private void Filter_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton rb && rb.Tag is string tag)
        {
            ViewModel.SelectedFilter = tag switch
            {
                "Threats" => HistoryFilter.Threats,
                "CleanScans" => HistoryFilter.CleanScans,
                "Cleans" => HistoryFilter.Cleans,
                "Quarantine" => HistoryFilter.Quarantine,
                _ => HistoryFilter.All,
            };
        }
    }

    private void Search_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (sender is TextBox tb)
            ViewModel.SearchText = tb.Text;
    }

    private void TimelineList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ViewModel.SelectedEntry = TimelineList.SelectedItem as ActivityEntry;
    }

    private ScanSession? CurrentSession => ViewModel.SelectedEntry?.ScanSession;

    private void QuarantineAll_Click(object sender, RoutedEventArgs e)
    {
        var session = CurrentSession;
        if (session == null) return;
        HistoryThreatRemediationCoordinator.QuarantineAllThreats(_container, ViewModel, session, Refresh);
    }

    private void QuarantineThreat_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path } && CurrentSession != null)
            HistoryThreatRemediationCoordinator.QuarantineThreat(_container, ViewModel, CurrentSession, path, Refresh);
    }

    private void DismissThreat_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path } && CurrentSession != null)
            HistoryThreatRemediationCoordinator.DismissThreat(_container, CurrentSession, path, Refresh);
    }

    private void IgnoreThreat_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path } && CurrentSession != null)
            HistoryThreatRemediationCoordinator.IgnoreThreat(_container, CurrentSession, path, Refresh);
    }

    private void DeleteThreat_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path } && CurrentSession != null)
            HistoryThreatRemediationCoordinator.DeleteThreat(
                _container, CurrentSession, path, Refresh, WinUiServiceHost.Instance.Confirm);
    }

    /// <summary>Charge les menaces de la session dans l'onglet Analyse de l'antivirus pour les traiter comme après un scan.</summary>
    private void TreatInAntivirus_Click(object sender, RoutedEventArgs e)
    {
        if (CurrentSession is not { Threats.Count: > 0 } session)
            return;
        ServiceContainer.UiEvents.RequestReviewHistorySession(session);
    }

    private void OpenAntivirus_Click(object sender, RoutedEventArgs e)
    {
        if (App.MainWindowInstance != null)
            App.MainWindowInstance.SelectNavigation("antivirus");
    }

    private void ManageInAv_Click(object sender, RoutedEventArgs e) =>
        ServiceContainer.UiEvents.RequestOpenQuarantineTab();

    private void ViewInQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path } && ViewModel.IsFileStillQuarantined(path))
            ServiceContainer.UiEvents.RequestOpenQuarantineTab();
    }

    private void ViewSourceScan_Click(object sender, RoutedEventArgs e)
    {
        var session = ViewModel.SelectedQuarantineSourceScan;
        if (session != null)
            ViewModel.TrySelectScanSession(session.SessionId);
    }

    private async void ExportHtml_Click(object sender, RoutedEventArgs e)
    {
        var path = await PickSavePathAsync(
            LocalizationService.GetString("Export_HtmlFilter"),
            $"optiCombat_rapport_{DateTime.Now:yyyyMMdd_HHmm}.html",
            ".html");
        if (path == null) return;

        try
        {
            var html = new HtmlExportService();
            var hist = _container.Logger.GetHistory();
            var threats = hist.SelectMany(s => s.Threats).ToList();
            html.ExportFullReport(hist, threats, _container.Quarantine.GetEntries(),
                _container.UserPreferencesAccessor.Current, path);
        }
        catch (Exception ex)
        {
            AppLogger.Error("HistoryPage", "Export HTML", ex);
        }
    }

    private async void ExportPdf_Click(object sender, RoutedEventArgs e)
    {
        var session = ViewModel.SelectedEntry?.ScanSession;
        if (session == null) return;

        var path = await PickSavePathAsync(
            LocalizationService.GetString("Export_PdfFilter"),
            $"optiCombat_scan_{session.StartedAt:yyyyMMdd_HHmm}.pdf",
            ".pdf");
        if (path == null) return;

        try
        {
            new PdfReportGenerator().GenerateReportFromSession(session, path);
        }
        catch (Exception ex)
        {
            AppLogger.Error("HistoryPage", "Export PDF", ex);
        }
    }

    /// <summary>
    /// « Enregistrer sous » Win32 natif (le FileSavePicker WinRT échoue en administrateur et
    /// pouvait bloquer l'UI). <paramref name="filter"/> au format « Libellé|*.ext|… » : seul le libellé est repris.
    /// </summary>
    private static Task<string?> PickSavePathAsync(string filter, string defaultName, string ext)
    {
        var label = filter.Split('|', 2)[0].Trim();
        return Task.FromResult(WinUiNativeDialogs.PickSaveFile(defaultName, label, ext));
    }
}
