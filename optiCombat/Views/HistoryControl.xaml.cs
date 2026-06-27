using optiCombat.Coordinators;
using optiCombat.Localization;

using optiCombat.Models;

using optiCombat.Services;

using optiCombat.Strings;

using optiCombat.ViewModels;

using System.Globalization;

using System.Windows;

using System.Windows.Controls;

using System.Windows.Media;

using System.Windows.Threading;

using Brush = System.Windows.Media.Brush;

using Button = System.Windows.Controls.Button;

using RadioButton = System.Windows.Controls.RadioButton;



namespace optiCombat.Views

{

    /// <summary>

    /// Historique unifié (journal d'activité) avec filtres chips et traitement des menaces.

    /// </summary>

    public partial class HistoryControl : System.Windows.Controls.UserControl

    {

        private IHistoryServices? _history;
        private Converters.QuarantinePathVisibilityConverter? _quarantineVis;
        private bool _bound;
        private bool _loadedHandlersAttached;
        private bool _syncingFilterChips;
        private void HideDetailPanels() => HistoryDetailCoordinator.HideDetailPanels(_detailView);
        private readonly HistoryDetailView _detailView;

        public HistoryViewModel VM { get; private set; } = null!;

        private IHistoryServices History => _history ?? throw new InvalidOperationException("HistoryControl.Bind() must be called before use.");
        private IUiEventBus UiEvents => History;
        private AntivirusActions Actions => History.Actions;
        private ScanLogManager Logger => History.Logger;

        public HistoryControl()
        {
            InitializeComponent();
            _detailView = new HistoryDetailView
            {
                ThreatsGrid = dgHistoryThreats,
                CleanLogPanel = cleanLogPanel,
                CleanLogText = txtCleanLog,
                QuarantineDetailPanel = quarantineDetailPanel,
                QuarTitle = txtQuarTitle,
                QuarPath = txtQuarPath,
                QuarMeta = txtQuarMeta,
                QuarStatus = txtQuarStatus,
                BtnManageInAv = btnManageInAv,
                NoThreatsState = noThreatsState,
                ThreatsLegacyText = txtHistThreatsLegacy,
            };
            Loaded += OnLoaded;
            Unloaded += OnUnloaded;
        }

        /// <summary>Branche les services partagés (appelé par <see cref="optiCombat.MainWindow"/> au démarrage).</summary>
        public void Bind(IHistoryServices services)
        {
            if (_bound)
                return;
            _bound = true;
            _history = services;
            if (Resources["QuarantinePathVis"] is Converters.QuarantinePathVisibilityConverter quarantineVis)
            {
                _quarantineVis = quarantineVis;
                quarantineVis.Quarantine = services.Quarantine;
            }
            VM = new HistoryViewModel(services);
            DataContext = VM;
            VM.PropertyChanged += OnViewModelPropertyChanged;

            if (IsLoaded)
                AttachLoadedHandlers();
        }



        public void RefreshTimeline()
        {
            if (!_bound || VM == null) return;

            _quarantineVis?.RefreshCache();
            VM.Refresh();
            SyncFilterChips();
            UpdateDetailPanels();
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            if (!_bound) return;
            AttachLoadedHandlers();
        }

        private void AttachLoadedHandlers()
        {
            if (_loadedHandlersAttached) return;
            _loadedHandlersAttached = true;

            UiEvents.ScanHistoryViewsRefreshRequested += OnExternalRefreshRequested;
            RefreshTimeline();
        }

        private void OnUnloaded(object sender, RoutedEventArgs e)
        {
            UiEvents.ScanHistoryViewsRefreshRequested -= OnExternalRefreshRequested;
            _loadedHandlersAttached = false;
        }



        private void OnExternalRefreshRequested(object? sender, EventArgs e)

        {

            if (!IsLoaded) return;

            Dispatcher.BeginInvoke(RefreshTimeline, DispatcherPriority.Background);

        }



        private void OnViewModelPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)

        {

            switch (e.PropertyName)

            {

                case nameof(HistoryViewModel.SelectedEntry):

                case nameof(HistoryViewModel.ShowScanActions):

                case nameof(HistoryViewModel.ShowQuarantineReadOnly):

                case nameof(HistoryViewModel.HasQuarantineSourceScan):

                    UpdateDetailPanels();

                    break;

                case nameof(HistoryViewModel.SelectedFilter):

                    SyncFilterChips();

                    break;

            }

        }



        private void SyncFilterChips()
        {
            if (!IsLoaded || !_bound || VM == null) return;



            var tag = VM.SelectedFilter switch

            {

                HistoryFilter.Threats => "Threats",

                HistoryFilter.CleanScans => "CleanScans",

                HistoryFilter.Cleans => "Cleans",

                HistoryFilter.Quarantine => "Quarantine",

                _ => "All",

            };



            _syncingFilterChips = true;

            try

            {

                if (chipAll != null) chipAll.IsChecked = tag == "All";

                if (chipThreats != null) chipThreats.IsChecked = tag == "Threats";

                if (chipClean != null) chipClean.IsChecked = tag == "CleanScans";

                if (chipSweep != null) chipSweep.IsChecked = tag == "Cleans";

                if (chipQuarantine != null) chipQuarantine.IsChecked = tag == "Quarantine";

            }

            finally

            {

                _syncingFilterChips = false;

            }

        }



        private void Chip_Checked(object sender, RoutedEventArgs e)
        {
            if (!_bound || _syncingFilterChips || sender is not RadioButton { Tag: string tag } || !IsLoaded) return;

            VM.SelectedFilter = tag switch

            {

                "Threats" => HistoryFilter.Threats,

                "CleanScans" => HistoryFilter.CleanScans,

                "Cleans" => HistoryFilter.Cleans,

                "Quarantine" => HistoryFilter.Quarantine,

                _ => HistoryFilter.All,

            };

        }



        private void UpdateDetailPanels()

        {

            var entry = VM.SelectedEntry;

            if (entry == null)

            {

                ShowNoSelectionHint();

                HideDetailPanels();

                return;

            }



            if (txtNoSelHint != null)

                txtNoSelHint.Visibility = Visibility.Collapsed;

            if (sessionInfoBar != null)

                sessionInfoBar.Visibility = Visibility.Visible;



            ShowEntryInfo(entry);



            if (entry.Kind == ActivityKind.Quarantine)

                ShowQuarantineDetail(entry);

            else if (entry.Kind == ActivityKind.Clean)

                ShowCleanDetail(entry.CleanSession);

            else

                ShowScanDetail(entry.ScanSession);

        }



        private void ShowNoSelectionHint()

        {

            if (sessionInfoBar != null)

                sessionInfoBar.Visibility = Visibility.Collapsed;

            if (txtNoSelHint != null)

                txtNoSelHint.Visibility = Visibility.Visible;

            HideDetailPanels();

        }



        private void ShowEntryInfo(ActivityEntry entry)

        {

            var cult = CultureInfo.CurrentCulture;



            if (txtSessionDate != null)

                txtSessionDate.Text = entry.StartedAt.ToString("dd/MM/yyyy HH:mm", cult);



            if (txtSessionMeta != null)

            {

                txtSessionMeta.Text = entry.Kind switch

                {

                    ActivityKind.Clean => entry.CleanSession?.TargetsSummary ?? entry.TargetDisplay,

                    ActivityKind.Quarantine => entry.DetailDisplay,

                    _ => entry.ScanSession != null

                        ? LocalizationService.Format("Hist_InfoFiles", entry.ScanSession.FilesScanned.ToString("N0", cult))

                        : string.Empty,

                };

            }



            if (txtSessionResult != null)

            {

                txtSessionResult.Text = entry.ResultSummary;

                ApplyResultChipStyle(entry);

            }

        }



        private void ApplyResultChipStyle(ActivityEntry entry)

        {

            if (txtSessionResult == null) return;



            if (entry.HasThreats)

            {

                txtSessionResult.Foreground = TryFindBrush("DangerRed") ?? txtSessionResult.Foreground;

                if (resultChip != null)

                    resultChip.Background = TryFindBrush("RiskMinor") ?? resultChip.Background;

            }

            else if (entry.Kind == ActivityKind.Clean)

            {

                txtSessionResult.Foreground = TryFindBrush("TextAccent") ?? txtSessionResult.Foreground;

                if (resultChip != null)

                    resultChip.Background = TryFindBrush("InfoBg") ?? resultChip.Background;

            }

            else if (entry.Kind == ActivityKind.Quarantine)

            {

                txtSessionResult.Foreground = TryFindBrush("WarningOrange") ?? txtSessionResult.Foreground;

                if (resultChip != null)

                    resultChip.Background = TryFindBrush("SurfaceBg") ?? resultChip.Background;

            }

            else

            {

                txtSessionResult.Foreground = TryFindBrush("SuccessGreen") ?? txtSessionResult.Foreground;

                if (resultChip != null)

                    resultChip.Background = TryFindBrush("SuccessBg") ?? resultChip.Background;

            }

        }



        private void ShowScanDetail(ScanSession? session)
        {
            var rows = session?.Threats.Count > 0
                ? VM.BuildThreatRows(session!.Threats)
                : null;
            HistoryDetailCoordinator.ShowScanDetail(_detailView, session, rows);
        }

        private void ShowQuarantineDetail(ActivityEntry entry) =>
            HistoryDetailCoordinator.ShowQuarantineDetail(_detailView, entry);

        private void ShowCleanDetail(CleanSession? session) =>
            HistoryDetailCoordinator.ShowCleanDetail(_detailView, session);



        private static string? FilePathFromSender(object sender) =>

            sender is Button { Tag: string path } && !string.IsNullOrEmpty(path) ? path : null;



        private Brush? TryFindBrush(string key)

        {

            try { return TryFindResource(key) as Brush; }

            catch { return null; }

        }



        private ScanSession? SelectedScanSession => VM.SelectedEntry?.ScanSession;



        private void BtnTreatInAntivirus_Click(object sender, RoutedEventArgs e)

        {

            if (SelectedScanSession is not { Threats.Count: > 0 } session) return;

            UiEvents.RequestReviewHistorySession(session);

        }



        private void BtnHistQuarantineAll_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedScanSession is not ScanSession session || session.Threats.Count == 0) return;
            HistoryThreatRemediationCoordinator.QuarantineAllThreats(History, VM, session, RefreshTimeline);
        }

        private void BtnHistQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (FilePathFromSender(sender) is not string filePath ||
                SelectedScanSession is not ScanSession session) return;
            HistoryThreatRemediationCoordinator.QuarantineThreat(History, VM, session, filePath, RefreshTimeline);
        }

        private void BtnHistDismiss_Click(object sender, RoutedEventArgs e)
        {
            if (FilePathFromSender(sender) is not string filePath ||
                SelectedScanSession is not ScanSession session) return;
            HistoryThreatRemediationCoordinator.DismissThreat(History, session, filePath, RefreshTimeline);
        }

        private void BtnHistIgnore_Click(object sender, RoutedEventArgs e)
        {
            if (FilePathFromSender(sender) is not string filePath ||
                SelectedScanSession is not ScanSession session) return;
            HistoryThreatRemediationCoordinator.IgnoreThreat(History, session, filePath, RefreshTimeline);
        }

        private void BtnHistDelete_Click(object sender, RoutedEventArgs e)
        {
            if (FilePathFromSender(sender) is not string filePath ||
                SelectedScanSession is not ScanSession session) return;
            HistoryThreatRemediationCoordinator.DeleteThreat(History, session, filePath, RefreshTimeline);
        }



        private void BtnViewInQuarantine_Click(object sender, RoutedEventArgs e)

        {

            if (FilePathFromSender(sender) is not string filePath) return;

            if (!VM.IsFileStillQuarantined(filePath)) return;

            OpenAntivirusQuarantineTab();

        }



        private void BtnViewSourceScan_Click(object sender, RoutedEventArgs e)

        {

            var sessionId = VM.SelectedEntry?.QuarantineEntry?.SourceSessionId;

            if (sessionId is not { } id || id == Guid.Empty) return;

            if (!VM.TrySelectScanSession(id)) return;

            SyncFilterChips();

            UpdateDetailPanels();

        }



        private void BtnManageInAv_Click(object sender, RoutedEventArgs e) =>
            OpenAntivirusQuarantineTab();

        private void OpenAntivirusQuarantineTab() =>
            UiEvents.RequestOpenQuarantineTab();



        private void BtnOpenAntivirus_Click(object sender, RoutedEventArgs e) =>

            History.Navigation?.NavigateTo(OpticombatStrings.PanelIds.Antivirus);



        private void BtnExportHtml_Click(object sender, RoutedEventArgs e) =>

            UiEvents.RequestExportScanHistoryHtml();



        private void BtnExportSelectedPdf_Click(object sender, RoutedEventArgs e)

        {

            if (SelectedScanSession is ScanSession session)

                UiEvents.RequestExportScanSessionPdf(session);

        }

    }

}


