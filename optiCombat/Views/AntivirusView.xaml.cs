using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Strings;
using optiCombat.ViewModels;
using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using FolderBrowserDialog = System.Windows.Forms.FolderBrowserDialog;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;

namespace optiCombat.Views
{
    /// <summary>
    /// Vue principale de l'onglet Antivirus — scan, historique, signatures et quarantaine.
    /// Se connecte au <see cref="ScanViewModel"/> via DataContext.
    /// </summary>
    public partial class AntivirusView : System.Windows.Controls.UserControl, IAntivirusSignaturesPanel
    {
        private IViewServices? _services;
        private ScanViewModel? _vmScanTabSubscription;

        private readonly ConcurrentQueue<string> _signatureLogQueue = new();
        private DispatcherTimer? _signatureLogFlushTimer;
        private int _signatureLogArmPosted;

        public AntivirusView()
        {
            InitializeComponent();
            DataContextChanged += AntivirusView_DataContextChanged;
            Loaded += AntivirusView_Loaded;
            Unloaded += AntivirusView_Unloaded;
        }

        public void Bind(IViewServices services) => _services = services;

        private void AntivirusView_Loaded(object sender, RoutedEventArgs e)
        {
            if (antivirusMainTabs != null)
                antivirusMainTabs.SelectionChanged += AntivirusMainTabs_SelectionChanged;
        }

        private void AntivirusMainTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (antivirusMainTabs?.SelectedIndex == 1)
                VM?.LoadQuarantine(reset: true);
        }

        private void AntivirusView_DataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
            if (_vmScanTabSubscription != null)
            {
                _vmScanTabSubscription.DisplayScanProgressRequested -= SurDemandeAffichageProgressionScan;
                _vmScanTabSubscription = null;
            }

            if (DataContext is ScanViewModel vm)
            {
                _vmScanTabSubscription = vm;
                vm.DisplayScanProgressRequested += SurDemandeAffichageProgressionScan;
            }
        }

        private void AntivirusView_Unloaded(object sender, RoutedEventArgs e)
        {
            if (antivirusMainTabs != null)
                antivirusMainTabs.SelectionChanged -= AntivirusMainTabs_SelectionChanged;

            if (_vmScanTabSubscription != null)
            {
                _vmScanTabSubscription.DisplayScanProgressRequested -= SurDemandeAffichageProgressionScan;
                _vmScanTabSubscription = null;
            }

            _signatureLogFlushTimer?.Stop();
            _signatureLogFlushTimer = null;
            while (_signatureLogQueue.TryDequeue(out _)) { }
            Interlocked.Exchange(ref _signatureLogArmPosted, 0);
        }

        private void SurDemandeAffichageProgressionScan(object? sender, EventArgs e)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (antivirusMainTabs is System.Windows.Controls.TabControl tc)
                {
                    tc.SelectedIndex = 0;
                    _ = tc.Focus();
                }
            });
        }

        private ScanViewModel? VM => DataContext as ScanViewModel;
        private MainWindow? Win => Window.GetWindow(this) as MainWindow;
        private AntivirusActions Actions => _services?.Actions
            ?? throw new InvalidOperationException("AntivirusView.Bind() must be called before use.");

        public void UpdateLastScanDisplay(DateTime? lastScan)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (antivirusHeroLastScan != null)
                    antivirusHeroLastScan.Text = FormatHeroLastScan(lastScan);
            }, DispatcherPriority.Background);
        }

        public void UpdateQuarantineList(IEnumerable<QuarantineEntry>? _ = null)
        {
            Dispatcher.InvokeAsync(() => VM?.LoadQuarantine(reset: true));
        }

        public void AppendSignatureLog(string message)
        {
            if (string.IsNullOrWhiteSpace(message))
                return;

            _signatureLogQueue.Enqueue(message);
            if (Interlocked.CompareExchange(ref _signatureLogArmPosted, 1, 0) != 0)
                return;

            var disp = System.Windows.Application.Current?.Dispatcher;
            if (disp == null) return;
            disp.BeginInvoke(ArmSignatureLogFlush, DispatcherPriority.Background);
        }

        private void ArmSignatureLogFlush()
        {
            Interlocked.Exchange(ref _signatureLogArmPosted, 0);

            _signatureLogFlushTimer ??= new DispatcherTimer(
                TimeSpan.FromMilliseconds(110),
                DispatcherPriority.Background,
                SurTickVidageLogSignatures,
                Dispatcher);

            _signatureLogFlushTimer.Stop();
            _signatureLogFlushTimer.Start();
        }

        private void SurTickVidageLogSignatures(object? sender, EventArgs e)
        {
            _signatureLogFlushTimer?.Stop();
            if (signatureLog == null)
                return;

            var sb = new StringBuilder(8192);
            for (var i = 0; i < 500 && _signatureLogQueue.TryDequeue(out var line); i++)
                sb.AppendLine(line);

            if (sb.Length > 0)
            {
                signatureLog.AppendText(sb.ToString());
                // During signature updates, always keep the latest line visible.
                signatureLog.ScrollToEnd();
            }

            if (!_signatureLogQueue.IsEmpty)
                _signatureLogFlushTimer?.Start();
        }

        public void SetSignatureUpdating(bool updating)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (sigUpdateProgressBar != null)
                {
                    sigUpdateProgressBar.Visibility = updating ? Visibility.Visible : Visibility.Collapsed;
                    sigUpdateProgressBar.IsIndeterminate = updating;
                }

                if (btnManualUpdateSignatures != null)
                {
                    btnManualUpdateSignatures.IsEnabled = !updating;
                    btnManualUpdateSignatures.Opacity = updating ? 0.55 : 1.0;
                }

                if (btnStopUpdateSignatures != null)
                    btnStopUpdateSignatures.Visibility = updating ? Visibility.Visible : Visibility.Collapsed;
            });
        }

        public void SelectSignaturesTab() => SelectTab(2);

        public void SelectQuarantineTab() => SelectTab(1);

        public void SelectScanTab() => SelectTab(0);

        public void UpdateSignaturesPanel(string yaraVersion, string yaraLastMaj, string clamVersion, string clamLastMaj)
        {
            Dispatcher.InvokeAsync(() =>
            {
                SetDisplayText(sigYaraVersion, yaraVersion);
                SetDisplayText(sigYaraLastMaj, yaraLastMaj);
                SetDisplayText(sigClamVersion, clamVersion);
                SetDisplayText(sigClamLastMaj, clamLastMaj);
            });
        }

        public void UpdateSignatureInfo(string version, string date)
            => UpdateSignaturesPanel("—", "—", version, date);

        public void RefreshAllData()
        {
            if (Win != null)
                _ = Win.RefreshAntivirusDataAsync();
        }
        private void SelectTab(int tabIndex)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (antivirusMainTabs != null && tabIndex >= 0 && tabIndex < antivirusMainTabs.Items.Count)
                    antivirusMainTabs.SelectedIndex = tabIndex;
            });
        }

        private static string FormatHeroLastScan(DateTime? lastScan)
        {
            if (!lastScan.HasValue)
                return Localization.LocalizationService.GetString("Av_LastScanNone");

            var diff = DateTime.Now - lastScan.Value;
            if (diff.TotalMinutes < 1)
                return Localization.LocalizationService.GetString("Av_LastScanInstant");
            if (diff.TotalMinutes < 60)
                return Localization.LocalizationService.Format("Av_LastScanMinutes", (int)diff.TotalMinutes);
            if (diff.TotalHours < 24)
                return Localization.LocalizationService.Format("Av_LastScanHours", (int)diff.TotalHours);
            if (diff.TotalDays < 7)
                return Localization.LocalizationService.Format("Av_LastScanDays", (int)diff.TotalDays);

            return Localization.LocalizationService.Format(
                "Av_LastScanLabel",
                lastScan.Value.ToString("G", CultureInfo.CurrentCulture));
        }

        private static void SetDisplayText(System.Windows.Controls.TextBlock? block, string value)
        {
            if (block == null) return;
            block.Text = VersionDisplayHelper.NormalizeForDisplay(value);
        }

        private void BrowseFolder_Click(object sender, RoutedEventArgs e)
        {
            using var dlg = new FolderBrowserDialog
            {
                Description = LocalizationService.GetString("Av_PickFolder"),
                UseDescriptionForTitle = true
            };

            if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK
                && VM?.ScanFolderCommand is { } cmd
                && cmd.CanExecute(dlg.SelectedPath))
            {
                cmd.Execute(dlg.SelectedPath);
            }
        }

        private void BrowseFile_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Title = LocalizationService.GetString("Av_PickFile"),
                CheckFileExists = true,
                CheckPathExists = true
            };

            if (dlg.ShowDialog() == true
                && VM?.ScanFileCommand is { } cmd
                && cmd.CanExecute(dlg.FileName))
            {
                cmd.Execute(dlg.FileName);
            }
        }

        private void BtnQuarantineThreat_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Button btn && btn.Tag is string filePath)
            {
                var sessionId = VM?.ActiveScanSessionId ?? Guid.Empty;
                var known = _services!.FindKnownThreat(filePath);
                var result = known != null
                    ? Actions.QuarantineThreat(known.Clone(), sessionId)
                    : Actions.QuarantineThreat(filePath, sessionId);
                if (result.Success)
                {
                    VM?.RemoveDetectedThreat(filePath);
                    VM?.NotifyThreatQuarantinedDuringScan(filePath);
                }
                VM?.LoadQuarantine(reset: true);
                _services!.RequestScanHistoryViewsRefresh();
            }
        }

        private void BtnIgnoreThreat_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Button btn && btn.Tag is string filePath)
            {
                var result = Actions.IgnoreThreat(filePath);
                if (result.Success)
                    VM?.RemoveDetectedThreat(filePath);
                RefreshAllData();
            }
        }

        private async void BtnCheckReputation_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Button btn || btn.Tag is not string filePath)
                return;

            btn.IsEnabled = false;
            try
            {
                var result = await _services!.ThreatReputation.LookupFileAsync(filePath);
                var message = result.Summary;
                if (!string.IsNullOrEmpty(result.Permalink))
                    message += Environment.NewLine + result.Permalink;

                System.Windows.MessageBox.Show(
                    message,
                    LocalizationService.GetString("Av_ReputationTitle"),
                    MessageBoxButton.OK,
                    result.IsError ? MessageBoxImage.Warning : MessageBoxImage.Information);
            }
            finally
            {
                btn.IsEnabled = true;
            }
        }

        private void BtnDeleteThreat_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Button btn || btn.Tag is not string filePath)
                return;

            if (System.Windows.MessageBox.Show(
                    LocalizationService.GetString("Av_ConfirmDeleteFile"),
                    OpticombatStrings.Confirmations.Title,
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning) != MessageBoxResult.Yes)
                return;

            var result = Actions.DeleteThreatFile(filePath);
            if (result.Success)
                VM?.RemoveDetectedThreat(filePath);
            RefreshAllData();
        }

        private void BtnRestoreFromQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Button btn || btn.Tag is not string quarantineId)
                return;

            var result = Actions.RestoreFromQuarantine(quarantineId);
            if (result.Success)
                RefreshAllData();
        }

        private void BtnDeleteFromQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Button btn || btn.Tag is not string quarantineId)
                return;

            if (System.Windows.MessageBox.Show(
                    LocalizationService.GetString("Av_ConfirmDeleteQuarantine"),
                    OpticombatStrings.Confirmations.Title,
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;

            var result = Actions.DeleteFromQuarantine(quarantineId);
            if (result.Success)
                RefreshAllData();
        }

        private void BtnManualUpdateSignatures_Click(object sender, RoutedEventArgs e)
        {
            _services!.TriggerSignatureUpdate();
        }

        private void BtnStopUpdateSignatures_Click(object sender, RoutedEventArgs e)
        {
            Actions.StopAllUpdates();
            SetSignatureUpdating(false);
            AppendSignatureLog(LocalizationService.GetString("Status_SigInterrupted"));
        }
    }
}
