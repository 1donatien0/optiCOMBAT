using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;

namespace optiCombat.Views
{
    /// <summary>
    /// Vue Nettoyer — analyse et suppression des fichiers temporaires, caches navigateurs et corbeille.
    /// L'analyse doit être exécutée avant de pouvoir lancer le nettoyage.
    /// </summary>
    public partial class CleanControl : System.Windows.Controls.UserControl
    {
        private IViewServices? _services;
        private ScanLogManager? _logger;

        public void Bind(IViewServices services)
        {
            _services = services;
            _logger = services.Logger;
        }

        // Analyse doit être lancée avant de pouvoir nettoyer
        private bool _analysed = false;

        private readonly struct CleanSelection
        {
            public bool TempWin { get; init; }
            public bool TempUser { get; init; }
            public bool Recycle { get; init; }
            public bool Logs { get; init; }
            public bool Edge { get; init; }
            public bool Chrome { get; init; }
            public bool Firefox { get; init; }
            public bool Brave { get; init; }
            public bool Opera { get; init; }
            public bool Vivaldi { get; init; }
            public bool Arc { get; init; }

            public bool AnySystem => TempWin || TempUser || Recycle || Logs;
            public bool AnyBrowser => Edge || Chrome || Firefox || Brave || Opera || Vivaldi || Arc;
        }

        public CleanControl()
        {
            InitializeComponent();
        }

        // ── Analyser ─────────────────────────────────────────────────────────
        private async void btnAnalyze_Click(object sender, RoutedEventArgs e)
        {
            var sel = ReadCleanSelection();
            if (!sel.AnySystem && !sel.AnyBrowser)
            {
                System.Windows.MessageBox.Show(
                    LocalizationService.GetString("Clean_LogHint"),
                    LocalizationService.GetString("Clean_Title"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            btnAnalyze.IsEnabled = false;
            btnCleanNow.IsEnabled = false;
            _analysed = false;
            SetEmptyResultState(false);
            SetLog(LocalizationService.GetString("Clean_LogAnalyzeStart"));

            await Task.Run(() =>
            {
                long tempWin = sel.TempWin
                    ? MeasureDir(Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "Temp"))
                    : 0;
                long tempUser = sel.TempUser ? MeasureDir(Path.GetTempPath()) : 0;
                long logsSize = sel.Logs ? MeasureDir(WindowsLogsPath()) : 0;
                long edgeCache = sel.Edge ? MeasureDir(EdgeCachePath()) : 0;
                long chromeCache = sel.Chrome ? MeasureDir(ChromeCachePath()) : 0;
                long ffCache = sel.Firefox ? MeasureDir(FirefoxCachePath()) : 0;
                long braveCache = sel.Brave ? MeasureDir(BraveCachePath()) : 0;
                long operaCache = sel.Opera ? MeasureDir(OperaCachePath()) : 0;
                long vivaldiCache = sel.Vivaldi ? MeasureDir(VivaldiCachePath()) : 0;
                long arcCache = sel.Arc ? MeasureDir(ArcCachePath()) : 0;

                long sysTotal = tempWin + tempUser + logsSize;
                long browserTotal = edgeCache + chromeCache + ffCache + braveCache + operaCache + vivaldiCache + arcCache;
                long total = sysTotal + browserTotal;

                Dispatcher.Invoke(() =>
                {
                    txtTempSize.Text = FormatSize(sysTotal);
                    txtBrowserSize.Text = FormatSize(browserTotal);
                    txtTotalSize.Text = FormatSize(total);

                    if (sel.TempWin)
                        AppendLog(LocalizationService.Format("Clean_LogLineTempWin", FormatSize(tempWin)));
                    if (sel.TempUser)
                        AppendLog(LocalizationService.Format("Clean_LogLineTempUser", FormatSize(tempUser)));
                    if (sel.Logs)
                        AppendLog(LocalizationService.Format("Clean_LogLineLogs", FormatSize(logsSize)));
                    if (sel.Edge)
                        AppendLog(LocalizationService.Format("Clean_LogLineEdge", FormatSize(edgeCache)));
                    if (sel.Chrome)
                        AppendLog(LocalizationService.Format("Clean_LogLineChrome", FormatSize(chromeCache)));
                    if (sel.Firefox)
                        AppendLog(LocalizationService.Format("Clean_LogLineFirefox", FormatSize(ffCache)));
                    if (sel.Brave)
                        AppendLog(LocalizationService.Format("Clean_LogLineBrave", FormatSize(braveCache)));
                    if (sel.Opera)
                        AppendLog(LocalizationService.Format("Clean_LogLineOpera", FormatSize(operaCache)));
                    if (sel.Vivaldi)
                        AppendLog(LocalizationService.Format("Clean_LogLineVivaldi", FormatSize(vivaldiCache)));
                    if (sel.Arc)
                        AppendLog(LocalizationService.Format("Clean_LogLineArc", FormatSize(arcCache)));
                    AppendLog($"─────────────────────────");
                    AppendLog(LocalizationService.Format("Clean_LogTotal", FormatSize(total)));
                    AppendLog(LocalizationService.GetString("Clean_LogAnalyzeEnd"));

                    _analysed = true;
                    btnCleanNow.IsEnabled = total > 0;
                    SetEmptyResultState(total == 0);
                });
            });

            btnAnalyze.IsEnabled = true;
        }

        // ── Nettoyer ─────────────────────────────────────────────────────────
        private async void btnCleanNow_Click(object sender, RoutedEventArgs e)
        {
            if (!_analysed) return;

            var sel = ReadCleanSelection();

            btnAnalyze.IsEnabled = false;
            btnCleanNow.IsEnabled = false;
            AppendLog(LocalizationService.GetString("Clean_LogCleanStart"));
            var cleanStarted = DateTime.Now;

            try
            {
                await Task.Run(() =>
                {
                    long freed = 0;

                    if (sel.TempWin)
                    {
                        string path = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "Temp");
                        long f = CleanDir(path);
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog(LocalizationService.Format("Clean_LogFreedTempWin", FormatSize(f))));
                    }
                    if (sel.TempUser)
                    {
                        long f = CleanDir(Path.GetTempPath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog(LocalizationService.Format("Clean_LogFreedTempUser", FormatSize(f))));
                    }
                    if (sel.Recycle)
                    {
                        SHEmptyRecycleBin(IntPtr.Zero, null, 0x0007);
                        Dispatcher.Invoke(() => AppendLog(LocalizationService.GetString("Clean_LogRecycleEmptied")));
                    }
                    if (sel.Edge)
                    {
                        long f = CleanDir(EdgeCachePath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog(LocalizationService.Format("Clean_LogFreedCache", LocalizationService.GetString("Clean_Browser_Edge"), FormatSize(f))));
                    }
                    if (sel.Chrome)
                    {
                        long f = CleanDir(ChromeCachePath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog(LocalizationService.Format("Clean_LogFreedCache", LocalizationService.GetString("Clean_Browser_Chrome"), FormatSize(f))));
                    }
                    if (sel.Firefox)
                    {
                        long f = CleanDir(FirefoxCachePath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog(LocalizationService.Format("Clean_LogFreedCache", LocalizationService.GetString("Clean_Browser_Firefox"), FormatSize(f))));
                    }
                    if (sel.Brave)
                    {
                        long f = CleanDir(BraveCachePath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog(LocalizationService.Format("Clean_LogFreedCache", LocalizationService.GetString("Clean_Browser_Brave"), FormatSize(f))));
                    }
                    if (sel.Opera)
                    {
                        long f = CleanDir(OperaCachePath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog(LocalizationService.Format("Clean_LogFreedCache", LocalizationService.GetString("Clean_Browser_Opera"), FormatSize(f))));
                    }
                    if (sel.Vivaldi)
                    {
                        long f = CleanDir(VivaldiCachePath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog(LocalizationService.Format("Clean_LogFreedCache", LocalizationService.GetString("Clean_Browser_Vivaldi"), FormatSize(f))));
                    }
                    if (sel.Arc)
                    {
                        long f = CleanDir(ArcCachePath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog(LocalizationService.Format("Clean_LogFreedCache", LocalizationService.GetString("Clean_Browser_Arc"), FormatSize(f))));
                    }
                    if (sel.Logs)
                    {
                        long f = CleanDir(WindowsLogsPath());
                        freed += f;
                        Dispatcher.Invoke(() => AppendLog(LocalizationService.Format("Clean_LogFreedLogs", FormatSize(f))));
                    }

                    Dispatcher.Invoke(() =>
                    {
                        AppendLog($"─────────────────────────");
                        AppendLog(LocalizationService.Format("Clean_LogFreedTotal", FormatSize(freed)));
                        AppendLog(LocalizationService.GetString("Clean_LogCleanEnd"));
                        txtTempSize.Text = ByteSizeFormat.Format(0);
                        txtBrowserSize.Text = ByteSizeFormat.Format(0);
                        txtTotalSize.Text = ByteSizeFormat.Format(0);
                        _analysed = false;
                        btnCleanNow.IsEnabled = false;

                        var cleanEnd = DateTime.Now;
                        var targets = BuildCleanTargetsSummary(sel);
                        try
                        {
                            _logger!.SaveCleanSession(new CleanSession
                            {
                                StartedAt = cleanStarted,
                                FinishedAt = cleanEnd,
                                TargetsSummary = targets,
                                BytesFreed = freed,
                                OperationLog = CaptureCleanOperationLog()
                            });
                            _services!.RequestScanHistoryViewsRefresh();
                        }
                        catch (Exception ex)
                        {
                            AppLogger.Warn("CleanControl", "Enregistrement historique nettoyage", ex);
                        }
                    });
                });
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", "Nettoyage système", ex);
                AppendLog(LocalizationService.Format("Clean_ErrCleaning", ex.Message));
            }
            finally
            {
                btnAnalyze.IsEnabled = true;
                if (_analysed)
                    btnCleanNow.IsEnabled = true;
            }
        }

        // ── Journalisation ───────────────────────────────────────────────────
        private void SetEmptyResultState(bool show)
        {
            if (emptyCleanResultState == null || txtCleanLog == null) return;
            emptyCleanResultState.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
            txtCleanLog.Visibility = show ? Visibility.Collapsed : Visibility.Visible;
        }

        private void SetLog(string text)
        {
            if (txtCleanLog != null)
                txtCleanLog.Text = $"[{DateTime.Now:HH:mm:ss}] {text}\n";
        }

        public void AppendLog(string line)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtCleanLog == null) return;
                if (txtCleanLog.Text.StartsWith("Cliquez", StringComparison.OrdinalIgnoreCase)
                    || txtCleanLog.Text.StartsWith("Click", StringComparison.OrdinalIgnoreCase))
                    txtCleanLog.Text = string.Empty;
                txtCleanLog.Text += $"[{DateTime.Now:HH:mm:ss}] {line}\n";
                txtCleanLog.ScrollToEnd();
            });
        }

        private string CaptureCleanOperationLog()
        {
            var t = txtCleanLog?.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(t)) return "";
            if (t.StartsWith("Cliquez", StringComparison.OrdinalIgnoreCase)
                || t.StartsWith("Click", StringComparison.OrdinalIgnoreCase))
                return "";
            return t;
        }

        // ── Chemins de cache navigateurs ─────────────────────────────────────
        private static string LocalApp => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        private static string EdgeCachePath() => Path.Combine(LocalApp, @"Microsoft\Edge\User Data\Default\Cache");
        private static string ChromeCachePath() => Path.Combine(LocalApp, @"Google\Chrome\User Data\Default\Cache");
        private static string BraveCachePath() => Path.Combine(LocalApp, @"BraveSoftware\Brave-Browser\User Data\Default\Cache");
        private static string OperaCachePath() => Path.Combine(LocalApp, @"Opera Software\Opera Stable\Cache");
        private static string VivaldiCachePath() => Path.Combine(LocalApp, @"Vivaldi\User Data\Default\Cache");
        private static string ArcCachePath() => Path.Combine(LocalApp, @"Arc\User Data\Default\Cache");
        private static string WindowsLogsPath() => Path.Combine(
            Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", @"Logs");
        private static string FirefoxCachePath()
        {
            var localProfilesBase = Path.Combine(LocalApp, @"Mozilla\Firefox\Profiles");
            if (!Directory.Exists(localProfilesBase))
                return string.Empty;

            // Priorité : default-release, puis default, puis premier profil local disponible.
            var directories = Directory.EnumerateDirectories(localProfilesBase).ToList();
            string? preferred = directories.FirstOrDefault(d => d.Contains(".default-release", StringComparison.OrdinalIgnoreCase))
                                ?? directories.FirstOrDefault(d => d.Contains(".default", StringComparison.OrdinalIgnoreCase))
                                ?? directories.FirstOrDefault();

            if (!string.IsNullOrEmpty(preferred))
            {
                var cache = Path.Combine(preferred, "cache2");
                if (Directory.Exists(cache))
                    return cache;
            }

            // Repli : lire profiles.ini (Roaming), puis mapper vers le dossier de cache LocalAppData.
            var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var profilesIni = Path.Combine(roaming, @"Mozilla\Firefox\profiles.ini");
            if (!File.Exists(profilesIni))
                return string.Empty;

            try
            {
                var lines = File.ReadAllLines(profilesIni);
                foreach (var line in lines)
                {
                    if (!line.StartsWith("Path=", StringComparison.OrdinalIgnoreCase))
                        continue;
                    var relativeOrAbsolute = line["Path=".Length..].Trim();
                    if (string.IsNullOrEmpty(relativeOrAbsolute))
                        continue;

                    var profileName = Path.GetFileName(relativeOrAbsolute.TrimEnd('\\', '/'));
                    if (string.IsNullOrEmpty(profileName))
                        continue;

                    var localCandidate = Path.Combine(localProfilesBase, profileName, "cache2");
                    if (Directory.Exists(localCandidate))
                        return localCandidate;
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", "Lecture de profiles.ini Firefox", ex);
            }

            return string.Empty;
        }

        // ── Helpers fichiers ─────────────────────────────────────────────────
        private static long MeasureDir(string path)
        {
            if (string.IsNullOrEmpty(path) || !Directory.Exists(path)) return 0;
            try
            {
                long total = 0;
                foreach (var f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                {
                    try { total += new FileInfo(f).Length; }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("CleanControl", $"Mesure ignorée : {f}", ex);
                    }
                }
                return total;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", $"Mesure impossible « {path} » : {ex.Message}");
                return 0;
            }
        }

        private static long CleanDir(string path)
        {
            if (string.IsNullOrEmpty(path) || !Directory.Exists(path)) return 0;
            long freed = 0;
            try
            {
                foreach (var f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                {
                    try
                    {
                        long s = new FileInfo(f).Length;
                        File.Delete(f);
                        freed += s;
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Warn("CleanControl", $"Fichier non supprimé : {f}", ex);
                    }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", $"Nettoyage incomplet « {path} » : {ex.Message}");
            }
            return freed;
        }

        private CleanSelection ReadCleanSelection() => new()
        {
            TempWin = chkTempWin?.IsChecked == true,
            TempUser = chkTempUser?.IsChecked == true,
            Recycle = chkRecycleBin?.IsChecked == true,
            Logs = chkLogs?.IsChecked == true,
            Edge = chkEdge?.IsChecked == true,
            Chrome = chkChrome?.IsChecked == true,
            Firefox = chkFirefox?.IsChecked == true,
            Brave = chkBrave?.IsChecked == true,
            Opera = chkOpera?.IsChecked == true,
            Vivaldi = chkVivaldi?.IsChecked == true,
            Arc = chkArc?.IsChecked == true
        };

        private static string BuildCleanTargetsSummary(CleanSelection sel)
        {
            var parts = new List<string>(12);
            if (sel.TempWin) parts.Add(LocalizationService.GetString("Clean_TempWinCb"));
            if (sel.TempUser) parts.Add(LocalizationService.GetString("Clean_TempUserCb"));
            if (sel.Recycle) parts.Add(LocalizationService.GetString("Clean_RecycleCb"));
            if (sel.Logs) parts.Add(LocalizationService.GetString("Clean_LogsCb"));
            if (sel.Edge) parts.Add(LocalizationService.GetString("Clean_Edge"));
            if (sel.Chrome) parts.Add(LocalizationService.GetString("Clean_Chrome"));
            if (sel.Firefox) parts.Add(LocalizationService.GetString("Clean_Firefox"));
            if (sel.Brave) parts.Add(LocalizationService.GetString("Clean_Brave"));
            if (sel.Opera) parts.Add(LocalizationService.GetString("Clean_Opera"));
            if (sel.Vivaldi) parts.Add(LocalizationService.GetString("Clean_Vivaldi"));
            if (sel.Arc) parts.Add(LocalizationService.GetString("Clean_Arc"));
            return parts.Count == 0 ? "—" : string.Join(", ", parts);
        }

        private static string FormatSize(long bytes) => ByteSizeFormat.Format(bytes);

        [DllImport("Shell32.dll", CharSet = CharSet.Unicode)]
        private static extern int SHEmptyRecycleBin(IntPtr hwnd, string? pszRootPath, uint dwFlags);
    }
}