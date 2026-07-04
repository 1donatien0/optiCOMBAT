using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Views;
using optiCombat.WinUI.Services;
using System.Globalization;
using WinUiApp = Microsoft.UI.Xaml.Application;

namespace optiCombat.WinUI.Views;

public sealed partial class OverviewPage : UserControl, IOverviewPanel
{
    public event EventHandler<string>? ActionRequested;

    public OverviewPage()
    {
        InitializeComponent();
        ApplyElevationBanner();
    }

    public void ApplyElevationBanner()
    {
        ElevationBanner.Visibility = ElevationHelper.IsRunningElevated()
            ? Visibility.Collapsed
            : Visibility.Visible;
    }

    public void UpdateProtectionHeadline(bool isProtected, string? headline = null)
    {
        ProtectionHeadline.Text = string.IsNullOrWhiteSpace(headline)
            ? (isProtected
                ? LocalizationService.GetString("Overview_Protected")
                : LocalizationService.GetString("Overview_ProtectionIncomplete"))
            : headline;
        ProtectionSubtitle.Text = isProtected
            ? LocalizationService.GetString("Overview_ProtectedSub")
            : LocalizationService.GetString("Overview_PartialScanBanner");
    }

    public void UpdateRecommendations(string hygieneLine, int hygieneSeverity, bool showSigUpdateLink = false)
    {
        HygieneRecommendation.Text = hygieneLine;
        HygieneRecommendation.Foreground = hygieneSeverity switch
        {
            0 or 2 => (Brush)WinUiApp.Current.Resources["AccentBrush"],
            1 => (Brush)WinUiApp.Current.Resources["WarningBrush"],
            _ => new SolidColorBrush(Microsoft.UI.Colors.DodgerBlue)
        };

        if (showSigUpdateLink)
            HygieneRecommendation.Tapped += (_, _) => ActionRequested?.Invoke(this, "update");
    }

    public void UpdateSecurityPosture(SecurityPostureReport report)
    {
        SecurityScore.Text = report.Score.ToString(CultureInfo.CurrentCulture);
        PostureIssues.Items.Clear();

        var failed = report.Checks.Where(c => !c.Passed).Take(4).ToList();
        if (failed.Count == 0)
        {
            PostureIssues.Items.Add(new TextBlock
            {
                Text = LocalizationService.GetString("Posture_AllGood"),
                TextWrapping = TextWrapping.WrapWholeWords,
                Foreground = (Brush)WinUiApp.Current.Resources["TextMutedBrush"]
            });
            return;
        }

        foreach (var check in failed)
        {
            var panel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
            panel.Children.Add(new TextBlock
            {
                Text = "• " + check.Title,
                TextWrapping = TextWrapping.WrapWholeWords,
                Foreground = (Brush)WinUiApp.Current.Resources["TextMutedBrush"]
            });

            if (!string.IsNullOrWhiteSpace(check.FixUri))
            {
                var link = new HyperlinkButton
                {
                    Content = LocalizationService.GetString("Posture_Fix"),
                    Padding = new Thickness(0),
                    Tag = check.FixUri
                };
                link.Click += (_, _) => OnPostureFixRequested(check.FixUri!);
                panel.Children.Add(link);
            }

            PostureIssues.Items.Add(panel);
        }
    }

    public void UpdatePlatformProtectionStatus(PlatformProtectionStatusReport report)
    {
        PlatformStatusList.Children.Clear();
        foreach (var item in report.Components)
        {
            var color = item.State switch
            {
                PlatformComponentState.Active => (Brush)WinUiApp.Current.Resources["AccentBrush"],
                PlatformComponentState.Warning => (Brush)WinUiApp.Current.Resources["WarningBrush"],
                PlatformComponentState.Inactive => (Brush)WinUiApp.Current.Resources["TextMutedBrush"],
                _ => new SolidColorBrush(Microsoft.UI.Colors.Gray)
            };

            var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
            row.Children.Add(new FontIcon { Glyph = "\uE735", Foreground = color, FontSize = 10 });
            row.Children.Add(new TextBlock
            {
                Text = LocalizationService.GetString(item.LabelKey),
                TextWrapping = TextWrapping.WrapWholeWords,
                Foreground = (Brush)WinUiApp.Current.Resources["TextMutedBrush"]
            });
            PlatformStatusList.Children.Add(row);
        }
    }

    public void UpdateAntivirusCardStatus(bool clamAvOk, int yaraRulesCount, string? clamEngineMode = null)
    {
        if (clamAvOk && !string.IsNullOrWhiteSpace(clamEngineMode))
            ClamAvStatus.Text = LocalizationService.Format("Overview_ClamEngine", clamEngineMode);
        else
            ClamAvStatus.Text = clamAvOk
                ? LocalizationService.GetString("Overview_ClamActive")
                : LocalizationService.GetString("Overview_ClamMissing");

        ClamAvStatus.Foreground = clamAvOk
            ? (Brush)WinUiApp.Current.Resources["AccentBrush"]
            : new SolidColorBrush(Microsoft.UI.Colors.IndianRed);

        YaraStatus.Text = yaraRulesCount > 0
            ? LocalizationService.Format("Overview_YaraLoaded", yaraRulesCount)
            : LocalizationService.GetString("Overview_YaraMissing");
    }

    public void UpdateSignaturesSummary(string yaraPackVer, string yaraLastMaj, string clamDbVer, string clamLastMaj)
    {
        YaraPackVersion.Text = string.IsNullOrWhiteSpace(yaraPackVer) ? "—" : yaraPackVer;
        YaraLastUpdate.Text = string.IsNullOrWhiteSpace(yaraLastMaj) ? "—" : yaraLastMaj;
        ClamDbVersion.Text = VersionDisplayHelper.NormalizeForDisplay(
            string.IsNullOrWhiteSpace(clamDbVer) ? null : clamDbVer);
        ClamLastUpdate.Text = string.IsNullOrWhiteSpace(clamLastMaj) ? "—" : clamLastMaj;
    }

    public void UpdateProtectionStatistics(IReadOnlyList<ScanSession> history)
    {
        var now = DateTime.Now;
        int totalLifetime = WinUiServiceHost.Instance.Container.UserPreferencesAccessor.Current.TotalScansCount;
        ProtectionStatsBody.Text = OverviewProtectionStatsFormatter.Format(history, totalLifetime, now);
        ProtectionStatsUpdated.Text = LocalizationService.Format("Overview_UpdatedAt", now.ToString("G", CultureInfo.CurrentCulture));
    }

    public void UpdateLastScanSummary(ScanSession? lastSession)
    {
        LastScanText.Text = ScanLastScanDisplay.FormatDetailed(lastSession);
    }

    private void OnPostureFixRequested(string uri)
    {
        const string prefix = "opticombat://panel/";
        if (uri.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            var segment = uri[prefix.Length..].Trim().TrimEnd('/');
            var slash = segment.IndexOfAny(['/', '?', '#']);
            if (slash >= 0)
                segment = segment[..slash];

            var tag = segment.ToLowerInvariant() switch
            {
                "antivirus" => "antivirus",
                "options" => "options",
                "history" => "history",
                "clean" => "clean",
                _ => "overview"
            };
            ActionRequested?.Invoke(this, tag);
            return;
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(uri) { UseShellExecute = true });
        }
        catch
        {
        }
    }

    private void Action_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string tag })
            ActionRequested?.Invoke(this, tag == "update" ? "update" : tag);
    }

    private void RunAsAdmin_Click(object sender, RoutedEventArgs e)
    {
        if (ElevationHelper.RelaunchElevated())
            WinUiApp.Current.Exit();
    }
}
