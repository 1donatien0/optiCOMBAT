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

    /// <summary>Message à afficher dans la barre d'état (résultat d'une correction de posture).</summary>
    public event EventHandler<string>? StatusMessageRequested;

    public OverviewPage()
    {
        InitializeComponent();
        BuildScanFlyout();
        ApplyElevationBanner();
    }

    /// <summary>Menu de la tuile Antivirus : analyse rapide, complète ou choix manuel (comme optiSCAN).</summary>
    private void BuildScanFlyout()
    {
        var flyout = new MenuFlyout();

        var quick = new MenuFlyoutItem { Icon = new FontIcon { Glyph = "\uE945" } };
        quick.Click += (_, _) => ActionRequested?.Invoke(this, "scan-quick");

        var full = new MenuFlyoutItem { Icon = new FontIcon { Glyph = "\uE721" } };
        full.Click += (_, _) => ActionRequested?.Invoke(this, "scan-full");

        var custom = new MenuFlyoutItem { Icon = new FontIcon { Glyph = "\uE8B7" } };
        custom.Click += (_, _) => ActionRequested?.Invoke(this, "antivirus");

        flyout.Items.Add(quick);
        flyout.Items.Add(full);
        flyout.Items.Add(new MenuFlyoutSeparator());
        flyout.Items.Add(custom);

        // Libellés relus à chaque ouverture : suivent le changement de langue.
        flyout.Opening += (_, _) =>
        {
            quick.Text = LocalizationService.GetString("ScanType_Quick");
            full.Text = LocalizationService.GetString("ScanType_Full");
            custom.Text = LocalizationService.GetString("Overview_ScanTitle") + "…";
        };

        ActionScanBtn.Flyout = flyout;
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
            0 or 2 => WinUiThemeManager.GetBrush("AccentBrush"),
            1 => WinUiThemeManager.GetBrush("WarningBrush"),
            _ => WinUiThemeManager.GetBrush("AccentBrush")
        };

        // Un seul abonnement : cette méthode est rappelée à chaque rafraîchissement de l'accueil,
        // ce qui empilait auparavant un gestionnaire (et donc une mise à jour) par rafraîchissement.
        _hygieneLinkActive = showSigUpdateLink;
        if (!_hygieneTappedHooked)
        {
            _hygieneTappedHooked = true;
            HygieneRecommendation.Tapped += (_, _) =>
            {
                if (_hygieneLinkActive)
                    ActionRequested?.Invoke(this, "update");
            };
        }
    }

    private bool _hygieneLinkActive;
    private bool _hygieneTappedHooked;

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
                Foreground = WinUiThemeManager.GetBrush("TextMutedBrush")
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
                Foreground = WinUiThemeManager.GetBrush("TextMutedBrush")
            });

            if (PostureFixService.CanAutoFix(check.Id))
            {
                var fix = new HyperlinkButton
                {
                    Content = LocalizationService.GetString("Posture_Fix"),
                    Padding = new Thickness(0),
                };
                var checkId = check.Id;
                fix.Click += async (_, _) => await OnPostureAutoFixAsync(checkId, fix);
                panel.Children.Add(fix);
            }
            else if (!string.IsNullOrWhiteSpace(check.FixUri))
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
                PlatformComponentState.Active => WinUiThemeManager.GetBrush("AccentBrush"),
                PlatformComponentState.Warning => WinUiThemeManager.GetBrush("WarningBrush"),
                PlatformComponentState.Inactive => WinUiThemeManager.GetBrush("TextMutedBrush"),
                _ => WinUiThemeManager.GetBrush("TextMutedBrush")
            };

            var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
            row.Children.Add(new FontIcon { Glyph = "\uE735", Foreground = color, FontSize = 10 });
            row.Children.Add(new TextBlock
            {
                Text = LocalizationService.GetString(item.LabelKey),
                TextWrapping = TextWrapping.WrapWholeWords,
                Foreground = WinUiThemeManager.GetBrush("TextMutedBrush")
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
            ? WinUiThemeManager.GetBrush("AccentBrush")
            : WinUiThemeManager.GetBrush("DangerBrush");

        YaraStatus.Text = yaraRulesCount > 0
            ? LocalizationService.Format("Overview_YaraLoaded", yaraRulesCount)
            : LocalizationService.GetString("Overview_YaraMissing");
        YaraStatus.Foreground = yaraRulesCount > 0
            ? WinUiThemeManager.GetBrush("InfoBrush")
            : WinUiThemeManager.GetBrush("DangerBrush");
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

        // Plusieurs cibles possibles séparées par « | » (ex. ms-settings:…|control.exe …) : première qui s'ouvre.
        foreach (var candidate in uri.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                var space = candidate.StartsWith("ms-settings:", StringComparison.OrdinalIgnoreCase) ? -1 : candidate.IndexOf(' ');
                var psi = space > 0
                    ? new System.Diagnostics.ProcessStartInfo(candidate[..space], candidate[(space + 1)..]) { UseShellExecute = true }
                    : new System.Diagnostics.ProcessStartInfo(candidate) { UseShellExecute = true };
                System.Diagnostics.Process.Start(psi);
                return;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("OverviewPage", $"Ouverture {candidate}", ex);
            }
        }
    }

    private async Task OnPostureAutoFixAsync(string checkId, Control trigger)
    {
        trigger.IsEnabled = false;
        try
        {
            var host = WinUiServiceHost.Instance;
            var result = await PostureFixService.FixAsync(
                checkId,
                host.Container,
                (message, title) => host.Confirm.ConfirmYesNo(message, title),
                startQuickScan: () =>
                {
                    ActionRequested?.Invoke(this, "antivirus");
                    return host.Antivirus.QuickScanAsync();
                }).ConfigureAwait(true);

            if (!string.IsNullOrWhiteSpace(result.Message))
                StatusMessageRequested?.Invoke(this, result.Message);
            if (result.Status is PostureFixStatus.Done or PostureFixStatus.NeedsRestart && checkId != "scan")
                ActionRequested?.Invoke(this, "overview");
        }
        finally
        {
            trigger.IsEnabled = true;
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
