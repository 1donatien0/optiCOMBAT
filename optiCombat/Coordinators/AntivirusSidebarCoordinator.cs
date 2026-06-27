using MaterialDesignThemes.Wpf;
using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Views;
using System.Windows.Controls;
using System.Windows.Media;

namespace optiCombat.Coordinators;

/// <summary>Badges ClamAV de la barre latérale et carte antivirus de l'accueil.</summary>
public static class AntivirusSidebarCoordinator
{
    public sealed class Host
    {
        public required Func<bool> IsClamAvInstalled { get; init; }
        public required Func<int> GetYaraRulesCount { get; init; }
        public required Func<string> GetClamActiveEngine { get; init; }
        public IOverviewPanel? OverviewPanel { get; init; }
        public TextBlock? SidebarClamBadge { get; init; }
        public PackIcon? SidebarClamIcon { get; init; }
    }

    public static async Task RefreshAsync(Host host)
    {
        bool clamAvOk = await Task.Run(host.IsClamAvInstalled).ConfigureAwait(true);
        int yaraRules = host.GetYaraRulesCount();

        if (host.SidebarClamBadge != null)
        {
            host.SidebarClamBadge.Text = clamAvOk
                ? LocalizationService.GetString("Main_ClamBadgeActive")
                : LocalizationService.GetString("Main_ClamBadgeMissing");
            host.SidebarClamBadge.Foreground = clamAvOk
                ? ThemeUiBrushes.Get("SuccessGreen", host.SidebarClamBadge)
                : ThemeUiBrushes.Get("DangerRed", host.SidebarClamBadge);
        }

        if (host.SidebarClamIcon != null)
        {
            host.SidebarClamIcon.Kind = clamAvOk ? PackIconKind.ShieldCheck : PackIconKind.ShieldOff;
            host.SidebarClamIcon.Foreground = clamAvOk
                ? ThemeUiBrushes.Get("SuccessGreen", host.SidebarClamIcon)
                : ThemeUiBrushes.Get("DangerRed", host.SidebarClamIcon);
        }

        host.OverviewPanel?.UpdateAntivirusCardStatus(clamAvOk, yaraRules, host.GetClamActiveEngine());
    }
}
