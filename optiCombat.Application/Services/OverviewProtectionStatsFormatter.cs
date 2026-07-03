using optiCombat.Localization;
using optiCombat.Models;
using System.Globalization;
using System.Text;

namespace optiCombat.Services
{
    /// <summary>
    /// Texte de la carte « Statistiques de protection » (synthèse 30 j + renvoi Historique).
    /// </summary>
    public static class OverviewProtectionStatsFormatter
    {
        public static string Format(IReadOnlyList<ScanSession> history, int totalLifetime, DateTime now)
        {
            var cutoff = now.AddDays(-30);
            int sessions30 = 0;
            long files30 = 0;
            long threats30 = 0;

            foreach (var s in history)
            {
                if (s.StartedAt < cutoff) continue;
                sessions30++;
                files30 += Math.Max(0, s.FilesScanned);
                threats30 += Math.Max(0, s.ThreatsFound);
            }

            var cult = CultureInfo.CurrentCulture;
            var sb = new StringBuilder();

            if (history.Count == 0)
            {
                sb.AppendLine(LocalizationService.GetString("Overview_StatsNoHistory"));
            }
            else if (sessions30 == 0)
            {
                sb.AppendLine(LocalizationService.GetString("Overview_StatsNone30"));
            }
            else
            {
                sb.AppendLine(LocalizationService.Format("Overview_StatsScans", sessions30.ToString("N0", cult)));
                sb.AppendLine(LocalizationService.Format("Overview_StatsFiles", files30.ToString("N0", cult)));
                sb.AppendLine(LocalizationService.Format("Overview_StatsThreats", threats30.ToString("N0", cult)));
                if (threats30 > 0)
                    sb.AppendLine(LocalizationService.GetString("Overview_StatsTreatHint"));
            }

            sb.AppendLine();
            sb.AppendLine(LocalizationService.Format("Overview_StatsLifetime", totalLifetime.ToString("N0", cult)));
            sb.Append(LocalizationService.GetString("Overview_StatsHistoryHint"));
            return sb.ToString().TrimEnd();
        }
    }
}
