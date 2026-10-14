using optiCombat.Localization;
using optiCombat.Models;
using System.Globalization;
using System.IO;
using System.Text;

namespace optiCombat.Services
{
    /// <summary>
    /// Génère un rapport HTML moderne à partir de l'historique des scans
    /// et des menaces détectées (libellés selon la culture UI active).
    /// </summary>
    public sealed class HtmlExportService
    {
        public void ExportFullReport(
            IEnumerable<ScanSession> scanHistory,
            IEnumerable<ThreatInfo> activeThreats,
            IEnumerable<QuarantineEntry> quarantine,
            UserPreferences prefs,
            string outputPath)
        {
            var html = BuildHtml(scanHistory, activeThreats, quarantine, prefs);
            File.WriteAllText(outputPath, html, Encoding.UTF8);
        }

        private static string RedactPath(string? path) => PathRedaction.RedactPath(path);

        private static string BuildHtml(
            IEnumerable<ScanSession> scans,
            IEnumerable<ThreatInfo> threats,
            IEnumerable<QuarantineEntry> quarantine,
            UserPreferences prefs)
        {
            static string L(string key) => LocalizationService.GetString(key);

            var cult = CultureInfo.CurrentCulture;
            var lang = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
            var now = DateTime.Now;
            var scanList = scans.Take(20).ToList();
            var threatList = threats.ToList();
            var quarList = quarantine.Take(50).ToList();
            var totalScans = scanList.Count;
            var totalThreats = scanList.Sum(s => s.ThreatsFound);
            var dateShort = now.ToString("d", cult);
            var generatedAt = now.ToString("f", cult);

            var sb = new StringBuilder();
            sb.AppendLine($@"<!DOCTYPE html>
<html lang=""{lang}"">
<head>
  <meta charset=""UTF-8"">
  <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
  <title>{LocalizationService.Format("Export_Html_Title", dateShort)}</title>
  <style>
    :root {{
      --bg:       #0b1628;
      --surface:  #111f3c;
      --card:     #162040;
      --border:   #1e3a6e;
      --blue:     #3b82f6;
      --gold:     #f59e0b;
      --green:    #22c55e;
      --red:      #ef4444;
      --text:     #e2e8f0;
      --muted:    #64748b;
      --radius:   12px;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 32px;
      line-height: 1.6;
    }}
    header {{
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 32px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
    }}
    .logo {{
      width: 48px; height: 48px;
      background: linear-gradient(135deg, #E02020, #8B0000);
      border-radius: 12px;
      display: flex; align-items: center; justify-content: center;
      font-size: 24px;
      color: #fff;
    }}
    h1 {{ font-size: 22px; font-weight: 700; }}
    .meta {{ color: var(--muted); font-size: 13px; margin-top: 2px; }}
    .grid-4 {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 28px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 18px 20px;
    }}
    .card-label {{ color: var(--muted); font-size: 11px; font-weight: 600;
                   text-transform: uppercase; letter-spacing: .6px; margin-bottom: 6px; }}
    .card-value {{ font-size: 28px; font-weight: 700; }}
    .blue {{ color: var(--blue); }}
    .gold {{ color: var(--gold); }}
    .green {{ color: var(--green); }}
    .red {{ color: var(--red); }}
    h2 {{
      font-size: 14px; font-weight: 600; color: var(--gold);
      text-transform: uppercase; letter-spacing: .5px;
      margin-bottom: 12px;
    }}
    table {{
      width: 100%; border-collapse: collapse; font-size: 13px;
      margin-bottom: 28px;
    }}
    thead th {{
      background: var(--surface);
      color: var(--muted);
      font-size: 11px; font-weight: 600; text-align: left;
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
    }}
    tbody tr {{ border-bottom: 1px solid var(--border); }}
    tbody tr:hover {{ background: var(--surface); }}
    td {{ padding: 10px 14px; }}
    .badge {{
      display: inline-block; padding: 2px 8px; border-radius: 20px;
      font-size: 11px; font-weight: 600;
    }}
    .badge-ok  {{ background: #16532320; color: var(--green); }}
    .badge-warn {{ background: #92400e20; color: var(--gold); }}
    .badge-err  {{ background: #7f1d1d20; color: var(--red); }}
    .section {{ margin-bottom: 32px; }}
    footer {{
      color: var(--muted); font-size: 11px; text-align: center;
      margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border);
    }}
    @media (max-width: 700px) {{ .grid-4 {{ grid-template-columns: repeat(2,1fr); }} }}
  </style>
</head>
<body>
<header>
  <div class=""logo"" aria-hidden=""true"">
    <svg xmlns=""http://www.w3.org/2000/svg"" width=""28"" height=""28"" viewBox=""0 0 24 24"" fill=""currentColor"">
      <path d=""M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z""/>
    </svg>
  </div>
  <div>
    <h1>{L("Export_Html_ReportTitle")}</h1>
    <div class=""meta"">{LocalizationService.Format("Export_Html_GeneratedMeta", generatedAt, ProductVersionInfo.ReleaseLabel, ProductVersionInfo.SemVer)}</div>
  </div>
</header>

<div class=""grid-4"">
  <div class=""card"">
    <div class=""card-label"">{L("Export_Html_KpiTotalScans")}</div>
    <div class=""card-value blue"">{prefs.TotalScansCount}</div>
  </div>
  <div class=""card"">
    <div class=""card-label"">{L("Export_Html_KpiInReport")}</div>
    <div class=""card-value gold"">{totalScans}</div>
  </div>
  <div class=""card"">
    <div class=""card-label"">{L("Export_Html_KpiThreats")}</div>
    <div class=""card-value red"">{totalThreats}</div>
  </div>
  <div class=""card"">
    <div class=""card-label"">{L("Export_Html_KpiQuarantine")}</div>
    <div class=""card-value green"">{quarList.Count}</div>
  </div>
</div>

<div class=""section"">
  <h2>{L("Export_Html_ScanHistory")}</h2>
  <table>
    <thead>
      <tr>
        <th>{L("Export_Html_ColDate")}</th>
        <th>{L("Export_Html_ColType")}</th>
        <th>{L("Export_Html_ColFiles")}</th>
        <th>{L("Export_Html_ColThreats")}</th>
        <th>{L("Export_Html_ColDuration")}</th>
        <th>{L("Export_Html_ColStatus")}</th>
      </tr>
    </thead>
    <tbody>");

            foreach (var s in scanList)
            {
                string badge = s.ThreatsFound == 0
                    ? $"<span class=\"badge badge-ok\">{L("Export_Html_BadgeClean")}</span>"
                    : $"<span class=\"badge badge-err\">{LocalizationService.Format("Export_Html_BadgeThreats", s.ThreatsFound)}</span>";

                sb.AppendLine($@"      <tr>
        <td>{s.StartedAt.ToString("g", cult)}</td>
        <td>{System.Net.WebUtility.HtmlEncode(s.TypeDisplay)}</td>
        <td>{s.FilesScanned.ToString("N0", cult)}</td>
        <td class=""{(s.ThreatsFound > 0 ? "red" : "green")}"">{s.ThreatsFound}</td>
        <td>{System.Net.WebUtility.HtmlEncode(s.DurationDisplay)}</td>
        <td>{badge}</td>
      </tr>");
            }

            if (!scanList.Any())
                sb.AppendLine($"      <tr><td colspan=\"6\" style=\"text-align:center;color:var(--muted)\">{L("Export_Html_NoScans")}</td></tr>");

            sb.AppendLine("    </tbody></table></div>");

            if (threatList.Any())
            {
                sb.AppendLine($@"<div class=""section"">
  <h2>{L("Export_Html_ActiveThreats")}</h2>
  <table>
    <thead><tr><th>{L("Export_Html_ColFile")}</th><th>{L("Export_Html_ColVirus")}</th><th>{L("Export_Html_ColPath")}</th><th>{L("Export_Html_ColStatus")}</th></tr></thead>
    <tbody>");
                foreach (var t in threatList)
                {
                    sb.AppendLine($@"      <tr>
        <td>{System.Net.WebUtility.HtmlEncode(t.FileName)}</td>
        <td class=""red"">{System.Net.WebUtility.HtmlEncode(t.VirusName)}</td>
        <td style=""font-size:11px;color:var(--muted)"">{System.Net.WebUtility.HtmlEncode(RedactPath(t.FilePath))}</td>
        <td><span class=""badge badge-err"">{L("Export_Html_Untreated")}</span></td>
      </tr>");
                }
                sb.AppendLine("    </tbody></table></div>");
            }

            if (quarList.Any())
            {
                sb.AppendLine($@"<div class=""section"">
  <h2>{L("Export_Html_Quarantine")}</h2>
  <table>
    <thead><tr><th>{L("Export_Html_ColFile")}</th><th>{L("Export_Html_ColVirus")}</th><th>{L("Export_Html_ColQDate")}</th><th>{L("Export_Html_ColSize")}</th></tr></thead>
    <tbody>");
                foreach (var q in quarList)
                {
                    sb.AppendLine($@"      <tr>
        <td>{System.Net.WebUtility.HtmlEncode(q.FileName)}</td>
        <td class=""gold"">{System.Net.WebUtility.HtmlEncode(q.VirusName)}</td>
        <td>{q.QuarantinedAt.ToString("g", cult)}</td>
        <td>{System.Net.WebUtility.HtmlEncode(q.SizeDisplay)}</td>
      </tr>");
                }
                sb.AppendLine("    </tbody></table></div>");
            }

            if (prefs.RecentTargets.Any())
            {
                sb.AppendLine($@"<div class=""section"">
  <h2>{L("Export_Html_RecentTargets")}</h2>
  <table>
    <thead><tr><th>{L("Export_Html_ColPath")}</th><th>{L("Export_Html_ColType")}</th><th>{L("Export_Html_ColLastScan")}</th></tr></thead>
    <tbody>");
                foreach (var r in prefs.RecentTargets)
                {
                    sb.AppendLine($@"      <tr>
        <td>{System.Net.WebUtility.HtmlEncode(RedactPath(r.Path))}</td>
        <td>{System.Net.WebUtility.HtmlEncode(LocalizationService.ScanTypeDisplay(r.ScanType))}</td>
        <td>{r.LastUsed.ToString("g", cult)}</td>
      </tr>");
                }
                sb.AppendLine("    </tbody></table></div>");
            }

            sb.AppendLine($@"<footer>
  {LocalizationService.Format("Export_Html_Footer", ProductVersionInfo.ReleaseLabel, ProductVersionInfo.SemVer, now.Year.ToString(cult))}
</footer>
</body>
</html>");

            return sb.ToString();
        }
    }
}
