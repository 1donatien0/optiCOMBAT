using optiCombat.Localization;
using System.IO;
using System.Text;

namespace optiCombat.Services
{
    /// <summary>
    /// Vérifie la présence des binaires et ressources embarqués requis au runtime
    /// (non versionnés dans git — fournis par publish ou installateur).
    /// </summary>
    public static class RuntimeDependencies
    {
        public sealed class DependencyStatus
        {
            public string Name { get; init; } = string.Empty;
            public bool IsReady { get; init; }
            public string ExpectedPath { get; init; } = string.Empty;
            public string Detail { get; init; } = string.Empty;
        }

        public sealed class Report
        {
            public IReadOnlyList<DependencyStatus> Items { get; init; } = Array.Empty<DependencyStatus>();
            public bool IsFullyReady => Items.Count > 0 && Items.All(i => i.IsReady);
            public bool IsClamAvReady => Items.FirstOrDefault(i => i.Name == "ClamAV")?.IsReady == true;
            public bool IsYaraReady => Items.FirstOrDefault(i => i.Name == "YARA")?.IsReady == true;

            public string BuildSummaryLine()
            {
                if (IsFullyReady)
                    return LocalizationService.GetString("Runtime_ReadySummary");
                var missing = Items.Where(i => !i.IsReady).Select(i => i.Name).ToList();
                return missing.Count == 0
                    ? LocalizationService.GetString("Runtime_IncompleteSummary")
                    : LocalizationService.Format("Runtime_MissingSummary", string.Join(", ", missing));
            }

            public string BuildDetailedMessage()
            {
                var sb = new StringBuilder();
                sb.AppendLine(LocalizationService.Format("Runtime_ExecDirFormat", AppInstallPaths.GetInstallRoot()));
                sb.AppendLine();
                foreach (var item in Items)
                {
                    sb.AppendLine(item.IsReady ? UiLogText.ReadyLine(item.Name) : UiLogText.MissingLine(item.Name));
                    sb.AppendLine(LocalizationService.Format("Runtime_ExpectedPath", item.ExpectedPath));
                    if (!string.IsNullOrWhiteSpace(item.Detail))
                        sb.AppendLine($"  {item.Detail}");
                    sb.AppendLine();
                }
                if (!IsFullyReady)
                {
                    sb.AppendLine(LocalizationService.GetString("Runtime_DevCopyHint"));
                    sb.AppendLine(LocalizationService.GetString("Runtime_DevVerifyScript"));
                    sb.AppendLine(LocalizationService.GetString("Runtime_DevReadmeRefs"));
                }
                return sb.ToString().TrimEnd();
            }
        }

        public static Report Evaluate()
        {
            var baseDir = AppInstallPaths.GetInstallRoot();
            var arch = Environment.Is64BitProcess ? "x64" : "x86";
            var yaraArch = Environment.Is64BitProcess ? "64" : "32";

            var clamDir = Path.Combine(baseDir, "clamav", arch);
            var clamscan = Path.Combine(clamDir, "clamscan.exe");
            var freshclam = Path.Combine(clamDir, "freshclam.exe");
            var clamReady = File.Exists(clamscan);

            var yaraDir = Path.Combine(baseDir, "yara");
            var yaraExe = Path.Combine(yaraDir, $"yara{yaraArch}.exe");
            var yaracExe = Path.Combine(yaraDir, $"yarac{yaraArch}.exe");
            var rulesDir = Path.Combine(baseDir, "rules");
            int yarCount = 0;
            try
            {
                if (Directory.Exists(rulesDir))
                    yarCount = Directory.GetFiles(rulesDir, "*.yar", SearchOption.TopDirectoryOnly).Length;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("RuntimeDependencies", $"Énumération rules : {rulesDir}", ex);
            }

            var yaraBinOk = File.Exists(yaraExe);
            var yaraRulesOk = yarCount > 0;
            var yaraReady = yaraBinOk && yaraRulesOk;

            string clamDetail = clamReady
                ? (File.Exists(freshclam)
                    ? LocalizationService.GetString("Runtime_ClamBothDetected")
                    : LocalizationService.GetString("Runtime_ClamNoFreshclam"))
                : LocalizationService.GetString("Runtime_ClamMissing");

            string yaraDetail = yaraReady
                ? LocalizationService.Format("Runtime_YaraReady", yarCount.ToString(), Path.GetFileName(yaraExe))
                : !yaraBinOk
                    ? LocalizationService.Format("Runtime_YaraBinMissing", yaraArch)
                    : LocalizationService.Format("Runtime_YaraNoRules", rulesDir);

            var yaracSuffix = File.Exists(yaracExe)
                ? string.Empty
                : LocalizationService.GetString("Runtime_YaracMissing");

            return new Report
            {
                Items = new[]
                {
                    new DependencyStatus
                    {
                        Name = "ClamAV",
                        IsReady = clamReady,
                        ExpectedPath = clamscan,
                        Detail = clamDetail,
                    },
                    new DependencyStatus
                    {
                        Name = "YARA",
                        IsReady = yaraReady,
                        ExpectedPath = yaraExe,
                        Detail = yaraDetail + yaracSuffix,
                    },
                },
            };
        }

        /// <summary>Journalise un avertissement si des dépendances manquent (appel au démarrage UI).</summary>
        public static void LogReportIfIncomplete()
        {
            var report = Evaluate();
            if (report.IsFullyReady)
            {
                AppLogger.Info("RuntimeDependencies", report.BuildSummaryLine());
                return;
            }

            AppLogger.Warn("RuntimeDependencies", report.BuildSummaryLine());
            foreach (var item in report.Items.Where(i => !i.IsReady))
                AppLogger.Warn("RuntimeDependencies", $"{item.Name} : {item.Detail} ({item.ExpectedPath})");
        }
    }
}
