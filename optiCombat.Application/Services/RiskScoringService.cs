using optiCombat.Localization;
using optiCombat.Models;
using System.IO;

namespace optiCombat.Services
{
    /// <summary>
    /// Calcule un score de risque pour une menace détectée.
    /// Classification : Informationnel / Mineur / Majeur / Critique
    /// </summary>
    public static class RiskScoringService
    {
        private static readonly Dictionary<string, RiskLevel> KeywordRiskMap = new(StringComparer.OrdinalIgnoreCase)
        {
            { "ransom",          RiskLevel.Critical },
            { "ransomware",      RiskLevel.Critical },
            { "locky",           RiskLevel.Critical },
            { "wannacry",        RiskLevel.Critical },
            { "notpetya",        RiskLevel.Critical },
            { "rootkit",         RiskLevel.Critical },
            { "bootkit",         RiskLevel.Critical },
            { "backdoor",        RiskLevel.Critical },
            { "trojan.ransom",   RiskLevel.Critical },
            { "malware.ransom",  RiskLevel.Critical },
            { "worm.win32",      RiskLevel.Critical },

            { "trojan",          RiskLevel.Major },
            { "worm",            RiskLevel.Major },
            { "spy",             RiskLevel.Major },
            { "spyware",         RiskLevel.Major },
            { "keylog",          RiskLevel.Major },
            { "keylogger",       RiskLevel.Major },
            { "downloader",      RiskLevel.Major },
            { "dropper",         RiskLevel.Major },
            { "infostealer",     RiskLevel.Major },
            { "banker",          RiskLevel.Major },

            { "adware",          RiskLevel.Minor },
            { "pup",             RiskLevel.Minor },
            { "pua",             RiskLevel.Minor },
            { "hacktool",        RiskLevel.Minor },
            { "riskware",        RiskLevel.Minor },
            { "potentially",     RiskLevel.Minor },
            { "unsafe",          RiskLevel.Minor },

            { "suspicious",      RiskLevel.Informational },
            { "detected",        RiskLevel.Informational },
        };

        private static readonly HashSet<string> HighRiskExtensions = new(
            new[] { ".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js", ".jar", ".msi" },
            StringComparer.OrdinalIgnoreCase);

        private static readonly HashSet<string> MacroExtensions = new(
            new[] { ".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".ppam" },
            StringComparer.OrdinalIgnoreCase);

        public static RiskAssessment Assess(ThreatInfo threat)
        {
            var score = 0;
            var reasons = new List<string>();

            var (level, reason) = AnalyzeVirusName(threat.VirusName);
            score += GetScore(level);
            reasons.Add(reason);

            var fileLevel = AnalyzeFilePath(threat.FilePath);
            score += GetScore(fileLevel);
            reasons.Add(LocalizationService.Format(
                "Risk_Reason_File",
                GetFileRiskReason(threat.FilePath, fileLevel)));

            if (!string.IsNullOrEmpty(threat.DetectedBy) && threat.DetectedBy.Contains('+'))
            {
                score += 20;
                reasons.Add(LocalizationService.GetString("Risk_Reason_Corroborated"));
            }

            if (threat.FileSize > 0 && threat.FileSize < 1024 * 1024)
            {
                score += 10;
                reasons.Add(LocalizationService.GetString("Risk_Reason_SmallPayload"));
            }
            else if (threat.FileSize > 50 * 1024 * 1024)
            {
                score -= 10;
                reasons.Add(LocalizationService.GetString("Risk_Reason_LargeFile"));
            }

            var finalLevel = GetRiskLevelFromScore(score);

            return new RiskAssessment
            {
                Score = score,
                Level = finalLevel,
                Severity = GetSeverityString(finalLevel),
                Color = GetSeverityColor(finalLevel),
                BrushKey = GetSeverityBrushKey(finalLevel),
                IconKind = GetSeverityIconKind(finalLevel),
                Recommendation = GetRecommendation(finalLevel, threat),
                Reasons = reasons
            };
        }

        public static RiskAssessment AssessAll(IEnumerable<ThreatInfo> threats)
        {
            RiskAssessment? worst = null;
            foreach (var threat in threats)
            {
                var assessment = Assess(threat);
                if (worst == null || assessment.Score > worst.Score)
                    worst = assessment;
            }
            return worst ?? new RiskAssessment
            {
                Severity = LocalizationService.GetString("Risk_Severity_None"),
                Color = PdfRiskPalette.GetSeverityColor(RiskLevel.Informational),
                BrushKey = "RiskInformational",
                IconKind = UiIconKinds.Success,
                Recommendation = LocalizationService.GetString("Risk_Rec_Healthy")
            };
        }

        public static string GetSeverityLevel(ThreatInfo threat)
        {
            var (level, _) = AnalyzeVirusName(threat.VirusName);
            return GetSeverityString(level);
        }

        private static string NormalizeForMatch(string s)
            => s.Replace('_', ' ').Replace('.', ' ');

        private static (RiskLevel, string) AnalyzeVirusName(string virusName)
        {
            if (string.IsNullOrEmpty(virusName))
                return (RiskLevel.Informational, LocalizationService.GetString("Risk_Reason_UnknownName"));

            var normalizedName = NormalizeForMatch(virusName);

            foreach (var kvp in KeywordRiskMap)
            {
                if (virusName.Contains(kvp.Key, StringComparison.OrdinalIgnoreCase))
                    return (kvp.Value, LocalizationService.Format("Risk_Reason_Keyword", kvp.Key));

                var normalizedKey = NormalizeForMatch(kvp.Key);
                if (normalizedName.Contains(normalizedKey, StringComparison.OrdinalIgnoreCase))
                    return (kvp.Value, LocalizationService.Format("Risk_Reason_KeywordNormalized", kvp.Key));
            }

            return (RiskLevel.Minor, LocalizationService.GetString("Risk_Reason_GenericThreat"));
        }

        private static RiskLevel AnalyzeFilePath(string filePath)
        {
            var ext = Path.GetExtension(filePath);

            if (filePath.Contains(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase)
                || filePath.Contains(@"\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase))
                return RiskLevel.Critical;

            if (HighRiskExtensions.Contains(ext) || MacroExtensions.Contains(ext))
                return RiskLevel.Major;

            if (filePath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase)
                || filePath.Contains(@"\AppData\Local\Temp", StringComparison.OrdinalIgnoreCase))
                return RiskLevel.Minor;

            return RiskLevel.Informational;
        }

        private static string GetFileRiskReason(string filePath, RiskLevel level)
        {
            var ext = Path.GetExtension(filePath);

            if (filePath.Contains(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase)
                || filePath.Contains(@"\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase))
                return LocalizationService.GetString("Risk_File_SystemCritical");

            if (HighRiskExtensions.Contains(ext))
                return LocalizationService.Format("Risk_File_Executable", ext);

            if (MacroExtensions.Contains(ext))
                return LocalizationService.Format("Risk_File_Macro", ext);

            if (filePath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase)
                || filePath.Contains(@"\AppData\Local\Temp", StringComparison.OrdinalIgnoreCase))
                return LocalizationService.GetString("Risk_File_Temp");

            return LocalizationService.GetString("Risk_File_Standard");
        }

        private static int GetScore(RiskLevel level) => level switch
        {
            RiskLevel.Critical => 60,
            RiskLevel.Major => 40,
            RiskLevel.Minor => 20,
            RiskLevel.Informational => 5,
            _ => 10
        };

        private static RiskLevel GetRiskLevelFromScore(int score) => score switch
        {
            >= 80 => RiskLevel.Critical,
            >= 50 => RiskLevel.Major,
            >= 25 => RiskLevel.Minor,
            _ => RiskLevel.Informational
        };

        private static string GetSeverityString(RiskLevel level) => level switch
        {
            RiskLevel.Critical => LocalizationService.GetString("Risk_Severity_Critical"),
            RiskLevel.Major => LocalizationService.GetString("Risk_Severity_Major"),
            RiskLevel.Minor => LocalizationService.GetString("Risk_Severity_Minor"),
            _ => LocalizationService.GetString("Risk_Severity_Informational")
        };

        public static string GetSeverityBrushKey(RiskLevel level) => level switch
        {
            RiskLevel.Critical => "RiskCritical",
            RiskLevel.Major => "RiskMajor",
            RiskLevel.Minor => "RiskMinor",
            _ => "RiskInformational"
        };

        private static string GetSeverityColor(RiskLevel level) => PdfRiskPalette.GetSeverityColor(level);

        private static string GetSeverityIconKind(RiskLevel level) => UiIconKinds.ForRiskLevel(level);

        private static string GetRecommendation(RiskLevel level, ThreatInfo threat)
        {
            var name = Path.GetFileName(threat.FilePath);
            if (string.IsNullOrEmpty(name))
                name = threat.FileName;
            return level switch
            {
                RiskLevel.Critical => LocalizationService.Format("Risk_Rec_Critical", name),
                RiskLevel.Major => LocalizationService.Format("Risk_Rec_Major", name),
                RiskLevel.Minor => LocalizationService.Format("Risk_Rec_Minor", name),
                _ => LocalizationService.Format("Risk_Rec_Info", threat.VirusName ?? name),
            };
        }
    }

    public enum RiskLevel
    {
        Informational,
        Minor,
        Major,
        Critical
    }

    public class RiskAssessment
    {
        public int Score { get; set; }
        public RiskLevel Level { get; set; }
        public string Severity { get; set; } = string.Empty;
        public string Color { get; set; } = string.Empty;
        public string BrushKey { get; set; } = string.Empty;
        public string IconKind { get; set; } = string.Empty;
        public string Recommendation { get; set; } = string.Empty;
        public List<string> Reasons { get; set; } = new();
    }
}
