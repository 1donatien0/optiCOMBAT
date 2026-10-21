using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

[Collection("Localization")]
public sealed class RiskScoringServiceTests
{
    public RiskScoringServiceTests() => LocalizationService.ApplyCulture("fr-FR");

    private static ThreatInfo Threat(string virus, string path, long size = -1, string detectedBy = "ClamAV") => new()
    {
        VirusName = virus,
        FilePath = path,
        FileSize = size,
        DetectedBy = detectedBy,
    };

    [Theory]
    [InlineData("Win.Ransom.Locky", @"C:\Windows\System32\evil.dll", 4096, RiskLevel.Critical)]
    [InlineData("Win.Trojan.Agent", @"C:\Users\u\Downloads\setup.exe", -1, RiskLevel.Critical)]
    [InlineData("PUA.Win.Adware", @"C:\Users\u\AppData\Local\Temp\a.txt", -1, RiskLevel.Minor)]
    [InlineData("Heuristics.Suspicious", @"D:\docs\notes.txt", -1, RiskLevel.Informational)]
    [InlineData("", @"D:\docs\notes.txt", 60L * 1024 * 1024, RiskLevel.Informational)]
    [InlineData("Win.Spy.Keylogger", @"D:\docs\report.docm", -1, RiskLevel.Critical)]
    public void Assess_combines_name_path_and_size(string virus, string path, long size, RiskLevel expected)
    {
        var assessment = RiskScoringService.Assess(Threat(virus, path, size));

        Assert.Equal(expected, assessment.Level);
        Assert.False(string.IsNullOrWhiteSpace(assessment.Severity));
        Assert.False(string.IsNullOrWhiteSpace(assessment.Recommendation));
        Assert.False(string.IsNullOrWhiteSpace(assessment.Color));
        Assert.False(string.IsNullOrWhiteSpace(assessment.IconKind));
        Assert.StartsWith("Risk", assessment.BrushKey);
        Assert.True(assessment.Reasons.Count >= 2);
    }

    [Fact]
    public void Corroborated_detection_raises_the_score()
    {
        var single = RiskScoringService.Assess(Threat("Win.Adware.X", @"D:\a.txt", detectedBy: "ClamAV"));
        var both = RiskScoringService.Assess(Threat("Win.Adware.X", @"D:\a.txt", detectedBy: "ClamAV+YARA"));

        Assert.Equal(single.Score + 20, both.Score);
        Assert.Contains(LocalizationService.GetString("Risk_Reason_Corroborated"), both.Reasons);
    }

    [Fact]
    public void Small_payload_adds_points_and_large_file_removes_some()
    {
        var baseline = RiskScoringService.Assess(Threat("Win.Worm.Y", @"D:\b.txt"));
        var small = RiskScoringService.Assess(Threat("Win.Worm.Y", @"D:\b.txt", size: 2048));
        var large = RiskScoringService.Assess(Threat("Win.Worm.Y", @"D:\b.txt", size: 80L * 1024 * 1024));

        Assert.Equal(baseline.Score + 10, small.Score);
        Assert.Equal(baseline.Score - 10, large.Score);
    }

    [Fact]
    public void AssessAll_returns_worst_or_healthy_default()
    {
        var healthy = RiskScoringService.AssessAll(Array.Empty<ThreatInfo>());
        Assert.Equal(LocalizationService.GetString("Risk_Severity_None"), healthy.Severity);
        Assert.Equal("RiskInformational", healthy.BrushKey);
        Assert.Equal(LocalizationService.GetString("Risk_Rec_Healthy"), healthy.Recommendation);

        var worst = RiskScoringService.AssessAll(new[]
        {
            Threat("Heuristics.Suspicious", @"D:\a.txt"),
            Threat("Win.Rootkit.Z", @"C:\Windows\SysWOW64\z.sys"),
            Threat("PUA.Tool", @"D:\c.txt"),
        });
        Assert.Equal(RiskLevel.Critical, worst.Level);
    }

    [Theory]
    [InlineData(RiskLevel.Critical, "RiskCritical")]
    [InlineData(RiskLevel.Major, "RiskMajor")]
    [InlineData(RiskLevel.Minor, "RiskMinor")]
    [InlineData(RiskLevel.Informational, "RiskInformational")]
    public void Brush_keys_match_theme_dictionaries(RiskLevel level, string key) =>
        Assert.Equal(key, RiskScoringService.GetSeverityBrushKey(level));

    [Fact]
    public void GetSeverityLevel_only_looks_at_the_signature_name()
    {
        var critical = RiskScoringService.GetSeverityLevel(Threat("Backdoor.Win32", @"D:\a.txt"));
        var info = RiskScoringService.GetSeverityLevel(Threat("", @"C:\Windows\System32\a.exe"));

        Assert.Equal(LocalizationService.GetString("Risk_Severity_Critical"), critical);
        Assert.Equal(LocalizationService.GetString("Risk_Severity_Informational"), info);
    }

    [Theory]
    [InlineData(ScanType.File, "ScanType_File")]
    [InlineData(ScanType.Folder, "ScanType_Folder")]
    [InlineData(ScanType.FullScan, "ScanType_Full")]
    [InlineData(ScanType.QuickScan, "ScanType_Quick")]
    [InlineData(ScanType.RemovableDrive, "ScanType_Removable")]
    [InlineData(ScanType.RealTime, "ScanType_RealTime")]
    [InlineData((ScanType)99, "ScanType_Default")]
    public void ScanTypeDisplay_covers_every_type(ScanType type, string key) =>
        Assert.Equal(LocalizationService.GetString(key), LocalizationService.ScanTypeDisplay(type));

    [Fact]
    public void Format_with_bad_template_arguments_returns_template()
    {
        var template = LocalizationService.GetString("Vm_QuarantinePartial");
        Assert.Equal(template, LocalizationService.Format("Vm_QuarantinePartial"));
        Assert.Contains("5", LocalizationService.ScanSummaryDisplay(ScanStatus.Running, 5, 0, TimeSpan.Zero, null));
    }
}

public sealed class QuarantineRestoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "opticombat_qr_" + Guid.NewGuid().ToString("N"));
    private readonly QuarantineManager _quarantine;

    public QuarantineRestoreTests()
    {
        Directory.CreateDirectory(_root);
        _quarantine = new QuarantineManager(Path.Combine(_root, "q"), new TestSupport.FixedPreferencesAccessor(new UserPreferences()));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch { /* best effort */ }
    }

    private string QuarantineSample(string name, string content)
    {
        var dir = Path.Combine(_root, "src");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, name);
        File.WriteAllText(path, content);
        Assert.True(_quarantine.Quarantine(ThreatInfo.FromClamAv(path, "Win.Test", content.Length)));
        return _quarantine.GetEntries().Single(e => e.OriginalPath == path).Id;
    }

    [Fact]
    public void RestoreTo_writes_into_target_folder_and_avoids_overwrite()
    {
        var id = QuarantineSample("doc.txt", "contenu");
        var target = Path.Combine(_root, "restored");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "doc.txt"), "déjà là");

        Assert.True(_quarantine.RestoreTo(id, target));

        Assert.Equal("contenu", File.ReadAllText(Path.Combine(target, "doc_restored.txt")));
        Assert.Equal("déjà là", File.ReadAllText(Path.Combine(target, "doc.txt")));
        Assert.Equal(0, _quarantine.Count);
    }

    [Fact]
    public void RestoreTo_creates_missing_folder()
    {
        var id = QuarantineSample("x.bin", "abc");
        var target = Path.Combine(_root, "new", "folder");

        Assert.True(_quarantine.RestoreTo(id, target));
        Assert.True(File.Exists(Path.Combine(target, "x.bin")));
    }

    [Fact]
    public void Restore_operations_reject_unknown_ids()
    {
        Assert.False(_quarantine.RestoreTo("inconnu", _root));
        Assert.False(_quarantine.RestoreAdministrative("inconnu"));
        Assert.False(_quarantine.Restore("inconnu"));
        Assert.False(_quarantine.DeletePermanently("inconnu"));
    }

    [Fact]
    public void RestoreAdministrative_puts_file_back_at_original_path()
    {
        var id = QuarantineSample("admin.txt", "retour");
        var original = Path.Combine(_root, "src", "admin.txt");
        Assert.False(File.Exists(original));

        Assert.True(_quarantine.RestoreAdministrative(id));

        Assert.Equal("retour", File.ReadAllText(original));
    }

    [Fact]
    public void Quarantine_of_missing_file_fails()
    {
        Assert.False(_quarantine.Quarantine(ThreatInfo.FromClamAv(Path.Combine(_root, "absent.exe"), "Win.None")));
        Assert.Equal(0, _quarantine.Count);
    }
}
