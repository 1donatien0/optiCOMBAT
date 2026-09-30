using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class RedactPathTests
{
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    [Fact]
    public void PathRedaction_masks_user_profile()
    {
        var input = Path.Combine(UserProfile, "Documents", "malware.exe");
        var result = PathRedaction.RedactPath(input);
        Assert.StartsWith("%UserProfile%", result, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(UserProfile, result, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PathRedaction_preserves_system_path()
    {
        const string systemPath = @"C:\Windows\System32\notepad.exe";
        Assert.Equal(systemPath, PathRedaction.RedactPath(systemPath));
    }

    [Fact]
    public void PathRedaction_handles_null_and_empty()
    {
        Assert.Equal(string.Empty, PathRedaction.RedactPath(null));
        Assert.Equal(string.Empty, PathRedaction.RedactPath(string.Empty));
    }

    [Fact]
    public void Html_export_uses_shared_redaction()
    {
        var input = Path.Combine(UserProfile, "Downloads", "virus.zip");
        var method = typeof(HtmlExportService).GetMethod(
            "RedactPath",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var result = (string)method.Invoke(null, new object?[] { input })!;
        Assert.Contains("%UserProfile%", result, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Pdf_export_uses_shared_redaction()
    {
        var input = Path.Combine(UserProfile, "Desktop", "file.exe");
        var method = typeof(PdfReportGenerator).GetMethod(
            "RedactPath",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var result = (string)method.Invoke(null, new object?[] { input })!;
        Assert.Contains("%UserProfile%", result, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ScanLogManager_masks_threat_paths_in_detail()
    {
        var threatPath = Path.Combine(UserProfile, "AppData", "Temp", "evil.exe");
        var detail = ScanLogManager.FormatScanDetail(new optiCombat.Models.ScanResult
        {
            Type = optiCombat.Models.ScanType.QuickScan,
            TargetPath = threatPath,
            StartedAt = DateTime.Now,
            FinishedAt = DateTime.Now,
            FilesScanned = 10,
            Status = optiCombat.Models.ScanStatus.Completed,
            Threats =
            {
                new optiCombat.Models.ThreatInfo
                {
                    FilePath = threatPath,
                    VirusName = "TestVirus",
                    DetectedBy = "ClamAV",
                },
            },
        });

        Assert.Contains("%UserProfile%", detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(UserProfile, detail, StringComparison.OrdinalIgnoreCase);
    }
}
