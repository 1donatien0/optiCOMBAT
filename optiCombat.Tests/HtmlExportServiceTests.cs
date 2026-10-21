using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

[Collection(nameof(UserPreferencesStorageTests))]
public sealed class HtmlExportServiceTests : IDisposable
{
    private readonly string _root;

    public HtmlExportServiceTests()
    {
        LocalizationService.ApplyCulture("fr-FR");
        _root = Path.Combine(Path.GetTempPath(), "opticombat_html_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
        LocalizationService.ApplyCulture("fr-FR");
    }

    [Fact]
    public void ExportFullReport_empty_history_writes_placeholder()
    {
        var path = Path.Combine(_root, "empty.html");
        new HtmlExportService().ExportFullReport(
            Array.Empty<ScanSession>(),
            Array.Empty<ThreatInfo>(),
            Array.Empty<QuarantineEntry>(),
            new UserPreferences { TotalScansCount = 0 },
            path);

        var html = File.ReadAllText(path);
        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains(LocalizationService.GetString("Export_Html_NoScans"), html);
    }

    [Fact]
    public void ExportFullReport_includes_scans_threats_quarantine_and_recent_targets()
    {
        var path = Path.Combine(_root, "full.html");
        var prefs = new UserPreferences
        {
            TotalScansCount = 12,
            RecentTargets =
            {
                new RecentScanTarget
                {
                    Path = @"C:\Users\sample",
                    ScanType = ScanType.QuickScan,
                    LastUsed = DateTime.Now,
                },
            },
        };

        new HtmlExportService().ExportFullReport(
            new[]
            {
                new ScanSession
                {
                    SessionId = Guid.NewGuid(),
                    StartedAt = DateTime.Now.AddMinutes(-10),
                    FinishedAt = DateTime.Now.AddMinutes(-9),
                    ScanTypeValue = ScanType.QuickScan,
                    FilesScanned = 4,
                    ThreatsFound = 0,
                },
                new ScanSession
                {
                    SessionId = Guid.NewGuid(),
                    StartedAt = DateTime.Now.AddMinutes(-5),
                    FinishedAt = DateTime.Now.AddMinutes(-4),
                    ScanTypeValue = ScanType.FullScan,
                    FilesScanned = 9,
                    ThreatsFound = 2,
                },
            },
            new[] { ThreatInfo.FromClamAv(@"C:\Users\sample\bad.exe", "Win.Test", 32) },
            new[]
            {
                new QuarantineEntry
                {
                    Id = "q1",
                    OriginalPath = @"C:\Users\sample\bad.exe",
                    VirusName = "Win.Test",
                    QuarantinedAt = DateTime.Now,
                    OriginalSize = 32,
                },
            },
            prefs,
            path);

        var html = File.ReadAllText(path);
        Assert.Contains("badge-ok", html);
        Assert.Contains("badge-err", html);
        Assert.Contains("Win.Test", html);
        Assert.Contains("bad.exe", html);
        Assert.Contains(LocalizationService.GetString("Export_Html_ActiveThreats"), html);
        Assert.Contains(LocalizationService.GetString("Export_Html_Quarantine"), html);
        Assert.Contains(LocalizationService.GetString("Export_Html_RecentTargets"), html);
    }
}
