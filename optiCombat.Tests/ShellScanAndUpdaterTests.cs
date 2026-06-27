using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using System.Text;

namespace optiCombat.Tests;

public sealed class ShellScanArgumentsTests
{
    [Fact]
    public void TryGetScanPath_parses_file_path()
    {
        Assert.True(ShellScanArguments.TryGetScanPath(new[] { "--scan", @"C:\temp\file.exe" }, out var path));
        Assert.Equal(@"C:\temp\file.exe", path);
    }

    [Fact]
    public void TryGetScanPath_parses_quoted_folder_path()
    {
        Assert.True(ShellScanArguments.TryGetScanPath(new[] { "--scan", "\"D:\\Mes Docs\"" }, out var path));
        Assert.Equal("D:\\Mes Docs", path);
    }

    [Fact]
    public void ResolveScanType_folder_when_directory_exists()
    {
        var dir = Path.Combine(Path.GetTempPath(), "opticombat_shell_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            Assert.Equal(ScanType.Folder, ShellScanArguments.ResolveScanType(dir));
            Assert.True(ShellScanArguments.IsValidScanTarget(dir));
        }
        finally
        {
            try { Directory.Delete(dir); } catch { }
        }
    }
}

public sealed class ShellScanRequestTests
{
    [Fact]
    public void Publish_then_TryConsume_roundtrip()
    {
        var path = Path.Combine(Path.GetTempPath(), "opticombat_publish_" + Guid.NewGuid().ToString("N"));
        ShellScanRequest.Publish(path);
        try
        {
            Assert.Equal(path, ShellScanRequest.TryConsume());
            Assert.Null(ShellScanRequest.TryConsume());
        }
        finally
        {
            var pending = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiCombat", "shell_scan_pending.txt");
            try { if (File.Exists(pending)) File.Delete(pending); } catch { }
        }
    }
}

public sealed class FreshclamUpdaterTests : IDisposable
{
    private readonly string _root;

    public FreshclamUpdaterTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "opticombat_fc_upd_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    [Fact]
    public void EnableAutoUpdate_toggles_timer_state()
    {
        var updater = new FreshclamUpdater(_root);
        Assert.False(updater.IsAutoUpdateEnabled);
        updater.EnableAutoUpdate(TimeSpan.FromHours(6));
        Assert.True(updater.IsAutoUpdateEnabled);
        updater.DisableAutoUpdate();
        Assert.False(updater.IsAutoUpdateEnabled);
    }

    [Fact]
    public void GetLastSignatureUpdateTime_uses_local_cvd_timestamp()
    {
        var db = Path.Combine(_root, "database");
        Directory.CreateDirectory(db);
        var cvd = Path.Combine(db, "daily.cvd");
        File.WriteAllText(cvd, "stub");
        var stamp = new DateTime(2025, 12, 1, 8, 30, 0, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(cvd, stamp);

        var updater = new FreshclamUpdater(_root);
        var t = updater.GetLastSignatureUpdateTime();

        Assert.NotNull(t);
        Assert.Equal(stamp.ToLocalTime(), t.Value, precision: TimeSpan.FromSeconds(1));
    }
}

public sealed class YaraForgeUpdaterTests : IDisposable
{
    private readonly string _rulesDir;

    public YaraForgeUpdaterTests()
    {
        _rulesDir = Path.Combine(Path.GetTempPath(), "opticombat_yara_upd_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_rulesDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_rulesDir, recursive: true); } catch { }
    }

    [Fact]
    public void LoadPersistedMeta_reads_version_and_date()
    {
        var meta = Path.Combine(_rulesDir, ".opticombat-yara-meta.txt");
        File.WriteAllText(meta, "2025.12-core\n2025-12-01T10:15:00.0000000Z");

        var updater = new YaraForgeUpdater(_rulesDir);

        Assert.Equal("2025.12-core", updater.GetRulesPackVersionDisplay());
        Assert.NotEqual("—", updater.GetRulesLastUpdateDisplay());
    }

    [Fact]
    public void EnableAutoUpdate_toggles_timer_state()
    {
        var updater = new YaraForgeUpdater(_rulesDir);
        updater.EnableAutoUpdate(TimeSpan.FromHours(12));
        Assert.True(updater.IsAutoUpdateEnabled);
        updater.DisableAutoUpdate();
        Assert.False(updater.IsAutoUpdateEnabled);
    }
}

public sealed class PdfReportGeneratorTests
{
    public PdfReportGeneratorTests() => LocalizationService.ApplyCulture("fr-FR");

    [Fact]
    public void GenerateReport_produces_valid_pdf_bytes()
    {
        var result = new ScanResult
        {
            Type = ScanType.Folder,
            TargetPath = Path.GetTempPath(),
            Status = ScanStatus.Completed,
            StartedAt = DateTime.Now.AddMinutes(-2),
            FinishedAt = DateTime.Now,
            FilesScanned = 12,
        };

        var bytes = new PdfReportGenerator().GenerateReport(result);

        Assert.NotEmpty(bytes);
        Assert.Equal("%PDF", Encoding.ASCII.GetString(bytes.AsSpan(0, 4)));
    }
}
