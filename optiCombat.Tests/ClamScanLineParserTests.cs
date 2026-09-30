using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ClamScanLineParserTests
{
    [Fact]
    public void ProcessLine_FOUND_adds_threat()
    {
        var result = new ScanResult();
        ClamScanLineParser.ProcessLine(@"C:\temp\eicar.com: Eicar-Test-Signature FOUND", result, null);

        Assert.Single(result.Threats);
        Assert.Equal("Eicar-Test-Signature", result.Threats[0].VirusName);
        Assert.Equal("ClamAV", result.Threats[0].DetectedBy);
    }

    [Fact]
    public void ProcessLine_OK_increments_files_scanned()
    {
        var result = new ScanResult();
        ClamScanLineParser.ProcessLine(@"C:\temp\clean.txt: OK", result, null);

        Assert.Equal(1, result.FilesScanned);
        Assert.Empty(result.Threats);
    }

    [Fact]
    public void ProcessLine_stats_updates_scanned_files()
    {
        var result = new ScanResult();
        ClamScanLineParser.ProcessLine("Scanned files: 42", result, null);

        Assert.Equal(42, result.FilesScanned);
    }

    [Fact]
    public void ProcessLine_data_scanned_parses_megabytes_with_decimals()
    {
        var result = new ScanResult();
        ClamScanLineParser.ProcessLine("Data scanned: 10.5 MB", result, null);

        Assert.Equal((long)(10.5 * 1024 * 1024), result.TotalBytesScanned);
    }

    [Fact]
    public void ProcessLine_OK_throttles_progress_after_500_files()
    {
        var reports = new List<int>();
        var progress = new Progress<ScanProgress>(p =>
        {
            if (p.Phase == ScanPhase.Scanning && p.FilesScanned > 0)
                reports.Add(p.FilesScanned);
        });

        var result = new ScanResult();
        for (var i = 1; i <= 1000; i++)
            ClamScanLineParser.ProcessLine($@"C:\f\file{i}.txt: OK", result, progress);

        Assert.Equal(1000, result.FilesScanned);
        Assert.True(reports.Count < 200, $"trop de rapports UI: {reports.Count}");
        Assert.Contains(500, reports);
        Assert.Contains(600, reports);
        Assert.Contains(1000, reports);
    }
}
