using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ScanThreatMergerTests
{
    [Fact]
    public void AggregateClamByPath_merges_multiple_virus_names_per_file()
    {
        var path = @"C:\infected\file.exe";
        var threats = new[]
        {
            new ThreatInfo { FilePath = path, VirusName = "Trojan.A", DetectedBy = "ClamAV" },
            new ThreatInfo { FilePath = path, VirusName = "Trojan.B", DetectedBy = "ClamAV" },
        };

        var byPath = ScanThreatMerger.AggregateClamByPath(threats);

        Assert.Single(byPath);
        Assert.Contains("Trojan.A", byPath[path].VirusName);
        Assert.Contains("Trojan.B", byPath[path].VirusName);
    }

    [Fact]
    public void Merge_combines_clam_and_yara_on_same_path()
    {
        var path = @"C:\x\mal.dll";
        var clam = new ScanResult
        {
            Type = ScanType.File,
            TargetPath = path,
            Status = ScanStatus.Completed,
            Threats =
            {
                new ThreatInfo { FilePath = path, VirusName = "Win.Malware", DetectedBy = "ClamAV" }
            }
        };
        var yara = new ScanResult
        {
            Type = ScanType.File,
            TargetPath = path,
            Status = ScanStatus.Completed,
            Threats =
            {
                new ThreatInfo { FilePath = path, VirusName = "Suspicious_DLL", DetectedBy = "YARA" }
            }
        };

        var merged = ScanThreatMerger.Merge(ScanType.File, path, clam, yara);

        Assert.Single(merged.Threats);
        Assert.Equal("ClamAV+YARA", merged.Threats[0].DetectedBy);
        Assert.Contains("Win.Malware", merged.Threats[0].VirusName);
        Assert.Contains("YARA:Suspicious_DLL", merged.Threats[0].VirusName);
    }

    [Fact]
    public void Merge_aggregates_multiple_yara_rules_on_same_path_without_clam()
    {
        var path = @"C:\x\a.bin";
        var yara = new ScanResult
        {
            Type = ScanType.File,
            TargetPath = path,
            Status = ScanStatus.Completed,
            Threats =
            {
                new ThreatInfo { FilePath = path, VirusName = "Rule_A", DetectedBy = "YARA" },
                new ThreatInfo { FilePath = path, VirusName = "Rule_B", DetectedBy = "YARA" },
            }
        };
        var clam = new ScanResult
        {
            Type = ScanType.File,
            TargetPath = path,
            Status = ScanStatus.Completed,
        };

        var merged = ScanThreatMerger.Merge(ScanType.File, path, clam, yara);

        Assert.Single(merged.Threats);
        Assert.Equal("YARA", merged.Threats[0].DetectedBy);
        Assert.Contains("Rule_A", merged.Threats[0].VirusName);
        Assert.Contains("Rule_B", merged.Threats[0].VirusName);
    }

    [Fact]
    public void Merge_files_scanned_is_single_counter_not_sum_of_engines()
    {
        var clam = new ScanResult { FilesScanned = 10_000, TotalBytesScanned = 5_000_000 };
        var yara = new ScanResult { FilesScanned = 9_500 };

        var merged = ScanThreatMerger.Merge(ScanType.Folder, @"C:\", clam, yara);

        Assert.Equal(10_000, merged.FilesScanned);
        Assert.Equal(5_000_000, merged.TotalBytesScanned);
    }
}
