using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ScanOrchestratorTests
{
    [Fact]
    public void IsClamAvAvailable_reflects_injected_backend()
    {
        var clam = new FakeClamBackend { Installed = false };
        var orch = new ScanOrchestrator(clam, new FakeYaraBackend());

        Assert.False(orch.IsClamAvAvailable);

        clam.Installed = true;
        Assert.True(orch.IsClamAvAvailable);
    }

    [Fact]
    public void YaraRulesCount_reflects_injected_backend()
    {
        var yara = new FakeYaraBackend { IsAvailable = true, RulesCount = 42 };
        var orch = new ScanOrchestrator(new FakeClamBackend(), yara);

        Assert.True(orch.IsYaraAvailable);
        Assert.Equal(42, orch.YaraRulesCount);
    }

    [Fact]
    public async Task ScanFileAsync_excluded_file_is_skipped_without_calling_engines()
    {
        var dir = Path.Combine(Path.GetTempPath(), "opticombat_ut_excl_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "skip.me");
        await File.WriteAllTextAsync(file, "x");

        var clam = new FakeClamBackend();
        var yara = new FakeYaraBackend();

        try
        {
            ExclusionSettings.Current.AddFolder(dir);
            var orch = new ScanOrchestrator(clam, yara);
            var result = await orch.ScanFileAsync(file);

            Assert.Equal(ScanStatus.Completed, result.Status);
            Assert.Equal(ScanType.File, result.Type);
            Assert.Equal(file, result.TargetPath);
            Assert.Equal(1, result.FilesSkipped);
            Assert.Empty(result.Threats);
            Assert.Equal(0, clam.ScanFileCalls);
            Assert.Equal(0, yara.ScanFileCalls);
        }
        finally
        {
            ExclusionSettings.Current.RemoveFolder(dir);
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task ScanFolderAsync_under_install_root_skips_engines()
    {
        var installRoot = AppInstallPaths.GetInstallRoot();
        var clam = new FakeClamBackend();
        var yara = new FakeYaraBackend();
        var orch = new ScanOrchestrator(clam, yara);

        var result = await orch.ScanFolderAsync(installRoot);

        Assert.Equal(ScanStatus.Completed, result.Status);
        Assert.Equal(ScanType.Folder, result.Type);
        Assert.Equal(installRoot, result.TargetPath);
        Assert.Equal(1, result.FilesSkipped);
        Assert.Empty(result.Threats);
        Assert.Equal(0, clam.ScanFolderCalls);
        Assert.Equal(0, yara.ScanFolderCalls);
    }

    [Fact]
    public async Task ScanFileAsync_merges_clam_and_yara_threats()
    {
        var dir = Path.Combine(Path.GetTempPath(), "opticombat_ut_merge_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "sample.bin");
        await File.WriteAllTextAsync(file, "payload");

        var clam = new FakeClamBackend
        {
            ScanFileHandler = path => Task.FromResult(new ScanResult
            {
                Type = ScanType.File,
                TargetPath = path,
                Status = ScanStatus.Completed,
                FilesScanned = 1,
                Threats =
                {
                    new ThreatInfo { FilePath = path, VirusName = "Win.Test", DetectedBy = "ClamAV" }
                }
            })
        };
        var yara = new FakeYaraBackend
        {
            IsAvailable = true,
            ScanFileHandler = (path, _) => Task.FromResult(new List<YaraMatch>
            {
                new() { FilePath = path, RuleName = "Suspicious_Binary" }
            })
        };

        try
        {
            var orch = new ScanOrchestrator(clam, yara);
            var result = await orch.ScanFileAsync(file);

            Assert.Equal(ScanStatus.Completed, result.Status);
            Assert.Single(result.Threats);
            Assert.Equal("ClamAV+YARA", result.Threats[0].DetectedBy);
            Assert.Contains("Win.Test", result.Threats[0].VirusName);
            Assert.Contains("YARA:Suspicious_Binary", result.Threats[0].VirusName);
            Assert.Equal(1, clam.ScanFileCalls);
            Assert.Equal(1, yara.ScanFileCalls);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task ScanFileAsync_yara_unavailable_still_completes_from_clam()
    {
        var dir = Path.Combine(Path.GetTempPath(), "opticombat_ut_clam_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "clean.txt");
        await File.WriteAllTextAsync(file, "ok");

        var clam = new FakeClamBackend
        {
            ScanFileHandler = path => Task.FromResult(new ScanResult
            {
                Type = ScanType.File,
                TargetPath = path,
                Status = ScanStatus.Completed,
                FilesScanned = 1,
            })
        };
        var yara = new FakeYaraBackend { IsAvailable = false };

        try
        {
            var orch = new ScanOrchestrator(clam, yara);
            var result = await orch.ScanFileAsync(file);

            Assert.Equal(ScanStatus.Completed, result.Status);
            Assert.Empty(result.Threats);
            Assert.Equal(1, clam.ScanFileCalls);
            Assert.Equal(0, yara.ScanFileCalls);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task ScanFileListAsync_uses_file_list_pipeline()
    {
        var dir = Path.Combine(Path.GetTempPath(), "opticombat_ut_list_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var exe = Path.Combine(dir, "sample.exe");
        var txt = Path.Combine(dir, "readme.txt");
        await File.WriteAllTextAsync(exe, "bin");
        await File.WriteAllTextAsync(txt, "ok");

        var clam = new FakeClamBackend
        {
            ScanFileListHandler = (_, target) => Task.FromResult(new ScanResult
            {
                Type = ScanType.Folder,
                TargetPath = target,
                Status = ScanStatus.Completed,
                FilesScanned = 1,
            })
        };
        var yara = new FakeYaraBackend { IsAvailable = true };

        try
        {
            var orch = new ScanOrchestrator(clam, yara);
            var result = await orch.ScanFileListAsync(new[] { exe }, dir, ScanType.RemovableDrive);

            Assert.Equal(ScanStatus.Completed, result.Status);
            Assert.Equal(1, result.FilesScanned);
            Assert.Equal(1, clam.ScanFileListCalls);
            Assert.Equal(1, yara.ScanFilesCalls);
            Assert.Equal(0, clam.ScanFolderCalls);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    private sealed class FakeClamBackend : IClamAvOrchestratorBackend
    {
        public bool Installed { get; set; } = true;
        public int ScanFileCalls { get; private set; }
        public int ScanFolderCalls { get; private set; }
        public Func<string, Task<ScanResult>>? ScanFileHandler { get; init; }
        public Func<string, Task<ScanResult>>? ScanFolderHandler { get; init; }

        public bool IsClamAvInstalled() => Installed;

        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            ScanFileCalls++;
            if (ScanFileHandler != null)
                return ScanFileHandler(filePath);
            return Task.FromResult(new ScanResult
            {
                Type = ScanType.File,
                TargetPath = filePath,
                Status = ScanStatus.Completed,
            });
        }

        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            ScanFolderCalls++;
            if (ScanFolderHandler != null)
                return ScanFolderHandler(folderPath);
            return Task.FromResult(new ScanResult
            {
                Type = ScanType.Folder,
                TargetPath = folderPath,
                Status = ScanStatus.Completed,
            });
        }

        public int ScanFileListCalls { get; private set; }
        public Func<IReadOnlyList<string>, string, Task<ScanResult>>? ScanFileListHandler { get; init; }

        public Task<ScanResult> ScanFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            ScanFileListCalls++;
            if (ScanFileListHandler != null)
                return ScanFileListHandler(files, targetPath);
            return Task.FromResult(new ScanResult
            {
                Type = ScanType.Folder,
                TargetPath = targetPath,
                Status = ScanStatus.Completed,
                FilesScanned = files.Count,
            });
        }
    }

    private sealed class FakeYaraBackend : IYaraOrchestratorBackend
    {
        public bool IsAvailable { get; init; }
        public int RulesCount { get; init; }
        public int ScanFileCalls { get; private set; }
        public int ScanFolderCalls { get; private set; }
        public Func<string, CancellationToken, Task<List<YaraMatch>>>? ScanFileHandler { get; init; }

        public Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default)
        {
            ScanFileCalls++;
            if (ScanFileHandler != null)
                return ScanFileHandler(filePath, ct);
            return Task.FromResult(new List<YaraMatch>());
        }

        public Task<List<YaraMatch>> ScanFolderAsync(string folderPath, IProgress<string>? progress = null, CancellationToken ct = default)
        {
            ScanFolderCalls++;
            return Task.FromResult(new List<YaraMatch>());
        }

        public int ScanFilesCalls { get; private set; }
        public Func<IReadOnlyList<string>, CancellationToken, Task<List<YaraMatch>>>? ScanFilesHandler { get; init; }

        public Task<List<YaraMatch>> ScanFilesAsync(
            IReadOnlyList<string> files,
            IProgress<string>? progress = null,
            CancellationToken ct = default)
        {
            ScanFilesCalls++;
            if (ScanFilesHandler != null)
                return ScanFilesHandler(files, ct);
            return Task.FromResult(new List<YaraMatch>());
        }
    }
}
