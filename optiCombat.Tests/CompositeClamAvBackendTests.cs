using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class CompositeClamAvBackendTests
{
    [Fact]
    public async Task ScanFileAsync_uses_clamd_when_ready()
    {
        var clamd = new TrackingBackend("clamd");
        var clamscan = new TrackingBackend("clamscan");
        var composite = new CompositeClamAvBackend(_ => Task.FromResult(true), clamd, clamscan);

        await composite.ScanFileAsync(@"C:\temp\file.exe");

        Assert.Equal(1, clamd.FileCalls);
        Assert.Equal(0, clamscan.FileCalls);
        Assert.Equal("clamd", ClamdEngine.LastMode);
    }

    [Fact]
    public async Task ScanFileAsync_falls_back_when_clamd_not_ready()
    {
        var clamd = new TrackingBackend("clamd");
        var clamscan = new TrackingBackend("clamscan");
        var composite = new CompositeClamAvBackend(_ => Task.FromResult(false), clamd, clamscan);

        await composite.ScanFileAsync(@"C:\temp\file.exe");

        Assert.Equal(0, clamd.FileCalls);
        Assert.Equal(1, clamscan.FileCalls);
        Assert.Equal("clamscan", ClamdEngine.LastMode);
    }

    [Fact]
    public async Task ScanFileAsync_falls_back_when_clamd_throws()
    {
        var clamd = new ThrowingBackend();
        var clamscan = new TrackingBackend("clamscan");
        var composite = new CompositeClamAvBackend(_ => Task.FromResult(true), clamd, clamscan);

        await composite.ScanFileAsync(@"C:\temp\file.exe");

        Assert.Equal(1, clamscan.FileCalls);
        Assert.Equal("clamscan", ClamdEngine.LastMode);
    }

    private sealed class TrackingBackend : IClamAvOrchestratorBackend
    {
        private readonly string _label;

        public TrackingBackend(string label) => _label = label;
        public int FileCalls { get; private set; }

        public bool IsClamAvInstalled() => true;

        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            FileCalls++;
            ClamdEngine.LastMode = _label;
            return Task.FromResult(new ScanResult { Type = ScanType.File, TargetPath = filePath, Status = ScanStatus.Completed });
        }

        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = folderPath, Status = ScanStatus.Completed });

        public Task<ScanResult> ScanFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
        {
            ClamdEngine.LastMode = _label;
            return Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = targetPath, Status = ScanStatus.Completed, FilesScanned = files.Count });
        }
    }

    private sealed class ThrowingBackend : IClamAvOrchestratorBackend
    {
        public bool IsClamAvInstalled() => true;
        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => throw new InvalidOperationException("clamd down");
        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => throw new InvalidOperationException("clamd down");
        public Task<ScanResult> ScanFileListAsync(
            IReadOnlyList<string> files,
            string targetPath,
            IProgress<ScanProgress>? progress = null,
            CancellationToken ct = default)
            => throw new InvalidOperationException("clamd down");
    }
}
