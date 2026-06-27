using optiCombat.Models;
using optiCombat.Platform;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ProtectionScanGatewayTests
{
    [Fact]
    public void MapIpcResponse_threat_maps_engine()
    {
        var result = ProtectionScanGateway.MapIpcResponse(
            @"C:\temp\eicar.com",
            ProtectionPipeResponse.Threat("EICAR_Test", "optiCombat"));

        Assert.Single(result.Threats);
        Assert.Equal("optiCombat", result.Threats[0].DetectedBy);
        Assert.Equal("EICAR_Test", result.Threats[0].VirusName);
    }

    [Fact]
    public async Task ScanFileAsync_falls_back_to_orchestrator_when_ipc_unavailable()
    {
        var clam = new ThreatClamBackend();
        var orch = new ScanOrchestrator(clam, new FakeYaraBackend());
        var gateway = new ProtectionScanGateway(orch);
        var file = Path.GetTempFileName();
        try
        {
            var result = await gateway.ScanFileAsync(file);
            Assert.Equal(1, clam.ScanFileCalls);
            Assert.NotNull(result);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public async Task ScanFileAsync_service_host_skips_ipc_even_when_reachable()
    {
        ProtectionScanGateway.IsServiceHostProcess = true;
        try
        {
            var clam = new ThreatClamBackend();
            var orch = new ScanOrchestrator(clam, new FakeYaraBackend());
            var gateway = new ProtectionScanGateway(orch);
            var file = Path.GetTempFileName();
            try
            {
                await gateway.ScanFileAsync(file);
                Assert.Equal(1, clam.ScanFileCalls);
            }
            finally
            {
                File.Delete(file);
            }
        }
        finally
        {
            ProtectionScanGateway.IsServiceHostProcess = false;
        }
    }

    private sealed class ThreatClamBackend : IClamAvOrchestratorBackend
    {
        public int ScanFileCalls { get; private set; }
        public bool IsClamAvInstalled() => true;
        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            ScanFileCalls++;
            return Task.FromResult(new ScanResult
            {
                Type = ScanType.File,
                TargetPath = filePath,
                Status = ScanStatus.Completed,
                Threats = [new ThreatInfo { FilePath = filePath, VirusName = "ShouldNotRun", DetectedBy = "ClamAV" }],
            });
        }
        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = folderPath, Status = ScanStatus.Completed });
        public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = targetPath, Status = ScanStatus.Completed });
    }

    private sealed class FakeYaraBackend : IYaraOrchestratorBackend
    {
        public bool IsAvailable => true;
        public int RulesCount => 1;
        public Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default) =>
            Task.FromResult(new List<YaraMatch>());
        public Task<List<YaraMatch>> ScanFolderAsync(string folderPath, IProgress<string>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new List<YaraMatch>());
        public Task<List<YaraMatch>> ScanFilesAsync(IReadOnlyList<string> files, IProgress<string>? progress = null, CancellationToken ct = default) =>
            Task.FromResult(new List<YaraMatch>());
    }
}
