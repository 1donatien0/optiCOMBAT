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

    [Theory]
    [InlineData(null, "optiCombat")]
    [InlineData("", "optiCombat")]
    [InlineData("clamav", "clamav")]
    [InlineData("MoteurInconnu", "MoteurInconnu")]
    public void MapIpcResponse_maps_known_empty_and_unknown_engines(string? engine, string expected)
    {
        var result = ProtectionScanGateway.MapIpcResponse(
            @"C:\temp\a.exe",
            ProtectionPipeResponse.Threat("Win.Test", engine));
        Assert.Equal(expected, Assert.Single(result.Threats).DetectedBy);
    }

    [Fact]
    public void MapIpcResponse_error_and_nameless_hit_carry_no_threat()
    {
        var failed = ProtectionScanGateway.MapIpcResponse(
            @"C:\temp\a.exe",
            ProtectionPipeResponse.Error("hors service"));
        Assert.Equal(ScanStatus.Error, failed.Status);
        Assert.Equal("hors service", failed.ErrorMessage);
        Assert.Empty(failed.Threats);

        var nameless = ProtectionScanGateway.MapIpcResponse(
            @"C:\temp\a.exe",
            new ProtectionPipeResponse { Ok = true, Clean = false, ThreatName = "  " });
        Assert.Equal(ScanStatus.Completed, nameless.Status);
        Assert.Empty(nameless.Threats);
    }

    [Fact]
    public async Task Disabled_platform_service_scans_locally_without_waiting_on_the_pipe()
    {
        // Régression : chaque scan RTP sondait le tube IPC (5 s de délai) même service désactivé.
        var clam = new ThreatClamBackend();
        var prefs = new TestSupport.FixedPreferencesAccessor(new UserPreferences { UsePlatformProtectionService = false });
        var gateway = new ProtectionScanGateway(new ScanOrchestrator(clam, new FakeYaraBackend()), prefs);
        var file = Path.GetTempFileName();
        try
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();
            for (var i = 0; i < 3; i++)
                await gateway.ScanFileAsync(file);
            watch.Stop();

            Assert.Equal(3, clam.ScanFileCalls);
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(3), $"scan local trop lent : {watch.Elapsed}");
        }
        finally
        {
            File.Delete(file);
        }
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
