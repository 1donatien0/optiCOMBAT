using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Services.OptiCombat;

namespace optiCombat.Tests;

/// <summary>
/// Preuve d'intégration bout en bout : EICAR détecté via opticombat.dll (cœur Rust),
/// pas via le repli ClamAV+YARA managé. Ignore si la DLL native n'est pas déployée.
/// </summary>
public sealed class OptiCombatEicarIntegrationTests : IDisposable
{
    private const string EicarStandard =
        @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    private readonly string _samplePath;

    public OptiCombatEicarIntegrationTests()
    {
        _samplePath = Path.Combine(
            Path.GetTempPath(),
            "opticombat_eicar_" + Guid.NewGuid().ToString("N") + ".com");
        File.WriteAllText(_samplePath, EicarStandard);
    }

    public void Dispose()
    {
        try { File.Delete(_samplePath); } catch { /* best effort */ }
    }

    [Fact]
    public async Task OptiCombatScanEngine_detects_EICAR_via_native_dll()
    {
        var engine = new OptiCombatScanEngine();
        if (!engine.IsAvailable)
            return;

        var result = await engine.ScanFileAsync(_samplePath);

        Assert.Equal(ScanStatus.Completed, result.Status);
        Assert.NotEmpty(result.Threats);
        Assert.All(result.Threats, t =>
            Assert.NotEqual("ClamAV+YARA", t.DetectedBy));
        Assert.Contains(
            result.Threats,
            t => t.DetectedBy is "optiCombat" or "ClamAV" or "YARA");
    }

    [Fact]
    public async Task ScanOrchestrator_detects_EICAR_via_native_when_dll_present()
    {
        var clam = new FakeClamBackend();
        var yara = new FakeYaraBackend();
        var native = new OptiCombatScanEngine();
        if (!native.IsAvailable)
            return;

        var orch = new ScanOrchestrator(clam, yara, optiCombat: native);

        Assert.True(orch.IsOptiCombatAvailable);

        var result = await orch.ScanFileAsync(_samplePath);

        Assert.NotEmpty(result.Threats);
        Assert.Equal(0, clam.ScanFileCalls);
        Assert.Equal(0, yara.ScanFileCalls);
    }

    /// <summary>Backends factices locaux (orchestrateur ne doit pas les appeler si Rust actif).</summary>
    private sealed class FakeClamBackend : IClamAvOrchestratorBackend
    {
        public int ScanFileCalls { get; private set; }
        public bool IsClamAvInstalled() => true;
        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
        {
            ScanFileCalls++;
            return Task.FromResult(new ScanResult { Type = ScanType.File, TargetPath = filePath, Status = ScanStatus.Completed });
        }
        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = folderPath, Status = ScanStatus.Completed });
        public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
            => Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = targetPath, Status = ScanStatus.Completed });
    }

    private sealed class FakeYaraBackend : IYaraOrchestratorBackend
    {
        public bool IsAvailable => true;
        public int RulesCount => 1;
        public int ScanFileCalls { get; private set; }
        public Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default)
        {
            ScanFileCalls++;
            return Task.FromResult(new List<YaraMatch>());
        }
        public Task<List<YaraMatch>> ScanFolderAsync(string folderPath, IProgress<string>? progress = null, CancellationToken ct = default)
            => Task.FromResult(new List<YaraMatch>());
        public Task<List<YaraMatch>> ScanFilesAsync(IReadOnlyList<string> files, IProgress<string>? progress = null, CancellationToken ct = default)
            => Task.FromResult(new List<YaraMatch>());
    }
}
