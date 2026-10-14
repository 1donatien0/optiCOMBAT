using optiCombat.Models;
using optiCombat.Services;
using System.IO;

namespace optiCombat.Tests;

public sealed class RealTimeProtectionTests
{
  [Fact]
  public void Start_then_Stop_toggles_IsEnabled()
  {
    var orch = new ScanOrchestrator(new FakeClam(), new FakeYara());
    var q = new QuarantineManager(Path.Combine(Path.GetTempPath(), "opticombat_rtp_q_" + Guid.NewGuid().ToString("N")));
    var gateway = new ProtectionScanGateway(orch);
    var rtp = new RealTimeProtection(gateway, q, new NotificationService());

    Assert.False(rtp.IsEnabled);
    rtp.Start();
    Assert.True(rtp.IsEnabled);
    rtp.Start();
    Assert.True(rtp.IsEnabled);
    rtp.Stop();
    Assert.False(rtp.IsEnabled);
    rtp.Dispose();
  }

  [Fact]
  public void Dispose_can_be_called_twice()
  {
    var orch = new ScanOrchestrator(new FakeClam(), new FakeYara());
    var gateway = new ProtectionScanGateway(orch);
    var rtp = new RealTimeProtection(gateway, new QuarantineManager(), new NotificationService());
    rtp.Start();
    rtp.Dispose();
    rtp.Dispose();
    Assert.False(rtp.IsEnabled);
  }

  [Fact]
  public void Resume_below_zero_clamps_suspend_count()
  {
    var orch = new ScanOrchestrator(new FakeClam(), new FakeYara());
    var gateway = new ProtectionScanGateway(orch);
    var rtp = new RealTimeProtection(gateway, new QuarantineManager(), new NotificationService());

    rtp.Resume();
    rtp.Resume();
    Assert.False(rtp.IsPaused);
    rtp.Dispose();
  }

  [Fact]
  public void Suspend_Resume_controls_IsPaused()
  {
    var orch = new ScanOrchestrator(new FakeClam(), new FakeYara());
    var gateway = new ProtectionScanGateway(orch);
    var rtp = new RealTimeProtection(gateway, new QuarantineManager(), new NotificationService());

    Assert.False(rtp.IsPaused);
    rtp.Suspend();
    Assert.True(rtp.IsPaused);
    rtp.Suspend();
    Assert.True(rtp.IsPaused);
    rtp.Resume();
    Assert.True(rtp.IsPaused);
    rtp.Resume();
    Assert.False(rtp.IsPaused);
    rtp.Dispose();
  }

  [Fact]
  public async Task ScanFileAsync_raises_ThreatDetected_when_orchestrator_finds_threat()
  {
    var dir = Path.Combine(Path.GetTempPath(), "opticombat_rtp_threat_" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    var sample = Path.Combine(dir, "payload.exe");
    await File.WriteAllBytesAsync(sample, [0x4D, 0x5A]);

    var orch = new ScanOrchestrator(new ThreatClamBackend(), new FakeYara());
    var qDir = Path.Combine(dir, "q");
    var gateway = new ProtectionScanGateway(orch);
    var rtp = new RealTimeProtection(gateway, new QuarantineManager(qDir), new NotificationService());
    ThreatInfo? detected = null;
    rtp.ThreatDetected += (_, t) => detected = t;

    try
    {
      await InvokeScanFileAsync(rtp, sample, WatcherChangeTypes.Created);
      Assert.NotNull(detected);
      Assert.Equal(sample, detected!.FilePath);
      Assert.Equal("Test.Threat", detected.VirusName);
    }
    finally
    {
      rtp.Dispose();
      try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
    }
  }

  private static async Task InvokeScanFileAsync(
      RealTimeProtection rtp,
      string filePath,
      WatcherChangeTypes changeType)
  {
    var method = typeof(RealTimeProtection).GetMethod(
        "ScanFileAsync",
        System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
    Assert.NotNull(method);
    await (Task)method!.Invoke(rtp, [filePath, changeType])!;
  }

  private sealed class ThreatClamBackend : IClamAvOrchestratorBackend
  {
    public bool IsClamAvInstalled() => true;
    public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult
      {
        Type = ScanType.File,
        TargetPath = filePath,
        Status = ScanStatus.Completed,
        Threats = [new ThreatInfo { FilePath = filePath, VirusName = "Test.Threat", FileSize = 2 }],
      });
    public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = folderPath, Status = ScanStatus.Completed });
    public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = targetPath, Status = ScanStatus.Completed, FilesScanned = files.Count });
  }

  private sealed class FakeClam : IClamAvOrchestratorBackend
  {
    public bool IsClamAvInstalled() => true;
    public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.File, TargetPath = filePath, Status = ScanStatus.Completed });
    public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = folderPath, Status = ScanStatus.Completed });
    public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
      Task.FromResult(new ScanResult { Type = ScanType.Folder, TargetPath = targetPath, Status = ScanStatus.Completed, FilesScanned = files.Count });
  }

  private sealed class FakeYara : IYaraOrchestratorBackend
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
