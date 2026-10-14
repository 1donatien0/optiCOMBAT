using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class CloudThreatIntelServiceTests
{
  [Fact]
  public async Task EnrichThreatAsync_missing_file_returns_null()
  {
    var svc = new CloudThreatIntelService(new FakeReputation());
    var threat = new ThreatInfo { FilePath = @"C:\nope\missing.bin", VirusName = "Test" };

    var result = await svc.EnrichThreatAsync(threat);

    Assert.Null(result);
  }

  [Fact]
  public async Task EnrichThreatAsync_delegates_to_reputation_service()
  {
    var dir = Path.Combine(Path.GetTempPath(), "opticombat_cloud_" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    var file = Path.Combine(dir, "sample.bin");
    await File.WriteAllBytesAsync(file, [1, 2, 3]);

  try
  {
    var fake = new FakeReputation { Summary = "42/70 malicious" };
    var svc = new CloudThreatIntelService(fake);
    var threat = new ThreatInfo { FilePath = file, VirusName = "Test" };

    var result = await svc.EnrichThreatAsync(threat);

    Assert.Equal("42/70 malicious", result);
    Assert.Equal(1, fake.CallCount);
  }
  finally
  {
    try { Directory.Delete(dir, recursive: true); } catch { }
  }
  }

  private sealed class FakeReputation : IThreatReputationService
  {
    public string Summary { get; init; } = "ok";
    public int CallCount { get; private set; }

    public Task<ThreatReputationService.ReputationResult> LookupFileAsync(string filePath, CancellationToken ct = default)
    {
      CallCount++;
      return Task.FromResult(new ThreatReputationService.ReputationResult
      {
        Success = true,
        Summary = Summary,
      });
    }
  }
}
