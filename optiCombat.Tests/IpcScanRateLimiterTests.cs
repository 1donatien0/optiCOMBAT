using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class IpcScanRateLimiterTests
{
  [Fact]
  public void TryEnter_respects_max_concurrent()
  {
    var limiter = new IpcScanRateLimiter(maxPerMinute: 1000, maxConcurrent: 2);
    Assert.True(limiter.TryEnter(out var a));
    Assert.True(limiter.TryEnter(out var b));
    Assert.False(limiter.TryEnter(out var rejected));
    Assert.Null(rejected);

    a!.Dispose();
    Assert.True(limiter.TryEnter(out var c));
    c!.Dispose();
    b!.Dispose();
  }

  [Fact]
  public void TryEnter_respects_max_per_minute_then_recovers()
  {
    var now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
    var limiter = new IpcScanRateLimiter(maxPerMinute: 2, maxConcurrent: 10, clock: () => now);

    Assert.True(limiter.TryEnter(out var a));
    a!.Dispose();
    Assert.True(limiter.TryEnter(out var b));
    b!.Dispose();
    Assert.False(limiter.TryEnter(out _));
    Assert.Equal(1, limiter.RejectedCount);

    now = now.AddMinutes(1);
    Assert.True(limiter.TryEnter(out var c));
    c!.Dispose();
  }

  [Fact]
  public void Lease_double_dispose_releases_once()
  {
    var limiter = new IpcScanRateLimiter(maxPerMinute: 1000, maxConcurrent: 1);
    Assert.True(limiter.TryEnter(out var a));
    a!.Dispose();
    a.Dispose();
    Assert.True(limiter.TryEnter(out var b));
    Assert.False(limiter.TryEnter(out _));
    b!.Dispose();
  }

  [Fact]
  public async Task Lease_ttl_releases_stuck_slot()
  {
    var limiter = new IpcScanRateLimiter(
        maxPerMinute: 1000,
        maxConcurrent: 1,
        maxLeaseHold: TimeSpan.FromMilliseconds(80));

    Assert.True(limiter.TryEnter(out var stuck));
    Assert.False(limiter.TryEnter(out _));

    await Task.Delay(200);
    Assert.True(limiter.TryEnter(out var next));
    stuck!.Dispose();
    next!.Dispose();
  }
}
