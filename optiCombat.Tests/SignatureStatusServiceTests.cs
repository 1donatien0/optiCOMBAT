using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class SignatureStatusServiceTests
{
    [Fact]
    public async Task GetSnapshotAsync_caches_version_labels_until_invalidate()
    {
        var clamCalls = 0;
        var service = new SignatureStatusService(
            () =>
            {
                clamCalls++;
                return Task.FromResult($"v{clamCalls}");
            },
            () => "when1",
            () => "ypack",
            () => "ywhen",
            () => 12,
            () => true,
            TimeSpan.FromMinutes(5));

        var first = await service.GetSnapshotAsync();
        var second = await service.GetSnapshotAsync();

        Assert.Equal("v1", first.ClamDatabaseVersion);
        Assert.Equal("v1", second.ClamDatabaseVersion);
        Assert.Equal(1, clamCalls);

        service.InvalidateCache();
        var third = await service.GetSnapshotAsync();

        Assert.Equal("v2", third.ClamDatabaseVersion);
        Assert.Equal(2, clamCalls);
    }

    [Fact]
    public async Task GetSnapshotAsync_forceRefresh_bypasses_cache()
    {
        var clamCalls = 0;
        var service = new SignatureStatusService(
            () => Task.FromResult($"v{++clamCalls}"),
            () => "—",
            () => "—",
            () => "—",
            () => 0,
            () => false,
            TimeSpan.FromMinutes(5));

        await service.GetSnapshotAsync();
        await service.GetSnapshotAsync(forceRefresh: true);

        Assert.Equal(2, clamCalls);
    }

    [Fact]
    public async Task GetSnapshotAsync_reads_yara_rules_count_on_every_call()
    {
        var rulesCount = 1;
        var service = new SignatureStatusService(
            () => Task.FromResult("1"),
            () => "—",
            () => "—",
            () => "—",
            () => rulesCount,
            () => true,
            TimeSpan.FromMinutes(5));

        var first = await service.GetSnapshotAsync();
        rulesCount = 99;
        var second = await service.GetSnapshotAsync();

        Assert.Equal(1, first.YaraRulesCount);
        Assert.Equal(99, second.YaraRulesCount);
    }
}
