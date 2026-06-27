using optiCombat.Coordinators;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class SignatureRefreshCoordinatorTests
{
    [Fact]
    public async Task ScheduleRefreshAfterUpdate_invalidates_cache_and_refreshes_ui()
    {
        var freshclam = new FreshclamUpdater();
        var rules = new YaraForgeUpdater();
        var yara = new YaraEngine();
        var status = new SignatureStatusService(freshclam, rules, yara);
        var refreshCalls = 0;
        var footerCalls = 0;

        var coordinator = new SignatureRefreshCoordinator(
            freshclam,
            rules,
            status,
            (_, _) => { },
            (_, _) => { },
            async _ =>
            {
                refreshCalls++;
                await Task.CompletedTask;
            },
            () => footerCalls++,
            work => _ = work());

        coordinator.ScheduleRefreshAfterUpdateForTests();

        Assert.Equal(1, refreshCalls);
        Assert.Equal(1, footerCalls);
    }

    [Fact]
    public void Attach_and_detach_do_not_throw()
    {
        var freshclam = new FreshclamUpdater();
        var rules = new YaraForgeUpdater();
        var yara = new YaraEngine();
        var status = new SignatureStatusService(freshclam, rules, yara);

        var coordinator = new SignatureRefreshCoordinator(
            freshclam,
            rules,
            status,
            (_, _) => { },
            (_, _) => { },
            _ => Task.CompletedTask,
            () => { },
            _ => { });

        coordinator.Attach();
        coordinator.Detach();
    }
}
