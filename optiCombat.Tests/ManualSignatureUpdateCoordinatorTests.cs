using optiCombat.Coordinators;
using optiCombat.Services;
using optiCombat.Strings;

namespace optiCombat.Tests;

public sealed class ManualSignatureUpdateCoordinatorTests
{
    [Fact]
    public async Task RunAsync_second_call_while_locked_sets_already_running_status()
    {
        var runner = new SignatureUpdateUiRunner();
        Assert.True(runner.TryEnterUpdate());

        string? status = null;

        try
        {
            await ManualSignatureUpdateCoordinator.RunAsync(new ManualSignatureUpdateCoordinator.Host
            {
                Runner = runner,
                Freshclam = null!,
                Rules = null!,
                SignatureStatus = null!,
                SetStatus = (text, _, _, _) => status = text,
                RefreshLiveFooter = () => { },
                RefreshSignaturesDisplayAsync = _ => Task.CompletedTask,
            });
        }
        finally
        {
            runner.ReleaseUpdate();
        }

        Assert.Equal(OpticombatStrings.StatusUpdates.SignaturesUpdateAlreadyRunning, status);
    }
}
