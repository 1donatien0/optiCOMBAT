using Moq;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class SignatureUpdatePolicyTests
{
    [Fact]
    public void ApplyAutoUpdateTimers_when_disabled_calls_disable_on_both_targets()
    {
        var freshclam = new Mock<ISignatureAutoUpdateTarget>(MockBehavior.Strict);
        var rules = new Mock<ISignatureAutoUpdateTarget>(MockBehavior.Strict);
        freshclam.Setup(f => f.DisableAutoUpdate());
        rules.Setup(r => r.DisableAutoUpdate());

        SignatureUpdatePolicy.ApplyAutoUpdateTimers(freshclam.Object, rules.Object, enabled: false, new DefaultUserPreferencesAccessor());

        freshclam.Verify(f => f.DisableAutoUpdate(), Times.Once);
        rules.Verify(r => r.DisableAutoUpdate(), Times.Once);
        freshclam.VerifyNoOtherCalls();
        rules.VerifyNoOtherCalls();
    }

    [Fact]
    public void ApplyAutoUpdateTimers_when_enabled_schedules_both_updaters()
    {
        var freshclam = new Mock<ISignatureAutoUpdateTarget>(MockBehavior.Strict);
        var rules = new Mock<ISignatureAutoUpdateTarget>(MockBehavior.Strict);
        freshclam.Setup(f => f.EnableAutoUpdate(It.IsAny<TimeSpan?>()));
        rules.Setup(r => r.EnableAutoUpdate(It.IsAny<TimeSpan?>()));

        SignatureUpdatePolicy.ApplyAutoUpdateTimers(freshclam.Object, rules.Object, enabled: true, new DefaultUserPreferencesAccessor());

        freshclam.Verify(f => f.EnableAutoUpdate(It.IsAny<TimeSpan?>()), Times.Once);
        rules.Verify(r => r.EnableAutoUpdate(It.IsAny<TimeSpan?>()), Times.Once);
    }
}
