using Moq;
using optiCombat.Coordinators;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Views;

namespace optiCombat.Tests;

public sealed class OverviewRefreshCoordinatorTests
{
    [Fact]
    public void RefreshProtectionAndRecommendations_updates_protected_headline_when_engines_ready()
    {
        var panel = new Mock<IOverviewPanel>(MockBehavior.Strict);
        panel.Setup(p => p.UpdateProtectionHeadline(true, null));
        panel.Setup(p => p.UpdateRecommendations(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<bool>()));
        panel.Setup(p => p.UpdateSecurityPosture(It.IsAny<SecurityPostureReport>()));
        panel.Setup(p => p.UpdatePlatformProtectionStatus(It.IsAny<PlatformProtectionStatusReport>()));

        var posture = new Mock<ISecurityPostureService>(MockBehavior.Strict);
        posture.Setup(s => s.Evaluate(It.IsAny<SecurityPostureContext>()))
            .Returns(new SecurityPostureReport { Score = 80 });

        var ctx = new OverviewRefreshContext(
            panel.Object,
            ClamInstalled: true,
            YaraRulesCount: 12,
            YaraAvailable: true,
            CleanHistory: Array.Empty<CleanSession>(),
            ScanHistory: Array.Empty<ScanSession>(),
            LastFreshclamUpdate: DateTime.UtcNow,
            RealTimeProtectionEnabled: true,
            RealTimeProtectionRunning: true,
            SignatureAutoUpdateEnabled: true,
            SecurityPosture: posture.Object);

        OverviewRefreshCoordinator.RefreshProtectionAndRecommendations(ctx);

        panel.Verify(p => p.UpdateProtectionHeadline(true, null), Times.Once);
        posture.Verify(s => s.Evaluate(It.IsAny<SecurityPostureContext>()), Times.Once);
    }
}
