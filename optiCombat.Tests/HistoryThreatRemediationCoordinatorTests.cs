using Moq;
using optiCombat.Coordinators;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.ViewModels;

namespace optiCombat.Tests;

public sealed class HistoryThreatRemediationCoordinatorTests
{
    [Fact]
    public void QuarantineThreat_removes_from_session_on_success()
    {
        var sessionId = Guid.NewGuid();
        var file = Path.Combine(Path.GetTempPath(), "hist_threat_" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(file, [1]);

        var root = Path.Combine(Path.GetTempPath(), "hist_q_" + Guid.NewGuid().ToString("N"));
        var q = new QuarantineManager(Path.Combine(root, "q"));
        var logger = new ScanLogManager(Path.Combine(root, "log"));
        logger.SaveScanResult(new ScanResult
        {
            SessionId = sessionId,
            Type = ScanType.File,
            TargetPath = file,
            Status = ScanStatus.Completed,
            Threats = [new ThreatInfo { FilePath = file, VirusName = "T" }],
        });

        var history = new Mock<IHistoryServices>();
        history.SetupGet(h => h.Quarantine).Returns(q);
        history.SetupGet(h => h.Logger).Returns(logger);
        history.SetupGet(h => h.Actions).Returns(new AntivirusActions(q));

        var vm = new HistoryViewModel(history.Object);
        var session = logger.GetHistory().Single();
        int refreshes = 0;

        try
        {
            HistoryThreatRemediationCoordinator.QuarantineThreat(history.Object, vm, session, file, () => refreshes++);
            Assert.Equal(1, refreshes);
            Assert.Empty(session.Threats);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }
}
