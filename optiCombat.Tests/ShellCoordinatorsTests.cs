using Moq;
using optiCombat.Coordinators;
using optiCombat.Models;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ShellSectionsTests
{
  [Theory]
  [InlineData("overview", "Nav_Home")]
  [InlineData("clean", "Nav_Clean")]
  [InlineData("antivirus", "Nav_Antivirus")]
  [InlineData("history", "Nav_History")]
  [InlineData("options", "Nav_Options")]
  [InlineData("inconnu", "Nav_Home")]
  [InlineData(null, "Nav_Home")]
  public void NavLabelKey_maps_every_section(string? tag, string expected) =>
    Assert.Equal(expected, ShellSections.NavLabelKey(tag));

  [Fact]
  public void Normalize_falls_back_to_overview()
  {
    Assert.Equal(ShellSections.Overview, ShellSections.Normalize("???"));
    Assert.Equal(ShellSections.History, ShellSections.Normalize("history"));
  }
}

public sealed class NavigationRefreshCoordinatorTests
{
  private sealed class Calls
  {
    public int Overview, Antivirus, History;
  }

  private static NavigationRefreshCoordinator.Host HostFor(Calls c) => new()
  {
    RefreshOverviewAsync = () => { c.Overview++; return Task.CompletedTask; },
    RefreshAntivirusAsync = () => { c.Antivirus++; return Task.CompletedTask; },
    RefreshHistory = () => c.History++,
  };

  [Theory]
  [InlineData("overview", 1, 0, 0)]
  [InlineData("antivirus", 0, 1, 0)]
  [InlineData("history", 0, 0, 1)]
  [InlineData("clean", 0, 0, 0)]
  [InlineData("options", 0, 0, 0)]
  [InlineData("inconnu", 1, 0, 0)]
  public async Task Refreshes_only_the_displayed_section(string tag, int overview, int antivirus, int history)
  {
    var c = new Calls();
    await NavigationRefreshCoordinator.ApplyAsync(tag, HostFor(c));
    Assert.Equal((overview, antivirus, history), (c.Overview, c.Antivirus, c.History));
  }

  [Fact]
  public async Task Refresh_failure_is_swallowed()
  {
    var host = new NavigationRefreshCoordinator.Host
    {
      RefreshAntivirusAsync = () => throw new InvalidOperationException("boom"),
    };
    await NavigationRefreshCoordinator.ApplyAsync("antivirus", host);
  }
}

[Collection("Localization")]
public sealed class UsbScanStatusCoordinatorTests
{
  private static RemovableDriveScanStatusEventArgs Args(RemovableDriveScanPhase phase, int threats = 0) =>
    new(phase, @"E:\", "CLE_USB", threats, 42);

  [Fact]
  public void Started_is_neutral_and_mentions_drive()
  {
    var s = UsbScanStatusCoordinator.Describe(Args(RemovableDriveScanPhase.Started));
    Assert.False(s.IsError);
    Assert.False(s.IsWarning);
    Assert.Contains("CLE_USB", s.Text, StringComparison.Ordinal);
  }

  [Fact]
  public void Failed_is_an_error()
  {
    var s = UsbScanStatusCoordinator.Describe(Args(RemovableDriveScanPhase.Failed));
    Assert.True(s.IsError);
  }

  [Fact]
  public void Completed_with_threats_is_a_warning()
  {
    Assert.True(UsbScanStatusCoordinator.Describe(Args(RemovableDriveScanPhase.Completed, threats: 2)).IsWarning);
    Assert.False(UsbScanStatusCoordinator.Describe(Args(RemovableDriveScanPhase.Completed)).IsWarning);
  }
}

public sealed class AntivirusActionResultCoordinatorTests
{
  [Fact]
  public void Failure_only_sets_status()
  {
    string? status = null;
    var refreshes = 0;
    AntivirusActionResultCoordinator.Handle(
      new ActionResult { Success = false, Message = "ko", IsError = true },
      new AntivirusActionResultCoordinator.Host
      {
        SetStatus = (m, _, _) => status = m,
        RefreshQuarantineList = () => refreshes++,
        RefreshHistory = () => refreshes++,
        RefreshOverview = () => refreshes++,
      });
    Assert.Equal("ko", status);
    Assert.Equal(0, refreshes);
  }

  [Fact]
  public void Success_refreshes_quarantine_history_and_overview()
  {
    var calls = new List<string>();
    AntivirusActionResultCoordinator.Handle(
      new ActionResult { Success = true, Message = "ok" },
      new AntivirusActionResultCoordinator.Host
      {
        SetStatus = (m, _, _) => calls.Add("status:" + m),
        RefreshQuarantineList = () => calls.Add("quarantine"),
        RefreshHistory = () => calls.Add("history"),
        RefreshOverview = () => calls.Add("overview"),
      });
    Assert.Equal(new[] { "status:ok", "quarantine", "history", "overview" }, calls);
  }
}

[Collection("Localization")]
public sealed class RealTimeThreatCoordinatorTests
{
  [Fact]
  public void Threat_updates_badge_status_quarantine_and_overview()
  {
    var calls = new List<string>();
    RealTimeThreatCoordinator.Handle(
      new ThreatInfo { FilePath = @"C:\x.exe", VirusName = "Eicar-Test" },
      new RealTimeThreatCoordinator.Host
      {
        SetStatus = m => calls.Add(m.Contains("Eicar-Test", StringComparison.Ordinal) ? "status" : "status?"),
        RefreshProtectionBadge = () => calls.Add("badge"),
        RefreshQuarantineList = () => calls.Add("quarantine"),
        RefreshOverview = () => calls.Add("overview"),
      });
    Assert.Equal(new[] { "badge", "status", "quarantine", "overview" }, calls);
  }
}

public sealed class DestructiveActionConfirmationTests
{
  private static (Mock<IHistoryServices> history, ScanSession session, string file, string root) Setup()
  {
    var sessionId = Guid.NewGuid();
    var root = Path.Combine(Path.GetTempPath(), "oc_del_" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    var file = Path.Combine(root, "threat.bin");
    File.WriteAllBytes(file, [1, 2, 3]);

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
    return (history, logger.GetHistory().Single(), file, root);
  }

  [Fact]
  public void DeleteThreat_without_confirmation_keeps_the_file()
  {
    var (history, session, file, root) = Setup();
    try
    {
      var refreshes = 0;
      HistoryThreatRemediationCoordinator.DeleteThreat(
        history.Object, session, file, () => refreshes++, DeclineUserConfirmService.Instance);
      Assert.True(File.Exists(file));
      Assert.Equal(0, refreshes);
    }
    finally
    {
      try { Directory.Delete(root, recursive: true); } catch { }
    }
  }

  [Fact]
  public void DeleteThreat_after_confirmation_deletes_the_file()
  {
    var (history, session, file, root) = Setup();
    var confirm = new Mock<IUserConfirmService>();
    confirm.Setup(c => c.ConfirmYesNo(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>())).Returns(true);
    try
    {
      var refreshes = 0;
      HistoryThreatRemediationCoordinator.DeleteThreat(history.Object, session, file, () => refreshes++, confirm.Object);
      Assert.False(File.Exists(file));
      Assert.Equal(1, refreshes);
      confirm.Verify(c => c.ConfirmYesNo(It.Is<string>(m => m.Contains(file, StringComparison.Ordinal)), It.IsAny<string>(), true), Times.Once);
    }
    finally
    {
      try { Directory.Delete(root, recursive: true); } catch { }
    }
  }

  [Fact]
  public void SyncUiThreadScheduler_runs_inline()
  {
    var ran = 0;
    SyncUiThreadScheduler.Instance.Invoke(() => ran++);
    SyncUiThreadScheduler.Instance.BeginInvoke(() => ran++);
    Assert.Equal(2, ran);
  }
}
