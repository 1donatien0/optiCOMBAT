using Moq;
using optiCombat.Coordinators;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Strings;
using optiCombat.Tests.TestSupport;
using optiCombat.Views;

namespace optiCombat.Tests;

[Collection("OpticombatPrefs")]
public sealed class ShellRoutingIsolatedTests : IDisposable
{
    private readonly IsolatedServices _env = new();
    private readonly List<string> _calls = new();
    private readonly List<string> _navigated = new();
    private readonly List<(string Message, bool Error, bool Warning)> _status = new();

    public void Dispose() => _env.Dispose();

    private ToastActivationCoordinator.Host Host()
    {
        var nav = new Mock<INavigationService>();
        nav.Setup(n => n.NavigateTo(It.IsAny<string>())).Callback<string>(_navigated.Add);
        return new ToastActivationCoordinator.Host
        {
            Services = _env.Container,
            Navigation = nav.Object,
            ShowWindow = () => _calls.Add("show"),
            SetStatus = (m, e, w) => _status.Add((m, e, w)),
            RefreshQuarantineList = () => _calls.Add("refreshQuarantine"),
            RefreshAntivirusView = () => _calls.Add("refreshAv"),
            SelectAntivirusScanTab = () => _calls.Add("scanTab"),
            SelectAntivirusQuarantineTab = () => _calls.Add("quarantineTab"),
            SelectAntivirusSignaturesTab = () => _calls.Add("signaturesTab"),
            TriggerManualSignatureUpdate = () => _calls.Add("update"),
        };
    }

    private void Toast(string action, string? file = null) =>
        ToastActivationCoordinator.Handle(new ToastActivationEventArgs(action, file, "Win.Test"), Host());

    [Fact]
    public void Quarantine_toast_moves_file_and_opens_antivirus()
    {
        var file = _env.CreateFile("toast.exe");

        Toast("QUARANTINE", file);

        Assert.False(File.Exists(file));
        Assert.Equal(1, _env.Container.Quarantine.Count);
        Assert.Contains("refreshQuarantine", _calls);
        Assert.Contains("show", _calls);
        Assert.Equal(OpticombatStrings.PanelIds.Antivirus, Assert.Single(_navigated));
        Assert.Single(_status);
    }

    [Fact]
    public void Quarantine_toast_without_file_only_opens_antivirus()
    {
        Toast("quarantine");

        Assert.Empty(_status);
        Assert.Equal(new[] { "show" }, _calls);
    }

    [Fact]
    public void Ignore_toast_excludes_file()
    {
        var file = _env.CreateFile("ign.exe");

        Toast("ignore", file);
        Toast("ignore");

        Assert.True(_env.Exclusions.IsFileExcluded(file));
        Assert.Single(_status);
        Assert.Contains("refreshAv", _calls);
    }

    [Theory]
    [InlineData("openav", "scanTab")]
    [InlineData("open", "scanTab")]
    [InlineData("threat", "scanTab")]
    [InlineData("showquarantine", "quarantineTab")]
    [InlineData("update", "update")]
    public void Navigation_toasts_open_expected_tab(string action, string expectedCall)
    {
        Toast(action);

        Assert.Contains("show", _calls);
        Assert.Contains(expectedCall, _calls);
        Assert.Equal(OpticombatStrings.PanelIds.Antivirus, Assert.Single(_navigated));
    }

    [Fact]
    public void History_toasts_and_unknown_actions()
    {
        Toast("scanthreats");
        Toast("inconnu");

        Assert.Equal(OpticombatStrings.PanelIds.History, Assert.Single(_navigated));
    }

    [Fact]
    public async Task Overview_refresh_feeds_every_panel_from_container()
    {
        var overview = new Mock<IOverviewPanel>();
        var antivirus = new Mock<IAntivirusSignaturesPanel>();
        SignatureStatusSnapshot? applied = null;
        var after = false;
        _env.Container.Logger.SaveCleanSession(new CleanSession { StartedAt = DateTime.Now.AddDays(-2), FinishedAt = DateTime.Now });

        var ctx = OverviewRefreshContextBuilder.FromContainer(overview.Object, _env.Container);
        OverviewRefreshCoordinator.RefreshProtectionAndRecommendations(ctx);
        await OverviewRefreshCoordinator.RefreshSignaturesAsync(
            new SignaturesRefreshContext(
                _env.Container.SignatureStatus,
                overview.Object,
                antivirus.Object,
                s => applied = s,
                () => after = true),
            forceRefresh: true);

        Assert.False(ctx.RealTimeProtectionEnabled);
        Assert.Single(ctx.CleanHistory);
        overview.Verify(p => p.UpdateProtectionHeadline(It.IsAny<bool>(), It.IsAny<string?>()), Times.Once);
        overview.Verify(p => p.UpdateSecurityPosture(It.IsAny<SecurityPostureReport>()), Times.Once);
        overview.Verify(p => p.UpdateSignaturesSummary(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Once);
        antivirus.Verify(p => p.UpdateSignaturesPanel(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Once);
        Assert.NotNull(applied);
        Assert.True(after);
    }

    [Fact]
    public void Threat_repair_quarantines_or_reports_failure()
    {
        var file = _env.CreateFile("repair.exe");

        var ok = ThreatRepairService.TryRemediate(ThreatInfo.FromClamAv(file, "Win.Repair", 5), _env.Container.Quarantine, _env.PrefsAccessor);
        var ko = ThreatRepairService.TryRemediate(
            ThreatInfo.FromClamAv(Path.Combine(_env.Root, "absent.exe"), "Win.Repair"), _env.Container.Quarantine, _env.PrefsAccessor);

        Assert.True(ok.Success);
        Assert.False(string.IsNullOrWhiteSpace(ok.Message));
        Assert.False(ko.Success);
        Assert.False(ko.UsedDefenderFallback);
    }
}
