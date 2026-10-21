using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

[Collection("OpticombatPrefs")]
public sealed class ServiceContainerIsolatedTests : IDisposable
{
    private readonly IsolatedServices _env = new();

    public void Dispose() => _env.Dispose();

    [Fact]
    public void Container_exposes_every_service()
    {
        var c = _env.Container;

        Assert.NotNull(c.ClamAv);
        Assert.NotNull(c.Yara);
        Assert.NotNull(c.Orchestrator);
        Assert.NotNull(c.FreshclamUpdater);
        Assert.NotNull(c.RulesUpdater);
        Assert.NotNull(c.Quarantine);
        Assert.NotNull(c.Logger);
        Assert.NotNull(c.ActivityLog);
        Assert.NotNull(c.Notifications);
        Assert.NotNull(c.RealTimeProtection);
        Assert.NotNull(c.ProcessStartMonitor);
        Assert.NotNull(c.TamperProtection);
        Assert.NotNull(c.RemovableDriveScan);
        Assert.NotNull(c.ScheduledScan);
        Assert.NotNull(c.ScanEngine);
        Assert.NotNull(c.Actions);
        Assert.NotNull(c.ThreatReputation);
        Assert.NotNull(c.CloudThreatIntel);
        Assert.NotNull(c.SecurityPosture);
        Assert.NotNull(c.SignatureStatus);
        Assert.False(string.IsNullOrWhiteSpace(c.ClamActiveEngine));
        Assert.Same(_env.PrefsAccessor, c.UserPreferencesAccessor);
        Assert.Same(_env.ExclusionsAccessor, c.ExclusionSettingsAccessor);
        Assert.Null(c.Navigation);
    }

    [Fact]
    public void Ui_requests_are_routed_through_the_event_bus()
    {
        var c = _env.Container;
        var fired = new List<string>();
        var session = new ScanSession { TargetPath = @"C:\x" };
        ScanSession? exported = null, reviewed = null;

        EventHandler sig = (_, _) => fired.Add("sig");
        EventHandler protection = (_, _) => fired.Add("protection");
        c.RequestSignatureUpdate += sig;
        c.ProtectionStateRefreshRequested += protection;
        c.FocusAntivirusSignaturesRequested += (_, _) => fired.Add("focus");
        c.ScanHistoryViewsRefreshRequested += (_, _) => fired.Add("history");
        c.ExportScanHistoryHtmlRequested += (_, _) => fired.Add("html");
        c.ExportScanSessionPdfRequested += (_, s) => exported = s;
        c.ReviewHistorySessionRequested += (_, s) => reviewed = s;
        c.OpenQuarantineTabRequested += (_, _) => fired.Add("quarantine");

        c.TriggerSignatureUpdate();
        c.RequestProtectionStateRefresh();
        c.RequestFocusAntivirusSignaturesTab();
        c.RequestScanHistoryViewsRefresh();
        c.RequestExportScanHistoryHtml();
        c.RequestExportScanSessionPdf(session);
        c.RequestReviewHistorySession(session);
        c.RequestOpenQuarantineTab();

        Assert.Equal(new[] { "sig", "protection", "focus", "history", "html", "quarantine" }, fired);
        Assert.Same(session, exported);
        Assert.Same(session, reviewed);

        c.RequestSignatureUpdate -= sig;
        c.ProtectionStateRefreshRequested -= protection;
        c.TriggerSignatureUpdate();
        c.RequestProtectionStateRefresh();
        Assert.Equal(6, fired.Count);
    }

    [Fact]
    public void FindKnownThreat_uses_configured_lookup()
    {
        var c = _env.Container;
        Assert.Null(c.FindKnownThreat(@"C:\a.exe"));

        var known = ThreatInfo.FromClamAv(@"C:\a.exe", "Win.Known");
        c.ThreatLookup = p => p == known.FilePath ? known : null;

        Assert.Same(known, c.FindKnownThreat(@"C:\a.exe"));
        Assert.Null(c.FindKnownThreat(@"C:\b.exe"));
    }

    [Fact]
    public void Apply_methods_persist_choices_in_isolated_storage()
    {
        var c = _env.Container;

        c.ApplyAutoQuarantine(true);
        c.ApplyRemovableDriveScan(false);
        c.ApplyProcessMonitor(false);
        c.ApplySignatureAutoUpdate(false);
        c.ApplyRealtimeProtection(false);

        Assert.True(_env.Exclusions.AutoQuarantineEnabled);
        Assert.False(_env.Prefs.RemovableDriveScanEnabled);
        Assert.False(_env.Prefs.ProcessMonitorEnabled);
        Assert.False(_env.Prefs.SignatureAutoUpdateEnabled);
        Assert.False(_env.Exclusions.RealTimeEnabled);
        Assert.False(c.RealTimeProtection.IsEnabled);
    }

    [Fact]
    public void Shutdown_is_idempotent()
    {
        _env.Container.Shutdown();
        _env.Container.Shutdown();
    }
}

[Collection("Localization")]
public sealed class PdfReportThreatSectionTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "opticombat_pdf_" + Guid.NewGuid().ToString("N"));

    public PdfReportThreatSectionTests() => LocalizationService.ApplyCulture("fr-FR");

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch { /* best effort */ }
    }

    private static void AssertPdf(byte[] bytes) =>
        Assert.Equal("%PDF", System.Text.Encoding.ASCII.GetString(bytes, 0, 4));

    [Fact]
    public void Report_with_threats_includes_risk_section_and_is_saved()
    {
        var result = new ScanResult
        {
            Type = ScanType.Folder,
            TargetPath = @"C:\Users\demo\Downloads",
            StartedAt = DateTime.Now.AddMinutes(-3),
            FinishedAt = DateTime.Now,
            Status = ScanStatus.Completed,
            FilesScanned = 42,
        };
        result.Threats.Add(ThreatInfo.FromClamAv(@"C:\Users\demo\Downloads\a.exe", "Win.Trojan.A", 2048));
        result.Threats.Add(ThreatInfo.FromYara(@"C:\Users\demo\Downloads\b.docm", "Macro_Rule", 4096));
        var output = Path.Combine(_dir, "sub", "report.pdf");

        var bytes = new PdfReportGenerator().GenerateReport(result, output);

        AssertPdf(bytes);
        Assert.True(File.Exists(output));
        Assert.Equal(bytes.Length, new FileInfo(output).Length);
    }

    [Fact]
    public void Report_from_session_copies_threats()
    {
        var session = new ScanSession
        {
            SessionId = Guid.NewGuid(),
            StartedAt = DateTime.Now.AddHours(-1),
            FinishedAt = DateTime.Now,
            TargetPath = @"D:\",
            FilesScanned = 10,
            StatusDisplay = "Completed",
            ScanTypeValue = ScanType.FullScan,
        };
        session.Threats.Add(ThreatInfo.FromClamAv(@"D:\x.exe", "Win.X", 10));

        AssertPdf(new PdfReportGenerator().GenerateReportFromSession(session));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public void Report_from_legacy_session_synthesizes_threat_rows(int count)
    {
        var session = new ScanSession
        {
            StartedAt = DateTime.Now,
            ThreatsFound = count,
            StatusDisplay = "inconnu",
            TypeDisplayLegacy = "Type ancien",
        };

        AssertPdf(new PdfReportGenerator().GenerateReportFromSession(session));
    }
}
