using optiCombat.Tests.TestSupport;
using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Strings;
using optiCombat.ViewModels;

namespace optiCombat.Tests;

[Collection(nameof(UserPreferencesStorageTests))]
public sealed class CoverageCompletionTests : IDisposable
{
    private readonly string _root;

    public CoverageCompletionTests()
    {
        LocalizationService.ApplyCulture("fr-FR");
        _root = Path.Combine(Path.GetTempPath(), "opticombat_cov_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
        LocalizationService.ApplyCulture("fr-FR");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(512)]
    [InlineData(2048)]
    [InlineData(3_000_000)]
    [InlineData(4_000_000_000)]
    public void ByteSizeFormat_covers_all_units(long bytes)
    {
        var text = ByteSizeFormat.Format(bytes);
        Assert.False(string.IsNullOrWhiteSpace(text));
    }

    [Fact]
    public void VersionDisplayHelper_placeholders_and_normalize()
    {
        Assert.True(VersionDisplayHelper.IsPlaceholder(null));
        Assert.True(VersionDisplayHelper.IsPlaceholder(""));
        Assert.True(VersionDisplayHelper.IsPlaceholder("—"));
        Assert.True(VersionDisplayHelper.IsPlaceholder("Inconnue"));
        Assert.True(VersionDisplayHelper.IsPlaceholder(VersionDisplayHelper.UnknownLabel));
        Assert.False(VersionDisplayHelper.IsPlaceholder("1.4.2"));
        Assert.Equal("—", VersionDisplayHelper.NormalizeForDisplay(null));
        Assert.Equal("1.4.2", VersionDisplayHelper.NormalizeForDisplay("1.4.2"));
    }

    [Fact]
    public void ScanProgress_factories_clone_update_and_flags()
    {
        var start = ScanProgress.Starting();
        Assert.Equal(ScanPhase.Starting, start.Phase);
        Assert.True(start.IsActive);
        Assert.False(start.IsFinished);
        Assert.Equal(-1, start.PercentComplete);

        var scanning = ScanProgress.Scanning("f", 10, 1);
        scanning.TotalFiles = 20;
        Assert.Equal(50, scanning.PercentComplete);

        var threat = new ThreatInfo { FilePath = @"C:\t.exe", VirusName = "EICAR" };
        var found = ScanProgress.ThreatFound(threat);
        Assert.Equal(ScanPhase.ThreatFound, found.Phase);
        Assert.Equal(1, found.ThreatsFound);

        var done = ScanProgress.Completed("ok", 3, 0);
        Assert.True(done.IsFinished);
        var cancelled = ScanProgress.Cancelled();
        Assert.Equal(ScanPhase.Cancelled, cancelled.Phase);
        var error = ScanProgress.Error("boom");
        Assert.Equal(ScanPhase.Error, error.Phase);

        var copy = done.Clone();
        Assert.Equal(done.FilesScanned, copy.FilesScanned);
        copy.UpdateFrom(scanning);
        Assert.Equal(10, copy.FilesScanned);
        copy.Reset();
        Assert.Equal(0, copy.FilesScanned);
        Assert.Contains("Starting", copy.ToString());
        _ = new ScanProgress((ScanProgress)null!);
        copy.UpdateFrom(null!);
    }

    [Fact]
    public void UiIconKinds_and_UiLogText_cover_all_branches()
    {
        Assert.Equal("AlertOctagon", UiIconKinds.ForRiskLevel(RiskLevel.Critical));
        Assert.Equal("Alert", UiIconKinds.ForRiskLevel(RiskLevel.Major));
        Assert.Equal("AlertCircleOutline", UiIconKinds.ForRiskLevel(RiskLevel.Minor));
        Assert.Equal("InformationOutline", UiIconKinds.ForRiskLevel(RiskLevel.Informational));
        Assert.Equal(UiIconKinds.Error, UiIconKinds.ForStatusFooter(true, false));
        Assert.Equal(UiIconKinds.Warning, UiIconKinds.ForStatusFooter(false, true));
        Assert.Equal(UiIconKinds.Success, UiIconKinds.ForStatusFooter(false, false));
        Assert.StartsWith(UiLogText.OkPrefix, UiLogText.Ok("x"));
        Assert.StartsWith(UiLogText.ErrorPrefix, UiLogText.Error("x"));
        Assert.StartsWith(UiLogText.WarnPrefix, UiLogText.Warn("x"));
        Assert.StartsWith(UiLogText.InfoPrefix, UiLogText.Info("x"));
        Assert.Contains("n", UiLogText.ReadyLine("n"));
        Assert.Contains("n", UiLogText.MissingLine("n"));
    }

    [Fact]
    public void ElevationHelper_needs_elevation_for_system_paths_only()
    {
        Assert.False(ElevationHelper.NeedsElevation(""));
        Assert.False(ElevationHelper.NeedsElevation(_root));
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Assert.True(ElevationHelper.NeedsElevation(win));
        Assert.True(ElevationHelper.NeedsElevation(Path.Combine(win, "System32")));
        _ = ElevationHelper.IsRunningElevated();
    }

    [Fact]
    public void ComReleaseHelper_ignores_null_and_managed_objects()
    {
        ComReleaseHelper.Release(null);
        ComReleaseHelper.Release(new object());
    }

    [Fact]
    public void OpticombatStrings_localized_helpers_are_non_empty()
    {
        Assert.Equal("Overview", OpticombatStrings.PanelIds.Overview);
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.Confirmations.Title));
        Assert.Contains("2", OpticombatStrings.Confirmations.QuarantineAll(2));
        Assert.Contains("3", OpticombatStrings.Confirmations.PurgeQuarantine(3));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.UiMessages.ProtectionActive));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.UiMessages.ProtectionReducedTray));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.UiMessages.AnalyseInterrompueSurDemande));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.UiMessages.RestoreFromQuarantineSuccess));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.UiMessages.RestoreFromQuarantineError));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.UiMessages.DeleteThreatPermanentlySuccess));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.UiMessages.DeleteThreatPermanentlyError));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.StatusUpdates.SignaturesUpdateAlreadyRunning));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.StatusUpdates.SignaturesUpdateInProgress));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.StatusUpdates.RulesUpdateInProgress));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.StatusUpdates.FullSignaturesUpdateStarting));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.StatusUpdates.SignaturesUpdateFinishedSuccess));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.StatusUpdates.SignaturesUpdateFinishedError));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.StatusUpdates.FullSignaturesUpdateFinished));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.StatusUpdates.FullSignaturesUpdateFinishedWithErrors));
        Assert.False(string.IsNullOrWhiteSpace(OpticombatStrings.StatusUpdates.SignaturesUpdateStopping));
        Assert.StartsWith("https://", OpticombatStrings.Urls.OpticombatWebsite);
    }

    [Fact]
    public void ScanResult_display_properties_cover_badges()
    {
        var result = new ScanResult
        {
            Type = ScanType.QuickScan,
            Status = ScanStatus.Completed,
            FilesScanned = 4,
            StartedAt = DateTime.Now.AddMinutes(-1),
            FinishedAt = DateTime.Now,
        };
        Assert.True(result.IsClean);
        Assert.False(string.IsNullOrWhiteSpace(result.SummaryDisplay));
        Assert.False(string.IsNullOrWhiteSpace(result.TypeDisplay));
        Assert.False(string.IsNullOrWhiteSpace(result.DurationDisplay));
        Assert.Equal(LocalizationService.GetString("Badge_Clean"), result.ThreatsBadge);

        result.Threats.Add(new ThreatInfo { FilePath = "a", VirusName = "x" });
        Assert.Contains("1", result.ThreatsBadge);
        result.Threats.Add(new ThreatInfo { FilePath = "b", VirusName = "y" });
        Assert.Contains("2", result.ThreatsBadge);

        result.Status = ScanStatus.Running;
        Assert.Equal(LocalizationService.GetString("Badge_Running"), result.ThreatsBadge);
        result.Status = ScanStatus.Cancelled;
        Assert.Equal(LocalizationService.GetString("Badge_Cancelled"), result.ThreatsBadge);
        result.Status = ScanStatus.Error;
        result.ErrorMessage = "e";
        Assert.Equal(LocalizationService.GetString("Badge_Error"), result.ThreatsBadge);
        Assert.True(result.Duration > TimeSpan.Zero);
    }

    [Fact]
    public void HistoryThreatRow_flags_for_accessible_missing_and_quarantined()
    {
        var logDir = Path.Combine(_root, "hist");
        Directory.CreateDirectory(logDir);
        var logger = new ScanLogManager(logDir);
        var activity = new ActivityLogService(logger, logDir);
        logger.BindActivityLog(activity);
        var quarantine = new QuarantineManager(Path.Combine(logDir, "q"));
        var vm = new HistoryViewModel(activity, quarantine, logger);

        var live = Path.Combine(logDir, "live.bin");
        File.WriteAllBytes(live, new byte[] { 1, 2, 3 });
        var missing = Path.Combine(logDir, "gone.bin");

        var liveRow = new HistoryThreatRow(new ThreatInfo { FilePath = live, VirusName = "A" }, vm);
        Assert.True(liveRow.CanQuarantine);
        Assert.False(liveRow.CanViewInQuarantine);
        Assert.False(liveRow.CanDismiss);
        Assert.Equal(live, liveRow.FilePath);
        Assert.Equal("A", liveRow.VirusName);

        var missingRow = new HistoryThreatRow(new ThreatInfo { FilePath = missing, VirusName = "B" }, vm);
        Assert.True(missingRow.CanDismiss);
        Assert.False(missingRow.CanQuarantine);

        Assert.False(vm.IsThreatFileAccessible(""));
        Assert.False(vm.IsThreatFileAccessible(@"Z:\no-such-drive\x.bin"));

        var rows = vm.BuildThreatRows(new[]
        {
            new ThreatInfo { FilePath = live, VirusName = "A" },
        });
        Assert.Single(rows);
        Assert.Same(rows[0].Threat, rows[0].Threat);

        var toQuarantine = Path.Combine(logDir, "qme.bin");
        File.WriteAllBytes(toQuarantine, new byte[] { 9 });
        Assert.True(quarantine.Quarantine(new ThreatInfo { FilePath = toQuarantine, VirusName = "Q" }));
        var qRow = new HistoryThreatRow(new ThreatInfo { FilePath = toQuarantine, VirusName = "Q" }, vm);
        Assert.True(qRow.CanViewInQuarantine);
        Assert.False(qRow.CanQuarantine);
        Assert.True(vm.IsFileStillQuarantined(toQuarantine));
        Assert.Null(vm.FindLiveQuarantine(""));
    }

    [Fact]
    public void ThreatInfo_factories_display_clone_and_equality()
    {
        var clam = ThreatInfo.FromClamAv(@"C:\a.exe", "Win.Test", 100);
        var yara = ThreatInfo.FromYara(@"C:\b.exe", "Rule", 2048);
        var both = ThreatInfo.FromBoth(@"C:\c.exe", "Win.Test", "Rule", 2_000_000);
        var unknown = new ThreatInfo { FilePath = @"C:\d.exe", DetectedBy = "Other", FileSize = -1 };

        Assert.Equal("a.exe", clam.FileName);
        Assert.Contains("o", clam.FileSizeDisplay);
        Assert.Contains("Ko", yara.FileSizeDisplay);
        Assert.Contains("Mo", both.FileSizeDisplay);
        Assert.Equal("Inconnu", unknown.FileSizeDisplay);
        Assert.Equal("#27AE60", clam.DetectedByColor);
        Assert.Equal("#E67E22", yara.DetectedByColor);
        Assert.Equal("#9C27B0", both.DetectedByColor);
        Assert.Equal("#546478", unknown.DetectedByColor);
        Assert.Equal("ShieldCheck", clam.DetectedByIcon);
        Assert.Equal("FileSearch", yara.DetectedByIcon);
        Assert.Equal("ShieldCross", both.DetectedByIcon);
        Assert.Equal("Alert", unknown.DetectedByIcon);

        var copy = clam.Clone();
        Assert.Equal(clam, copy);
        Assert.Equal(clam.GetHashCode(), copy.GetHashCode());
        Assert.False(clam.Equals("x"));
        Assert.Contains("a.exe", clam.ToString());
    }

    [Theory]
    [InlineData(ScanType.File)]
    [InlineData(ScanType.Folder)]
    [InlineData(ScanType.QuickScan)]
    [InlineData(ScanType.FullScan)]
    [InlineData(ScanType.RemovableDrive)]
    [InlineData(ScanType.RealTime)]
    public void ScanResult_TypeDisplay_covers_all_scan_types(ScanType type)
    {
        var result = new ScanResult { Type = type, Status = ScanStatus.Completed };
        Assert.False(string.IsNullOrWhiteSpace(result.TypeDisplay));
        Assert.False(string.IsNullOrWhiteSpace(result.DurationDisplay));
    }

    [Fact]
    public void ScanSession_duration_and_badges()
    {
        var session = new ScanSession
        {
            SessionId = Guid.NewGuid(),
            StartedAt = DateTime.Now.AddSeconds(-5),
            FinishedAt = DateTime.Now,
            ScanTypeValue = ScanType.FullScan,
            ThreatsFound = 0,
        };
        Assert.False(string.IsNullOrWhiteSpace(session.TypeDisplay));
        Assert.NotEqual("—", session.DurationDisplay);
        Assert.Equal(LocalizationService.GetString("Badge_Clean"), session.ThreatsBadge);

        session.ThreatsFound = 2;
        Assert.Contains("2", session.ThreatsBadge);

        session.FinishedAt = null;
        Assert.Equal("—", session.DurationDisplay);
    }

    [Fact]
    public void ElevationHelper_invalid_path_does_not_need_elevation()
    {
        Assert.False(ElevationHelper.NeedsElevation("?:\\not-a-path"));
        Assert.True(ElevationHelper.NeedsElevation(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)));
        Assert.True(ElevationHelper.NeedsElevation(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)));
    }

    [Fact]
    public void ShellContextMenuSupport_writes_current_user_keys()
    {
        // Enregistreur : l'ancien test écrivait puis SUPPRIMAIT le vrai menu contextuel du poste.
        using var shell = RecordingShell.Install();
        LocalizationService.ApplyCulture("fr-FR");
        var name = LocalizationService.GetString("Shell_ScanWith");
        ShellContextMenuSupport.ExecutablePathOverride = @"C:\Program Files\optiCombat\optiCombat.exe";
        try
        {
            ShellContextMenuSupport.ApplyForCurrentCulture();
        }
        finally
        {
            ShellContextMenuSupport.ExecutablePathOverride = null;
        }

        foreach (var root in new[] { @"Software\Classes\*\shell", @"Software\Classes\Directory\shell" })
        {
            Assert.Equal(@"C:\Program Files\optiCombat\optiCombat.exe,0",
                shell.GetCurrentUserValue(root + "\\" + name, "Icon"));
            Assert.Equal("\"C:\\Program Files\\optiCombat\\optiCombat.exe\" --scan \"%1\"",
                shell.GetCurrentUserValue(root + "\\" + name + "\\command", string.Empty));
            Assert.Contains(root + "\\Scanner avec optiCombat", shell.DeletedTrees);
            Assert.Contains(root + "\\Scan with optiCombat", shell.DeletedTrees);
        }
    }
}
