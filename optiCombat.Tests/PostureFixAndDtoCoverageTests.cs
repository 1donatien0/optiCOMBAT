using System.Text.Json;
using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Services.OptiCombat;

namespace optiCombat.Tests;

[Collection(nameof(UserPreferencesStorageTests))]
public sealed class PostureFixAndDtoCoverageTests : IDisposable
{
    private readonly string _root;

    public PostureFixAndDtoCoverageTests()
    {
        LocalizationService.ApplyCulture("fr-FR");
        _root = Path.Combine(Path.GetTempPath(), "opticombat_pf_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
        LocalizationService.ApplyCulture("fr-FR");
    }

    [Theory]
    [InlineData("firewall", true)]
    [InlineData("uac", true)]
    [InlineData("shares", true)]
    [InlineData("opticombat", true)]
    [InlineData("scan", true)]
    [InlineData("sigauto", true)]
    [InlineData("windows-update", false)]
    [InlineData(null, false)]
    public void CanAutoFix_known_ids(string? id, bool expected) =>
        Assert.Equal(expected, PostureFixService.CanAutoFix(id));

    [Fact]
    public async Task FixAsync_covers_cancel_done_restart_scan_and_unsupported()
    {
        var unsupported = await PostureFixService.FixAsync("unknown", null!, (_, _) => true);
        Assert.Equal(PostureFixStatus.NotSupported, unsupported.Status);

        var scanMissing = await PostureFixService.FixAsync("scan", null!, (_, _) => true);
        Assert.Equal(PostureFixStatus.NotSupported, scanMissing.Status);

        var started = false;
        var scanOk = await PostureFixService.FixAsync("scan", null!, (_, _) => true, () =>
        {
            started = true;
            return Task.CompletedTask;
        });
        Assert.True(started);
        Assert.Equal(PostureFixStatus.Done, scanOk.Status);

        var cancelled = await PostureFixService.FixAsync("firewall", null!, (_, _) => false, runElevated: _ => true);
        Assert.Equal(PostureFixStatus.Cancelled, cancelled.Status);

        var denied = await PostureFixService.FixAsync("firewall", null!, (_, _) => true, runElevated: _ => false);
        Assert.Equal(PostureFixStatus.Cancelled, denied.Status);

        var done = await PostureFixService.FixAsync("firewall", null!, (_, _) => true, runElevated: _ => true);
        Assert.Equal(PostureFixStatus.Done, done.Status);

        var restart = await PostureFixService.FixAsync("uac", null!, (_, _) => true, runElevated: _ => true);
        Assert.Equal(PostureFixStatus.NeedsRestart, restart.Status);

        var shares = await PostureFixService.FixAsync("shares", null!, (_, _) => false, runElevated: _ => true);
        Assert.True(shares.Status is PostureFixStatus.Done or PostureFixStatus.Cancelled);
    }

    [Fact]
    public void BuildShareDeleteCommands_skips_admin_and_unsafe_names()
    {
        var cmds = PostureFixService.BuildShareDeleteCommands(
            new[] { "C$", "Docs", "bad&name", "Public" }, out var accepted);
        Assert.Equal(new[] { "Docs", "Public" }, accepted);
        Assert.All(cmds, c => Assert.Contains("net share", c));
    }

    [Fact]
    public void JsonElementExtensions_string_and_array_fallbacks()
    {
        using var doc = JsonDocument.Parse("""{"name":"ok","empty":null,"items":[1,2],"notArray":"x"}""");
        var root = doc.RootElement;
        Assert.Equal("ok", root.GetPropertyOrDefault("name", "fb"));
        Assert.Equal("fb", root.GetPropertyOrDefault("missing", "fb"));
        Assert.Equal("fb", root.GetPropertyOrDefault("empty", "fb"));
        Assert.Equal(2, root.GetArrayOrEmpty("items").Count());
        Assert.Empty(root.GetArrayOrEmpty("missing"));
        Assert.Empty(root.GetArrayOrEmpty("notArray"));
    }

    [Fact]
    public void ActivityLog_restore_delete_and_legacy_migration()
    {
        var logger = new ScanLogManager(_root);
        var activity = new ActivityLogService(logger, _root);
        var quarantine = new QuarantineManager(Path.Combine(_root, "q"));
        var entry = new QuarantineEntry
        {
            Id = "q1",
            OriginalPath = @"C:\legacy.exe",
            VirusName = "L",
            QuarantinedAt = DateTime.Now,
            OriginalSize = 8,
        };

        activity.RecordThreatRestored(entry);
        activity.RecordQuarantineDeleted(entry);
        var feed = activity.GetActivityFeed(quarantine);
        Assert.Equal(2, feed.Count);
        activity.EnsureMigrated(quarantine);

        var emptyDir = Path.Combine(_root, "legacy");
        Directory.CreateDirectory(emptyDir);
        var legacyLogger = new ScanLogManager(emptyDir);
        legacyLogger.SaveScanResult(new ScanResult
        {
            Type = ScanType.QuickScan,
            TargetPath = @"C:\old",
            Status = ScanStatus.Completed,
            StartedAt = DateTime.Now.AddDays(-1),
            FinishedAt = DateTime.Now.AddDays(-1).AddMinutes(1),
        });
        var legacyActivity = new ActivityLogService(legacyLogger, Path.Combine(emptyDir, "act"));
        legacyActivity.EnsureMigrated(new QuarantineManager(Path.Combine(emptyDir, "q")));
        Assert.NotEmpty(legacyActivity.GetActivityFeed(new QuarantineManager(Path.Combine(emptyDir, "q2"))));
    }

    [Fact]
    public void Update_and_exclusion_result_dtos()
    {
        var upd = new UpdateResult
        {
            Success = true,
            Message = "ok",
            Version = "1",
            AlreadyUpToDate = true,
            ExitCode = 0,
            StartedAt = DateTime.Now,
            FinishedAt = DateTime.Now,
        };
        Assert.True(upd.Success);
        Assert.True(upd.AlreadyUpToDate);

        var rules = new RulesUpdateResult
        {
            Success = true,
            Message = "ok",
            Version = "2",
            FilesInstalled = 3,
            StartedAt = DateTime.Now.AddSeconds(-2),
            FinishedAt = DateTime.Now,
        };
        Assert.True(rules.Duration > TimeSpan.Zero);
        Assert.Equal(TimeSpan.Zero, new RulesUpdateResult().Duration);

        Assert.Equal(DefenderExclusionStatus.NotApplicable, DefenderExclusionResult.NotApplicable().Status);
        Assert.Equal(DefenderExclusionStatus.DefenderUnavailable, DefenderExclusionResult.Unavailable("x").Status);
        Assert.Equal(DefenderExclusionStatus.AlreadyConfigured, DefenderExclusionResult.AlreadyConfigured().Status);
        Assert.Equal(DefenderExclusionStatus.Added, DefenderExclusionResult.Added(2).Status);
        Assert.Equal(DefenderExclusionStatus.AccessDenied, DefenderExclusionResult.AccessDenied().Status);
        Assert.Equal(DefenderExclusionStatus.PartialFailure, DefenderExclusionResult.Partial("p", 1).Status);
    }
}
