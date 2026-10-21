using optiCombat.Localization;
using optiCombat.Services;

namespace optiCombat.Tests;

[Collection(nameof(UserPreferencesStorageTests))]
public sealed class SystemCleanAndUpdateCoverageTests
{
    public SystemCleanAndUpdateCoverageTests()
    {
        LocalizationService.ApplyCulture("fr-FR");
    }

    [Fact]
    public void CleanSelection_any_selected_and_empty_summary()
    {
        Assert.False(new CleanSelection().AnySelected);
        Assert.Equal("—", SystemCleanService.BuildTargetsSummary(new CleanSelection()));

        var all = AllFlags();
        Assert.True(all.AnySelected);
        var summary = SystemCleanService.BuildTargetsSummary(all);
        Assert.NotEqual("—", summary);
        Assert.Contains(",", summary);
    }

    [Fact]
    public void Analyze_empty_is_zero_and_all_flags_are_non_negative()
    {
        var empty = SystemCleanService.Analyze(new CleanSelection());
        Assert.Equal(0, empty.GrandTotal);
        Assert.Equal(0, empty.SystemTotal);
        Assert.Equal(0, empty.BrowserTotal);

        var measured = SystemCleanService.Analyze(AllFlags());
        Assert.True(measured.GrandTotal >= 0);
        Assert.True(measured.SystemTotal >= 0);
        Assert.True(measured.BrowserTotal >= 0);
    }

    [Fact]
    public void Execute_with_no_selection_only_writes_totals()
    {
        var lines = new List<string>();
        var result = SystemCleanService.Execute(new CleanSelection(), lines.Add);
        Assert.Equal(0, result.BytesFreed);
        Assert.NotEmpty(result.LogLines);
        Assert.Equal(result.LogLines.Count, lines.Count);
    }

    [Fact]
    public async Task SignatureUpdateCoordinator_null_backends_succeeds()
    {
        var log = new List<string>();
        var ok = await SignatureUpdateCoordinator.RunFullSignatureUpdateAsync(null, null, log.Add);
        Assert.True(ok);
        Assert.NotEmpty(log);
    }

    [Fact]
    public async Task SignatureUpdateUiRunner_lock_and_null_backends()
    {
        var runner = new SignatureUpdateUiRunner();
        Assert.True(runner.TryEnterUpdate());
        Assert.False(runner.TryEnterUpdate());
        runner.ReleaseUpdate();
        Assert.True(runner.TryEnterUpdate());
        runner.ReleaseUpdate();

        var log = new List<string>();
        Assert.True(await runner.RunFullUpdateAsync(null, null, log.Add));
        Assert.NotEmpty(log);
    }

    [Fact]
    public async Task UpdateService_check_returns_not_configured()
    {
        var result = await new UpdateService().CheckForUpdatesAsync();
        Assert.Equal(AppUpdateChannelStatus.NotConfigured, result.Status);
        Assert.True(result.Success);
        Assert.False(string.IsNullOrWhiteSpace(result.CurrentVersion));
        Assert.False(string.IsNullOrWhiteSpace(result.UserMessage));
        Assert.True(Directory.Exists(result.StagingDirectory));
    }

    private static CleanSelection AllFlags() => new()
    {
        TempWin = true,
        TempUser = true,
        Recycle = true,
        Logs = true,
        Edge = true,
        Chrome = true,
        Firefox = true,
        Brave = true,
        Opera = true,
        Vivaldi = true,
        Arc = true,
        WUCache = true,
        Dns = true,
        History = true,
    };
}
