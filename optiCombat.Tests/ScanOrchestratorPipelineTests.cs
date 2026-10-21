using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary>Pipeline ClamAV + YARA de <see cref="ScanOrchestrator"/> avec des moteurs factices.</summary>
public sealed class ScanOrchestratorPipelineTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "opticombat_pipe_" + Guid.NewGuid().ToString("N"));
    private readonly ExclusionSettings _exclusions = new() { ExcludedRuleNames = new() { "Ignored_Rule" } };
    private readonly ScriptedClamBackend _clam = new();
    private readonly ScriptedYaraBackend _yara = new();

    public ScanOrchestratorPipelineTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch { /* best effort */ }
    }

    private ScanOrchestrator Create() => new(
        _clam,
        _yara,
        new FixedPreferencesAccessor(new UserPreferences()),
        new FixedExclusionsAccessor(_exclusions),
        optiCombat: null);

    private string File(string name)
    {
        var path = Path.Combine(_dir, name);
        System.IO.File.WriteAllText(path, name);
        return path;
    }

    [Fact]
    public async Task ScanFile_merges_yara_match_and_drops_excluded_rule()
    {
        var target = File("a.exe");
        _yara.Matches.Add(new YaraMatch { FilePath = target, RuleName = "Evil_Rule" });
        _yara.Matches.Add(new YaraMatch { FilePath = target, RuleName = "Ignored_Rule" });
        var reports = new List<ScanProgress>();

        var result = await Create().ScanFileAsync(target, new SyncProgress(reports));

        var threat = Assert.Single(result.Threats);
        Assert.Contains("Evil_Rule", threat.VirusName);
        Assert.Equal(ScanStatus.Completed, result.Status);
        Assert.Equal(1, _clam.Calls);
    }

    [Fact]
    public async Task ScanFile_survives_yara_failure()
    {
        _yara.ThrowOnScan = new InvalidOperationException("yara KO");

        var result = await Create().ScanFileAsync(File("b.exe"));

        Assert.Equal(ScanStatus.Completed, result.Status);
        Assert.Empty(result.Threats);
    }

    [Fact]
    public async Task ScanFile_is_skipped_when_file_is_excluded()
    {
        var target = File("skip.exe");
        _exclusions.ExcludedFilePaths.Add(target);

        var result = await Create().ScanFileAsync(target);

        Assert.Equal(1, result.FilesSkipped);
        Assert.Equal(0, _clam.Calls);
        Assert.Equal(0, _yara.Calls);
    }

    [Fact]
    public async Task ScanFolder_combines_both_engines()
    {
        var bad = File("bad.dll");
        File("good.txt");
        _clam.ThreatsByPath[bad] = "Win.Clam";
        _yara.Matches.Add(new YaraMatch { FilePath = Path.Combine(_dir, "good.txt"), RuleName = "Yara_Only" });

        var result = await Create().ScanFolderAsync(_dir, new SyncProgress(new List<ScanProgress>()));

        Assert.Equal(2, result.Threats.Count);
        Assert.Contains(result.Threats, t => t.FilePath == bad);
        Assert.Contains(result.Threats, t => t.DetectedBy.Contains("YARA", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ScanFolder_reports_yara_failure_as_completed()
    {
        File("x.bin");
        _yara.ThrowOnScan = new IOException("disque");

        var result = await Create().ScanFolderAsync(_dir);

        Assert.Equal(ScanStatus.Completed, result.Status);
    }

    [Fact]
    public async Task Background_folder_scan_skips_pre_count()
    {
        var bad = File("usb.exe");
        _yara.Matches.Add(new YaraMatch { FilePath = bad, RuleName = "Usb_Rule" });

        var result = await Create().ScanFolderBackgroundAsync(_dir, ScanType.RemovableDrive);

        Assert.Single(result.Threats);
        Assert.Equal(ScanType.RemovableDrive, result.Type);
    }

    [Fact]
    public async Task ScanFileList_returns_empty_result_when_everything_is_excluded()
    {
        var only = File("ex.exe");
        _exclusions.ExcludedFilePaths.Add(only);

        var result = await Create().ScanFileListAsync(new[] { only, only }, _dir);

        Assert.Equal(ScanStatus.Completed, result.Status);
        Assert.Equal(0, result.FilesScanned);
        Assert.Equal(0, _clam.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ScanFileList_dedupes_yara_matches(bool sequential)
    {
        var a = File("l1.exe");
        var b = File("l2.exe");
        _yara.Matches.Add(new YaraMatch { FilePath = a, RuleName = "Dup_Rule" });
        _yara.Matches.Add(new YaraMatch { FilePath = a, RuleName = "Dup_Rule" });
        _yara.Matches.Add(new YaraMatch { FilePath = b, RuleName = "Ignored_Rule" });
        var reports = new List<ScanProgress>();

        var result = await Create().ScanFileListAsync(
            new[] { a, b, a.ToUpperInvariant() },
            _dir,
            ScanType.Folder,
            new SyncProgress(reports),
            scanEnginesSequentially: sequential);

        Assert.Single(result.Threats);
        Assert.Contains(reports, r => r.Phase == ScanPhase.ThreatFound);
    }

    [Fact]
    public async Task ScanFileList_reports_yara_failure_as_completed()
    {
        _yara.ThrowOnScan = new InvalidOperationException("lot KO");

        var result = await Create().ScanFileListAsync(new[] { File("f.exe") }, _dir);

        Assert.Equal(ScanStatus.Completed, result.Status);
    }

    [Fact]
    public async Task Cancelled_yara_marks_result_cancelled()
    {
        using var cts = new CancellationTokenSource();
        _yara.ThrowOnScan = new OperationCanceledException();

        var result = await Create().ScanFileListAsync(new[] { File("c.exe") }, _dir, ct: cts.Token);

        Assert.NotNull(result);
    }

    [Fact]
    public async Task Yara_unavailable_skips_rules_engine()
    {
        _yara.IsAvailable = false;

        await Create().ScanFolderAsync(_dir);
        await Create().ScanFileListAsync(new[] { File("u.exe") }, _dir);

        Assert.Equal(0, _yara.Calls);
    }

    [Fact]
    public async Task Install_root_folder_is_never_scanned()
    {
        var result = await Create().ScanFolderAsync(AppContext.BaseDirectory);

        Assert.Equal(1, result.FilesSkipped);
        Assert.Equal(0, _clam.Calls);
    }

    private sealed class SyncProgress(List<ScanProgress> sink) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value)
        {
            lock (sink)
                sink.Add(value);
        }
    }
}

/// <summary>Backend YARA piloté par le test.</summary>
internal sealed class ScriptedYaraBackend : IYaraOrchestratorBackend
{
    public bool IsAvailable { get; set; } = true;

    public int RulesCount => 10;

    public List<YaraMatch> Matches { get; } = new();

    public Exception? ThrowOnScan { get; set; }

    public int Calls { get; private set; }

    private Task<List<YaraMatch>> Run(Func<YaraMatch, bool> filter)
    {
        Calls++;
        if (ThrowOnScan != null)
            throw ThrowOnScan;
        return Task.FromResult(Matches.Where(filter).ToList());
    }

    public Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default) =>
        Run(m => string.Equals(m.FilePath, filePath, StringComparison.OrdinalIgnoreCase));

    public Task<List<YaraMatch>> ScanFolderAsync(string folderPath, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        progress?.Report(folderPath);
        return Run(m => m.FilePath.StartsWith(folderPath, StringComparison.OrdinalIgnoreCase));
    }

    public Task<List<YaraMatch>> ScanFilesAsync(IReadOnlyList<string> files, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        foreach (var f in files)
            progress?.Report(f);
        return Run(m => files.Contains(m.FilePath, StringComparer.OrdinalIgnoreCase));
    }
}
