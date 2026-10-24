using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary><see cref="ClamAvEngine"/> contre un « clamscan » factice.</summary>
[Collection("Localization")]
public sealed class ClamAvEngineProcessTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "oc_clam_" + Guid.NewGuid().ToString("N"));
    private readonly string _bin;
    private readonly string _samples;
    private readonly string _exe;
    private readonly FixedExclusionsAccessor _exclusions = new(new ExclusionSettings());

    public ClamAvEngineProcessTests()
    {
        LocalizationService.ApplyCulture("fr-FR");
        _bin = Path.Combine(_root, "clamav");
        Directory.CreateDirectory(Path.Combine(_bin, "database"));
        _samples = Path.Combine(_root, "samples");
        Directory.CreateDirectory(_samples);
        _exe = FakeTools.Install(_bin, "clamscan.exe");
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, true); } catch { }
    }

    private ClamAvEngine Create() => new(_bin, _exclusions);

    private string Sample(string name, string content = "x")
    {
        var p = Path.Combine(_samples, name);
        File.WriteAllText(p, content);
        return p;
    }

    [Fact]
    public async Task Version_probe_is_cached_and_reports_first_line()
    {
        FakeTools.Script(_exe, "version", stdout: "ClamAV 1.4.1/27795/Thu Oct 23 2026\nligne 2");
        var engine = Create();

        Assert.True(engine.IsClamAvInstalled());
        Assert.True(engine.IsClamAvInstalled()); // cache 60 s
        Assert.Single(FakeTools.Calls(_exe));
        Assert.Equal("ClamAV 1.4.1/27795/Thu Oct 23 2026", await engine.GetVersionAsync());
        Assert.EndsWith("database", engine.DatabaseDir, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Missing_or_silent_clamscan_is_not_installed()
    {
        FakeTools.Script(_exe, "version", stdout: "autre chose");
        Assert.False(Create().IsClamAvInstalled());

        var empty = new ClamAvEngine(Path.Combine(_root, "vide"), _exclusions);
        Assert.False(empty.IsClamAvInstalled());
        Assert.Equal(LocalizationService.GetString("Clam_NotInstalled"), await empty.GetVersionAsync());
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            empty.ScanFileAsync(Sample("a.txt")));
    }

    [Fact]
    public async Task File_scan_reports_threats_and_progress()
    {
        var bad = Sample("bad.bin", "payload");
        FakeTools.Script(_exe, stdout:
            $"{bad}: Win.Test.Fake FOUND\n" +
            "----------- SCAN SUMMARY -----------\n" +
            "Scanned files: 1\n" +
            "Data scanned: 0.01 MB\n");
        var reports = new List<ScanProgress>();

        var result = await Create().ScanFileAsync(bad, new SyncProgress<ScanProgress>(reports.Add));

        Assert.Equal(ScanStatus.Completed, result.Status);
        var threat = Assert.Single(result.Threats);
        Assert.Equal("Win.Test.Fake", threat.VirusName);
        Assert.Equal(1, result.FilesScanned);
        Assert.Contains(reports, r => r.Phase == ScanPhase.Starting);
        Assert.Contains(reports, r => r.Phase == ScanPhase.Completed);
        var call = Assert.Single(FakeTools.Calls(_exe));
        Assert.Contains("--stdout", call);
        Assert.Contains(call, a => a.StartsWith("--database=", StringComparison.Ordinal));
        Assert.Equal(bad, call[^1]);
        await Assert.ThrowsAsync<FileNotFoundException>(() => Create().ScanFileAsync(Path.Combine(_samples, "absent")));
    }

    [Fact]
    public async Task Folder_scan_is_recursive_and_counts_ok_lines()
    {
        var a = Sample("a.txt");
        var b = Sample("b.txt");
        FakeTools.Script(_exe, stdout: $"{a}: OK\n{b}: OK\n");

        var result = await Create().ScanFolderAsync(_samples);

        Assert.Equal(2, result.FilesScanned);
        Assert.Empty(result.Threats);
        var call = Assert.Single(FakeTools.Calls(_exe));
        Assert.Equal("--recursive", call[0]);
        await Assert.ThrowsAsync<DirectoryNotFoundException>(() => Create().ScanFolderAsync(Path.Combine(_root, "nope")));
    }

    [Fact]
    public async Task File_list_scan_uses_a_temporary_list_and_deletes_it()
    {
        var a = Sample("l1.txt");
        FakeTools.Script(_exe, stdout: $"{a}: OK\n");
        var engine = Create();

        var empty = await engine.ScanFileListAsync(Array.Empty<string>(), _samples);
        Assert.Equal(ScanStatus.Completed, empty.Status);
        Assert.Empty(FakeTools.Calls(_exe));

        var result = await engine.ScanFileListAsync(new[] { a, Path.Combine(_samples, "absent") }, _samples);
        Assert.Equal(1, result.FilesScanned);
        var call = Assert.Single(FakeTools.Calls(_exe));
        var listArg = Assert.Single(call, x => x.StartsWith("--file-list=", StringComparison.Ordinal));
        Assert.False(File.Exists(listArg["--file-list=".Length..]), "liste temporaire supprimée");

        var none = await engine.ScanFileListAsync(new[] { Path.Combine(_samples, "absent") }, _samples);
        Assert.Equal(ScanStatus.Error, none.Status);
        Assert.False(string.IsNullOrEmpty(none.ErrorMessage));
    }

    [Fact]
    public async Task Cancellation_kills_clamscan()
    {
        FakeTools.Script(_exe, delayMs: 20_000);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(800));
        var result = await Create().ScanFolderAsync(_samples, ct: cts.Token);
        Assert.Equal(ScanStatus.Cancelled, result.Status);
    }

    [Fact]
    public async Task Quick_scan_runs_one_process_per_existing_target()
    {
        FakeTools.Script(_exe, stdout: "Scanned files: 0\n");
        var result = await Create().QuickScanAsync();
        Assert.Equal(ScanType.QuickScan, result.Type);
        Assert.True(FakeTools.Calls(_exe).Count >= 0);
    }

    private sealed class SyncProgress<T>(Action<T> onReport) : IProgress<T>
    {
        public void Report(T value)
        {
            lock (this)
                onReport(value);
        }
    }
}

/// <summary><see cref="YaraEngine"/> contre des « yara » / « yarac » factices.</summary>
[Collection("Localization")]
public sealed class YaraEngineProcessTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "oc_yara_" + Guid.NewGuid().ToString("N"));
    private readonly string _yaraDir;
    private readonly string _rules;
    private readonly string _samples;
    private readonly string _yara;
    private readonly string _yarac;
    private readonly FixedExclusionsAccessor _exclusions = new(new ExclusionSettings());

    private static string Arch => Environment.Is64BitProcess ? "64" : "32";

    public YaraEngineProcessTests()
    {
        LocalizationService.ApplyCulture("fr-FR");
        _yaraDir = Path.Combine(_root, "yara");
        _rules = Path.Combine(_root, "rules");
        _samples = Path.Combine(_root, "samples");
        Directory.CreateDirectory(_rules);
        Directory.CreateDirectory(_samples);
        File.WriteAllText(Path.Combine(_rules, "a.yar"), "rule A { condition: true }\n  rule B_2 { condition: false }\n");
        File.WriteAllText(Path.Combine(_rules, "b.yar"), "// commentaire\nrule C { condition: true }\n");
        _yara = FakeTools.Install(_yaraDir, $"yara{Arch}.exe");
        _yarac = FakeTools.Install(_yaraDir, $"yarac{Arch}.exe");
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, true); } catch { }
    }

    private YaraEngine Create() => new(_yaraDir, _rules, _exclusions);

    private string Compiled => Path.Combine(_rules, "_compiled.yarc");

    private string Sample(string name)
    {
        var p = Path.Combine(_samples, name);
        File.WriteAllText(p, "contenu");
        return p;
    }

    private void CompileSucceeds() => FakeTools.Script(_yarac, writes: (Compiled, "yarc"));

    [Fact]
    public void Counts_rules_and_caches_the_count()
    {
        var engine = Create();
        Assert.True(engine.IsAvailable);
        Assert.Equal(3, engine.RulesCount);
        Assert.True(File.Exists(Path.Combine(_rules, ".rules_count.cache")));
        Assert.Equal(3, Create().RulesCount); // relu depuis le cache
        Assert.False(engine.HasCompiled);
    }

    [Fact]
    public void Unavailable_without_executable_or_rules()
    {
        Assert.False(new YaraEngine(Path.Combine(_root, "none"), _rules, _exclusions).IsAvailable);
        var emptyRules = Path.Combine(_root, "empty");
        Directory.CreateDirectory(emptyRules);
        Assert.False(new YaraEngine(_yaraDir, emptyRules, _exclusions).IsAvailable);
        Assert.False(new YaraEngine(_yaraDir, Path.Combine(_root, "absent"), _exclusions).IsAvailable);
    }

    [Fact]
    public async Task Compiles_then_scans_with_compiled_rules()
    {
        CompileSucceeds();
        var file = Sample("s.bin");
        FakeTools.Script(_yara, "compiled-rules", stdout: $"EICAR_Test {file}\n0x0:$a: X5O\n");
        var engine = Create();

        Assert.True(await engine.CompileRulesAsync());
        Assert.True(engine.HasCompiled);
        var matches = await engine.ScanFileAsync(file);

        var m = Assert.Single(matches);
        Assert.Equal("EICAR_Test", m.RuleName);
        Assert.Equal(file, m.FilePath);
        Assert.True(await engine.IsMaliciousAsync(file));

        engine.InvalidateCompiledRules();
        Assert.False(engine.HasCompiled);
        Assert.False(File.Exists(Compiled));
    }

    [Fact]
    public async Task Without_yarac_each_rule_file_is_scanned()
    {
        File.Delete(_yarac);
        var file = Sample("t.bin");
        FakeTools.Script(_yara, stdout: $"A {file}\n");
        var engine = Create();

        Assert.False(await engine.CompileRulesAsync());
        var matches = await engine.ScanFileAsync(file);

        Assert.Equal(2, matches.Count); // une passe par fichier .yar
        Assert.Equal(2, FakeTools.Calls(_yara).Count);
        Assert.Empty(await engine.ScanFileAsync(Path.Combine(_samples, "absent")));
    }

    [Fact]
    public async Task Failed_compilation_is_reported()
    {
        FakeTools.Script(_yarac, exit: 1, stderr: "error: syntax");
        Assert.False(await Create().CompileRulesAsync());
        Assert.False(File.Exists(Compiled));
    }

    [Fact]
    public async Task Folder_scan_is_recursive_in_one_process()
    {
        CompileSucceeds();
        var a = Sample("dir a.bin");
        var b = Sample("b.bin");
        FakeTools.Script(_yara, "N", stdout: $"R1 {a}\nR2 {b}\n", stderr: "warning: x");
        var progress = new List<string>();

        var matches = await Create().ScanFolderAsync(_samples, new SyncProgress<string>(progress.Add));

        Assert.Equal(new[] { a, b }, matches.Select(x => x.FilePath).ToArray());
        var call = FakeTools.Calls(_yara).Single();
        Assert.Contains("--recursive", call);
        Assert.Contains("--compiled-rules", call);
        Assert.NotEmpty(progress);
        Assert.Empty(await Create().ScanFolderAsync(Path.Combine(_root, "absent")));
    }

    [Fact]
    public async Task Folder_scan_without_compiled_rules_runs_once_per_rule_file()
    {
        File.Delete(_yarac);
        var a = Sample("c.bin");
        FakeTools.Script(_yara, "N", stdout: $"R {a}\n");
        var matches = await Create().ScanFolderAsync(_samples);
        Assert.Equal(2, matches.Count);
    }

    [Fact]
    public async Task File_list_scan_runs_in_batches_and_skips_missing_files()
    {
        CompileSucceeds();
        var files = Enumerable.Range(0, 40).Select(i => Sample($"f{i}.bin")).ToList();
        files.Add(Path.Combine(_samples, "absent.bin"));
        FakeTools.Script(_yara, "N", stdout: $"R {files[0]}\n");

        var matches = await Create().ScanFilesAsync(files);

        Assert.Equal(2, FakeTools.Calls(_yara).Count); // 32 + 8
        Assert.Equal(2, matches.Count);
        Assert.Empty(await Create().ScanFilesAsync(Array.Empty<string>()));
    }

    [Fact]
    public async Task Cancellation_kills_yara()
    {
        CompileSucceeds();
        FakeTools.Script(_yara, "N", delayMs: 20_000);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(800));
        var matches = await Create().ScanFolderAsync(_samples, ct: cts.Token);
        Assert.Empty(matches);
    }

    private sealed class SyncProgress<T>(Action<T> onReport) : IProgress<T>
    {
        public void Report(T value)
        {
            lock (this)
                onReport(value);
        }
    }
}
