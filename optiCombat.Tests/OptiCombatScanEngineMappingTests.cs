using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Services.OptiCombat;

namespace optiCombat.Tests;

/// <summary>
/// Conversion de la sortie JSON du cœur Rust en <see cref="ScanResult"/> (appel natif simulé :
/// aucune DLL requise, mêmes chemins de code sous Windows et Linux).
/// </summary>
public sealed class OptiCombatScanEngineMappingTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "oc_map_" + Guid.NewGuid().ToString("N"));

    public OptiCombatScanEngineMappingTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private string File1(string name = "a.bin", string content = "contenu")
    {
        var p = Path.Combine(_dir, name);
        File.WriteAllText(p, content);
        return p;
    }

    private OptiCombatScanEngine Engine(Func<string, string?> scan) => new()
    {
        NativeScanJson = scan,
        NativeLoadThreatIntel = _ => 0,
        ThreatIntelDirectory = Path.Combine(_dir, "no-intel"),
    };

    private static string Json(string verdict, bool clamd = true, params (string Engine, string Name, int Score)[] dets)
    {
        var items = string.Join(",", dets.Select(d =>
            $$"""{"engine":"{{d.Engine}}","name":"{{d.Name}}","score":{{d.Score}},"explanation":"x"}"""));
        return $$"""{"target":"t","clamd":{{(clamd ? "true" : "false")}},"verdict":"{{verdict}}","severity":"Major","score":100,"detections":[{{items}}]}""";
    }

    [Fact]
    public async Task Malicious_verdict_becomes_one_threat_named_after_the_best_detection()
    {
        var file = File1(content: "12345");
        var engine = Engine(_ => Json("Malicious", true,
            ("heuristics", "Heur.Low", 20), ("reputation", "MalwareBazaar:Emotet", 100), ("ioc", "IOC.ThreatFox", 90)));
        var reports = new List<ScanProgress>();

        var result = await engine.ScanFileAsync(file, new SyncProgress(reports.Add));

        var t = Assert.Single(result.Threats);
        Assert.Equal("MalwareBazaar:Emotet", t.VirusName);
        Assert.Equal("MalwareBazaar", t.DetectedBy);
        Assert.Equal(5, t.FileSize);
        Assert.Equal(ThreatStatus.Detected, t.Status);
        Assert.Equal(ScanStatus.Completed, result.Status);
        Assert.Contains(reports, r => r.Phase == ScanPhase.ThreatFound);
    }

    [Theory]
    [InlineData("Suspicious")]
    [InlineData("Clean")]
    [InlineData("Inconclusive")]
    public async Task Non_malicious_verdicts_are_not_threats(string verdict)
    {
        var result = await Engine(_ => Json(verdict, true, ("heuristics", "Heur", 60))).ScanFileAsync(File1());
        Assert.Empty(result.Threats);
        Assert.Equal(1, result.FilesScanned);
    }

    [Fact]
    public async Task Missing_detections_or_clamd_flag_fall_back_to_verdict_name()
    {
        var result = await Engine(_ => """{"verdict":"Malicious","clamd":false}""").ScanFileAsync(File1());
        var t = Assert.Single(result.Threats);
        Assert.Equal("Malicious", t.VirusName);
        Assert.Equal("optiCombat", t.DetectedBy);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("pas du json")]
    public async Task Empty_or_invalid_json_is_treated_as_clean(string? json)
    {
        var result = await Engine(_ => json).ScanFileAsync(File1());
        Assert.Empty(result.Threats);
        Assert.Equal(ScanStatus.Completed, result.Status);
    }

    [Fact]
    public async Task Missing_or_blocked_native_library_marks_the_scan_as_error()
    {
        var r1 = await Engine(_ => throw new DllNotFoundException("opticombat")).ScanFileAsync(File1());
        Assert.Equal(ScanStatus.Error, r1.Status);
        Assert.Equal("opticombat_engine.dll introuvable", r1.ErrorMessage);

        var r2 = await Engine(_ => throw new FileLoadException("bloquée")).ScanFileAsync(File1());
        Assert.Equal(ScanStatus.Error, r2.Status);
        Assert.Contains("bloquée", r2.ErrorMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Folder_scan_walks_the_tree_and_applies_exclusions()
    {
        File1("a.bin");
        File1("skip.bin");
        Directory.CreateDirectory(Path.Combine(_dir, "sub"));
        File.WriteAllText(Path.Combine(_dir, "sub", "c.bin"), "c");
        var seen = new List<string>();
        var engine = Engine(p => { lock (seen) seen.Add(Path.GetFileName(p)); return Json("Malicious", true, ("yara", "Rule", 80)); });
        engine.ExclusionFilter = p => p.EndsWith("skip.bin", StringComparison.Ordinal);

        var result = await engine.ScanFolderAsync(_dir);

        Assert.Equal(new[] { "a.bin", "c.bin" }, seen.OrderBy(x => x).ToArray());
        Assert.Equal(1, result.FilesSkipped);
        Assert.Equal(2, result.Threats.Count);
        Assert.All(result.Threats, t => Assert.Equal("YARA", t.DetectedBy));
        Assert.Equal(ScanType.Folder, result.Type);
    }

    [Fact]
    public async Task Missing_folder_and_cancellation_are_handled()
    {
        var engine = Engine(_ => Json("Clean"));
        var missing = await engine.ScanFolderAsync(Path.Combine(_dir, "absent"));
        Assert.Equal(0, missing.FilesScanned);
        Assert.Equal(ScanStatus.Completed, missing.Status);

        File1("x.bin");
        using var cts = new CancellationTokenSource();
        var blocking = Engine(_ => { cts.Cancel(); return Json("Clean"); });
        File1("y.bin");
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => blocking.ScanFolderAsync(_dir, ct: cts.Token));
    }

    [Fact]
    public async Task Quick_scan_runs_without_native_library()
    {
        var engine = Engine(_ => Json("Clean"));
        engine.ExclusionFilter = _ => true; // n'analyse rien : on vérifie l'orchestration
        var result = await engine.QuickScanAsync();
        Assert.Equal(ScanType.QuickScan, result.Type);
        Assert.Equal(0, result.FilesScanned);
    }

    [Fact]
    public void Decisive_detection_detection()
    {
        using var decisive = System.Text.Json.JsonDocument.Parse(Json("Malicious", true, ("clamav", "Sig", 100)));
        using var heuristic = System.Text.Json.JsonDocument.Parse(Json("Malicious", true, ("sandbox", "S", 100), ("ml", "M", 40)));
        Assert.True(OptiCombatScanEngine.HasDecisiveDetection(decisive.RootElement));
        Assert.False(OptiCombatScanEngine.HasDecisiveDetection(heuristic.RootElement));
    }

    [Fact]
    public async Task Native_library_absent_reports_unavailable()
    {
        var engine = new OptiCombatScanEngine();
        // Le binaire de test ne contient pas opticombat_engine.dll copiée sous ce nom : repli ClamAV annoncé.
        if (!File.Exists(Path.Combine(AppContext.BaseDirectory, "opticombat_engine.dll")))
        {
            Assert.False(engine.IsAvailable);
            Assert.Contains("ClamAV", await engine.GetVersionAsync(), StringComparison.Ordinal);
        }
    }

    private sealed class SyncProgress(Action<ScanProgress> onReport) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value)
        {
            lock (this)
                onReport(value);
        }
    }
}
