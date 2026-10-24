using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Services.OptiCombat;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary><see cref="ScanOrchestrator"/> quand le cœur natif est activé (appel natif simulé).</summary>
public sealed class OrchestratorNativeTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "oc_orchn_" + Guid.NewGuid().ToString("N"));
    private readonly ScriptedClamBackend _clam = new();
    private readonly UserPreferences _prefs = new() { UseNativeEngine = true };
    private readonly ExclusionSettings _excl = new();
    private readonly List<string> _nativeCalls = new();

    public OrchestratorNativeTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private string Sample(string name)
    {
        var p = Path.Combine(_dir, name);
        File.WriteAllText(p, "x");
        return p;
    }

    private OptiCombatScanEngine Native(bool available = true) => new()
    {
        AvailabilityOverride = () => available,
        NativeLoadThreatIntel = _ => 0,
        ThreatIntelDirectory = Path.Combine(_dir, "no-intel"),
        NativeScanJson = p =>
        {
            lock (_nativeCalls)
                _nativeCalls.Add(Path.GetFileName(p));
            return p.EndsWith("bad.exe", StringComparison.Ordinal)
                ? """{"verdict":"Malicious","clamd":true,"detections":[{"engine":"clamav","name":"Win.Native","score":100}]}"""
                : """{"verdict":"Clean","clamd":true,"detections":[]}""";
        },
    };

    private ScanOrchestrator Create(OptiCombatScanEngine native, bool? optIn = null) =>
        new(_clam, new NoopYaraBackend(), new FixedPreferencesAccessor(_prefs), new FixedExclusionsAccessor(_excl), native, optIn);

    [Fact]
    public async Task Native_engine_handles_file_folder_background_and_list_scans()
    {
        var bad = Sample("bad.exe");
        var ok = Sample("ok.txt");
        var orch = Create(Native());

        Assert.True(orch.IsOptiCombatAvailable);
        Assert.True(orch.IsClamAvAvailable);
        Assert.Equal("Win.Native", Assert.Single((await orch.ScanFileAsync(bad)).Threats).VirusName);
        Assert.Single((await orch.ScanFolderAsync(_dir)).Threats);
        Assert.Single((await orch.ScanFolderBackgroundAsync(_dir, ScanType.RemovableDrive)).Threats);

        var list = await orch.ScanFileListAsync(new[] { bad, ok, ok }, _dir, ScanType.RemovableDrive);
        Assert.Equal(ScanType.RemovableDrive, list.Type);
        Assert.Equal(2, list.FilesScanned);
        Assert.Single(list.Threats);
        Assert.Equal(0, _clam.Calls);
    }

    [Fact]
    public async Task Native_quick_scan_is_delegated()
    {
        // Pas de scan complet ici : il parcourrait tous les disques fixes du poste de CI.
        var native = Native();
        native.ExclusionFilter = _ => true;
        var orch = Create(native);
        Assert.Equal(ScanType.QuickScan, (await orch.QuickScanAsync()).Type);
        Assert.Equal(0, _clam.Calls);
    }

    [Fact]
    public async Task Opt_in_flag_and_preference_control_the_native_engine()
    {
        var bad = Sample("bad.exe");
        var forcedOff = Create(Native(), optIn: false);
        Assert.False(forcedOff.IsOptiCombatAvailable);
        await forcedOff.ScanFileAsync(bad);
        Assert.Equal(1, _clam.Calls);

        _prefs.UseNativeEngine = false;
        Assert.False(Create(Native()).IsOptiCombatAvailable);
        Assert.True(Create(Native(), optIn: true).IsOptiCombatAvailable);
        Assert.False(Create(Native(available: false), optIn: true).IsOptiCombatAvailable);
    }

    [Fact]
    public async Task Native_file_list_honours_cancellation()
    {
        var a = Sample("a.txt");
        var b = Sample("b.txt");
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Create(Native()).ScanFileListAsync(new[] { a, b }, _dir, ct: cts.Token));
    }

    [Fact]
    public async Task Pipeline_quick_scan_without_native_engine_aggregates_targets()
    {
        var orch = Create(Native(), optIn: false);
        _clam.ListFiles = false;
        var result = await orch.QuickScanAsync();
        Assert.Equal(ScanType.QuickScan, result.Type);
    }
}

public sealed class ClamAvDatabaseSeedingTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "oc_seed_" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_root, true); } catch { }
    }

    [Fact]
    public void Signatures_are_copied_once_into_the_writable_directory()
    {
        var src = Path.Combine(_root, "pf", "database");
        var dst = Path.Combine(_root, "local", "database");
        Directory.CreateDirectory(src);
        Directory.CreateDirectory(dst);
        File.WriteAllText(Path.Combine(src, "main.cvd"), "m");
        File.WriteAllText(Path.Combine(src, "daily.cld"), "d");
        File.WriteAllText(Path.Combine(src, "notes.txt"), "ignoré");

        ClamAvDatabasePaths.TrySeedSignatureFiles(src, dst);

        Assert.True(File.Exists(Path.Combine(dst, "main.cvd")));
        Assert.True(File.Exists(Path.Combine(dst, "daily.cld")));
        Assert.False(File.Exists(Path.Combine(dst, "notes.txt")));
        Assert.True(File.Exists(Path.Combine(dst, ".opticombat-db-seeded")));

        // Marqueur présent : une nouvelle signature source n'est plus copiée.
        File.WriteAllText(Path.Combine(src, "bytecode.cvd"), "b");
        ClamAvDatabasePaths.TrySeedSignatureFiles(src, dst);
        Assert.False(File.Exists(Path.Combine(dst, "bytecode.cvd")));
    }

    [Fact]
    public void Existing_database_or_missing_source_only_writes_the_marker()
    {
        var dst = Path.Combine(_root, "has-db");
        Directory.CreateDirectory(dst);
        File.WriteAllText(Path.Combine(dst, "daily.cvd"), "d");
        ClamAvDatabasePaths.TrySeedSignatureFiles(Path.Combine(_root, "src"), dst);
        Assert.True(File.Exists(Path.Combine(dst, ".opticombat-db-seeded")));

        var empty = Path.Combine(_root, "empty");
        Directory.CreateDirectory(empty);
        ClamAvDatabasePaths.TrySeedSignatureFiles(Path.Combine(_root, "absent"), empty);
        Assert.True(File.Exists(Path.Combine(empty, ".opticombat-db-seeded")));
    }

    [Fact]
    public void Parent_database_folder_is_preferred_when_bin_has_none()
    {
        var bin = Path.Combine(_root, "clamav", "x64");
        Directory.CreateDirectory(bin);
        var parentDb = Path.Combine(_root, "clamav", "database");
        Directory.CreateDirectory(parentDb);
        Assert.Equal(Path.GetFullPath(parentDb), ClamAvDatabasePaths.ResolvePreferredDatabaseDir(bin));
    }
}
