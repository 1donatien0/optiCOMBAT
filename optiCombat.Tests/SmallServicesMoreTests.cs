using System.Text;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

public sealed class CompositeClamAvBackendMoreTests
{
    private sealed class Backend(string name, bool throws = false) : IClamAvOrchestratorBackend
    {
        public int Calls { get; private set; }

        public bool IsClamAvInstalled() => name == "clamscan";

        private Task<ScanResult> Run(string target)
        {
            Calls++;
            if (throws)
                throw new InvalidOperationException("clamd tombé");
            return Task.FromResult(new ScanResult { TargetPath = target, ErrorMessage = name });
        }

        public Task<ScanResult> ScanFileAsync(string filePath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) => Run(filePath);

        public Task<ScanResult> ScanFolderAsync(string folderPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) => Run(folderPath);

        public Task<ScanResult> ScanFileListAsync(IReadOnlyList<string> files, string targetPath, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) => Run(targetPath);
    }

    [Fact]
    public async Task Folder_scan_prefers_clamd_then_falls_back()
    {
        var clamd = new Backend("clamd");
        var clamscan = new Backend("clamscan");
        var composite = new CompositeClamAvBackend(_ => Task.FromResult(true), clamd, clamscan);

        Assert.Equal("clamd", (await composite.ScanFolderAsync("d")).ErrorMessage);
        Assert.True(composite.IsClamAvInstalled());

        var failing = new CompositeClamAvBackend(_ => Task.FromResult(true), new Backend("clamd", throws: true), clamscan);
        Assert.Equal("clamscan", (await failing.ScanFolderAsync("d")).ErrorMessage);
        Assert.Equal("clamscan", failing.ActiveEngine);

        var notReady = new CompositeClamAvBackend(_ => Task.FromResult(false), clamd, clamscan);
        Assert.Equal("clamscan", (await notReady.ScanFolderAsync("d")).ErrorMessage);
        Assert.Equal("clamscan", (await notReady.ScanFileListAsync(new[] { "a" }, "t")).ErrorMessage);
        Assert.Equal("clamscan", (await failing.ScanFileAsync("f")).ErrorMessage);
    }
}

public sealed class AtomicFileMoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "oc_atomic_" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    [Fact]
    public void Writes_with_encoding_into_new_directory_and_reads_backup_when_main_is_corrupt()
    {
        var path = Path.Combine(_dir, "sub", "data.txt");
        AtomicFile.WriteAllText(path, "été", Encoding.Unicode);
        Assert.Equal("été", File.ReadAllText(path, Encoding.Unicode));

        File.WriteAllText(path, "corrompu");
        File.WriteAllText(path + ".bak", "42");
        Assert.Equal(42, AtomicFile.ReadWithBackup(path, int.Parse, -1));

        File.WriteAllText(path + ".bak", "aussi corrompu");
        Assert.Equal(-1, AtomicFile.ReadWithBackup(path, int.Parse, -1));
        Assert.Equal(-2, AtomicFile.ReadWithBackup(Path.Combine(_dir, "absent"), int.Parse, -2));
    }
}

[Collection("OpticombatPrefs")]
public sealed class UserPreferencesMoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "oc_prefsm_" + Guid.NewGuid().ToString("N"));

    public UserPreferencesMoreTests() => OpticombatDataRoots.TestRootOverride = _root;

    public void Dispose()
    {
        OpticombatDataRoots.TestRootOverride = TestDataRoot.Session;
        try { Directory.Delete(_root, true); } catch { }
    }

    [Fact]
    public void Recent_targets_keep_five_and_full_scan_updates_date()
    {
        var prefs = new UserPreferences();
        for (var i = 0; i < 7; i++)
            prefs.AddRecentTarget($"/cible/{i}", ScanType.Folder);
        Assert.Equal(5, prefs.RecentTargets.Count);
        Assert.Equal("/cible/6", prefs.RecentTargets[0].Path);
        Assert.Equal("/cible/6", prefs.LastScanPath);

        prefs.IncrementScanCount(ScanType.FullScan);
        Assert.Equal(1, prefs.TotalScansCount);
        Assert.NotNull(prefs.LastFullScanDate);
    }
}
