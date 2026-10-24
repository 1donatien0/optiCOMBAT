using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary>Exécution réelle d'un processus « winget » factice (outil FakeTool).</summary>
public sealed class WingetProcessTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "oc_winget_" + Guid.NewGuid().ToString("N"));
    private readonly string _winget;

    public WingetProcessTests() => _winget = FakeTools.Install(_dir, "winget.exe");

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private const string UpgradeTable =
        "Name                Id                 Version   Available  Source\n" +
        "----------------------------------------------------------------\n" +
        "Git                 Git.Git            2.40.0    2.47.0     winget\n" +
        "7-Zip               7zip.7zip          23.01     24.08      winget\n" +
        "2 upgrades available.\n";

    private static string ListTable(string id, params string[] versions)
    {
        var lines = "Name                Id                 Version   Source\n" +
                    "-----------------------------------------------------\n";
        foreach (var v in versions)
            lines += $"Pkg                 {id,-18} {v,-9} winget\n";
        return lines;
    }

    private static WingetPackageUpdate Pkg(string id, string available = "2.47.0") =>
        new() { Name = id, Id = id, InstalledVersion = "1.0", AvailableVersion = available };

    [Fact]
    public async Task GetAvailableUpdates_parses_the_process_output()
    {
        FakeTools.Script(_winget, stdout: UpgradeTable);
        var svc = new WingetUpdateService(_winget);

        Assert.Equal(_winget, svc.ResolveWingetPath());
        var updates = await svc.GetAvailableUpdatesAsync();

        Assert.Equal(new[] { "Git.Git", "7zip.7zip" }, updates.Select(u => u.Id).ToArray());
        var call = Assert.Single(FakeTools.Calls(_winget));
        Assert.Equal("upgrade", call[0]);
        Assert.Contains("--include-unknown", call);
    }

    [Fact]
    public async Task Upgrade_success_then_removes_leftover_versions()
    {
        FakeTools.Script(_winget, "upgrade", stdout: "Installation réussie");
        FakeTools.Script(_winget, "list", stdout: ListTable("Git.Git", "2.40.0", "2.47.0"));
        FakeTools.Script(_winget, "uninstall", stdout: "Désinstallé");
        var svc = new WingetUpdateService(_winget);
        var lines = new List<string>();
        var completed = new List<WingetUpgradeResult>();

        var results = await svc.UpgradePackagesAsync(
            new[] { Pkg("Git.Git") }, lines.Add, new SyncProgress<WingetUpgradeResult>(completed.Add));

        var r = Assert.Single(results);
        Assert.Equal(WingetUpgradeStatus.Succeeded, r.Status);
        Assert.True(r.IsResolved);
        Assert.Single(completed);
        Assert.Contains(lines, l => l.Contains("Installation réussie", StringComparison.Ordinal));
        var calls = FakeTools.Calls(_winget);
        Assert.Equal(new[] { "upgrade", "list", "uninstall" }, calls.Select(c => c[0]).ToArray());
        Assert.Contains("2.40.0", calls[2]);
    }

    [Fact]
    public async Task Failed_uninstall_is_logged_and_side_by_side_runtimes_are_left_alone()
    {
        FakeTools.Script(_winget, "upgrade");
        FakeTools.Script(_winget, "list", stdout: ListTable("Git.Git", "2.40.0", "2.47.0"));
        FakeTools.Script(_winget, "uninstall", exit: 1, stderr: "refus");
        var svc = new WingetUpdateService(_winget);
        var lines = new List<string>();

        await svc.UpgradePackagesAsync(
            new[] { Pkg("Git.Git"), Pkg("Microsoft.VCRedist.2015+.x64"), Pkg("Unknown.Pkg", "Unknown") },
            lines.Add);

        var calls = FakeTools.Calls(_winget);
        // Git : upgrade + list + uninstall ; VCRedist : upgrade seul ; version inconnue : upgrade seul.
        Assert.Equal(new[] { "upgrade", "list", "uninstall", "upgrade", "upgrade" }, calls.Select(c => c[0]).ToArray());
        Assert.Contains(lines, l => l.Contains("refus", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Failed_upgrade_keeps_the_package_and_skips_cleanup()
    {
        FakeTools.Script(_winget, exit: 1);
        var results = await new WingetUpdateService(_winget).UpgradePackagesAsync(new[] { Pkg("Git.Git") }, _ => { });
        Assert.Equal(WingetUpgradeStatus.Failed, Assert.Single(results).Status);
        Assert.Single(FakeTools.Calls(_winget));
    }

    [Fact]
    public async Task UpgradeAll_runs_once_then_cleans_listed_packages()
    {
        FakeTools.Script(_winget, "upgrade");
        FakeTools.Script(_winget, "list", stdout: ListTable("Git.Git", "2.47.0"));
        var svc = new WingetUpdateService(_winget);

        var code = await svc.UpgradeAllAsync(_ => { }, new[] { Pkg("Git.Git") });

        Assert.Equal(0, code);
        var calls = FakeTools.Calls(_winget);
        Assert.Contains("--all", calls[0]);
        // Seule la version à garder est installée : rien à désinstaller.
        Assert.Equal(new[] { "upgrade", "list" }, calls.Select(c => c[0]).ToArray());
    }

    [Fact]
    public async Task Cancellation_stops_before_the_next_package()
    {
        FakeTools.Script(_winget);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new WingetUpdateService(_winget).UpgradePackagesAsync(new[] { Pkg("Git.Git") }, _ => { }, null, cts.Token));
        Assert.Empty(FakeTools.Calls(_winget));
    }

    [Fact]
    public void Missing_executable_is_handled()
    {
        var missing = Path.Combine(_dir, "absent", "winget.exe");
        var svc = new WingetUpdateService(missing);
        // Chemin imposé absent : la résolution retombe sur la recherche système (peut trouver un vrai winget).
        var resolved = svc.ResolveWingetPath();
        Assert.NotEqual(missing, resolved);
    }

    [Fact]
    public async Task Old_winget_without_uninstall_previous_is_retried()
    {
        if (!OperatingSystem.IsWindows())
            return; // codes de sortie 32 bits : Windows seulement
        FakeTools.Script(_winget, "1", exit: unchecked((int)0x8A150010));
        FakeTools.Script(_winget, "2", exit: 0);
        FakeTools.Script(_winget, "list", stdout: ListTable("Git.Git", "2.47.0"));
        var results = await new WingetUpdateService(_winget).UpgradePackagesAsync(new[] { Pkg("Git.Git") }, _ => { });
        Assert.Equal(WingetUpgradeStatus.Succeeded, Assert.Single(results).Status);
        var calls = FakeTools.Calls(_winget);
        Assert.Contains("--uninstall-previous", calls[0]);
        Assert.DoesNotContain("--uninstall-previous", calls[1]);
    }

    /// <summary>Progress synchrone (Progress&lt;T&gt; poste sur le pool : non déterministe).</summary>
    private sealed class SyncProgress<T>(Action<T> onReport) : IProgress<T>
    {
        public void Report(T value) => onReport(value);
    }
}
