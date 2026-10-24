using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.Tests;

/// <summary>
/// Nettoyage exécuté pour de vrai, mais sur une arborescence factice : racines, corbeille,
/// script élevé et vidage DNS sont remplacés (aucun cache réel du poste n'est touché).
/// </summary>
[Collection("OpticombatPrefs")]
public sealed class SystemCleanIsolatedTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "opticombat_clean_" + Guid.NewGuid().ToString("N"));
    private readonly CleanRoots _roots;
    private int _recycleCalls;
    private int _dnsCalls;
    private readonly List<IReadOnlyList<string>> _elevated = new();
    private bool _elevatedResult = true;

    public SystemCleanIsolatedTests()
    {
        LocalizationService.ApplyCulture("fr-FR");
        _roots = new CleanRoots(
            Path.Combine(_root, "local"),
            Path.Combine(_root, "roaming"),
            Path.Combine(_root, "windows"),
            Path.Combine(_root, "usertemp"));
        SystemCleanService.RootsOverride = _roots;
        SystemCleanService.EmptyRecycleBinOverride = () => _recycleCalls++;
        SystemCleanService.FlushDnsOverride = () => { _dnsCalls++; return true; };
        SystemCleanService.ElevatedBatchOverride = cmds =>
        {
            _elevated.Add(cmds);
            if (_elevatedResult)
                Directory.Delete(Path.Combine(_roots.SystemRoot, "SoftwareDistribution", "Download"), recursive: true);
            return _elevatedResult;
        };
    }

    public void Dispose()
    {
        SystemCleanService.RootsOverride = null;
        SystemCleanService.EmptyRecycleBinOverride = null;
        SystemCleanService.FlushDnsOverride = null;
        SystemCleanService.ElevatedBatchOverride = null;
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
    }

    private string Put(int bytes, params string[] segments)
    {
        var path = Path.Combine(segments);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, new byte[bytes]);
        return path;
    }

    private static readonly string[][] ChromiumCaches =
    [
        ["Microsoft", "Edge", "User Data", "Default", "Cache"],
        ["Google", "Chrome", "User Data", "Default", "Cache"],
        ["BraveSoftware", "Brave-Browser", "User Data", "Default", "Cache"],
        ["Opera Software", "Opera Stable", "Cache"],
        ["Vivaldi", "User Data", "Default", "Cache"],
        ["Arc", "User Data", "Default", "Cache"],
    ];

    private void BuildTree()
    {
        Put(100, _roots.SystemRoot, "Temp", "a.tmp");
        Put(200, _roots.UserTemp, "sub", "b.tmp");
        Put(300, _roots.SystemRoot, "Logs", "cbs.log");
        Put(400, _roots.SystemRoot, "SoftwareDistribution", "Download", "kb.cab");
        foreach (var cache in ChromiumCaches)
        {
            Put(10, [_roots.LocalApp, .. cache, "data_0"]);
            Put(5, [_roots.LocalApp, .. cache[..^1], "History"]);
        }
        Put(50, _roots.LocalApp, "Mozilla", "Firefox", "Profiles", "abcd.default-release", "cache2", "entries", "x");
    }

    private static CleanSelection Everything() => new()
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

    [Fact]
    public void Analyze_measures_each_target_in_the_fake_tree()
    {
        BuildTree();
        var r = SystemCleanService.Analyze(Everything());

        Assert.Equal(100, r.TempWinBytes);
        Assert.Equal(200, r.TempUserBytes);
        Assert.Equal(300, r.LogsBytes);
        Assert.Equal(400, r.WuCacheBytes);
        Assert.Equal(10, r.EdgeBytes);
        Assert.Equal(10, r.ArcBytes);
        Assert.Equal(50, r.FirefoxBytes);
        Assert.Equal(6 * 5, r.HistoryBytes);
        Assert.Equal(1000, r.SystemTotal);
        Assert.Equal(6 * 10 + 50 + 30, r.BrowserTotal);
    }

    [Fact]
    public void Execute_cleans_everything_selected_and_reports_the_total()
    {
        BuildTree();
        var lines = new List<string>();

        var result = SystemCleanService.Execute(Everything(), lines.Add);

        Assert.Equal(100 + 200 + 300 + 400 + 60 + 50 + 30, result.BytesFreed);
        Assert.Empty(Directory.GetFiles(_root, "*", SearchOption.AllDirectories));
        Assert.Equal(1, _recycleCalls);
        Assert.Equal(1, _dnsCalls);
        var commands = Assert.Single(_elevated);
        Assert.NotEmpty(commands);
        Assert.Equal(result.LogLines, lines);
        Assert.Contains(lines, l => l.Contains("Firefox", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Denied_elevation_keeps_the_update_cache_and_says_so()
    {
        BuildTree();
        _elevatedResult = false;

        var result = SystemCleanService.Execute(new CleanSelection { WUCache = true });

        Assert.Equal(0, result.BytesFreed);
        Assert.True(File.Exists(Path.Combine(_roots.SystemRoot, "SoftwareDistribution", "Download", "kb.cab")));
        Assert.Contains(LocalizationService.GetString("Clean_LogWUDenied"), result.LogLines);
    }

    [Fact]
    public void Dns_flush_failure_is_not_reported_as_success()
    {
        SystemCleanService.FlushDnsOverride = () => false;
        var result = SystemCleanService.Execute(new CleanSelection { Dns = true });
        Assert.DoesNotContain(LocalizationService.GetString("Clean_LogDnsFlushed"), result.LogLines);
    }

    [Fact]
    public void History_only_selection_counts_as_a_selection()
    {
        Assert.True(new CleanSelection { History = true }.AnySelected);
        Assert.False(new CleanSelection().AnySelected);
    }

    [Fact]
    public void Firefox_cache_is_found_through_profiles_ini_when_no_default_profile_has_one()
    {
        Directory.CreateDirectory(Path.Combine(_roots.LocalApp, "Mozilla", "Firefox", "Profiles", "zzzz.default"));
        Put(70, _roots.LocalApp, "Mozilla", "Firefox", "Profiles", "custom.work", "cache2", "c");
        Put(1, _roots.Roaming, "Mozilla", "Firefox", "profiles.ini");
        File.WriteAllLines(Path.Combine(_roots.Roaming, "Mozilla", "Firefox", "profiles.ini"),
            ["[Profile0]", "Path=", "Path=Profiles/absent", "Path=Profiles/custom.work"]);

        Assert.Equal(70, SystemCleanService.Analyze(new CleanSelection { Firefox = true }).FirefoxBytes);
    }

    [Fact]
    public void Firefox_without_profiles_measures_zero()
    {
        Assert.Equal(0, SystemCleanService.Analyze(new CleanSelection { Firefox = true }).FirefoxBytes);
        Directory.CreateDirectory(Path.Combine(_roots.LocalApp, "Mozilla", "Firefox", "Profiles", "p.default"));
        Assert.Equal(0, SystemCleanService.Analyze(new CleanSelection { Firefox = true }).FirefoxBytes);
    }

    [Fact]
    public void Locked_history_file_is_counted_and_reported()
    {
        if (!OperatingSystem.IsWindows())
            return; // le verrouillage exclusif n'empêche pas la suppression hors Windows
        var history = Put(5, [_roots.LocalApp, .. ChromiumCaches[1][..^1], "History"]);
        using var hold = new FileStream(history, FileMode.Open, FileAccess.Read, FileShare.None);

        var result = SystemCleanService.Execute(new CleanSelection { Chrome = true, History = true });

        Assert.Contains(LocalizationService.Format("Clean_LogHistoryLocked", 1), result.LogLines);
    }

    [Fact]
    public async Task CleanViewModel_analyze_then_clean_saves_a_session()
    {
        using var iso = new IsolatedServices();
        BuildTree();
        var vm = new CleanViewModel(iso.Container)
        {
            Logs = true,
            History = true,
            WUCache = true,
            Dns = true,
        };

        await vm.AnalyzeAsync();
        Assert.True(vm.CanClean);
        Assert.NotEqual(ByteSizeFormat.Format(0), vm.TotalSize);

        await vm.CleanAsync();

        Assert.False(vm.CanClean);
        Assert.False(vm.IsBusy);
        Assert.Equal(ByteSizeFormat.Format(0), vm.TotalSize);
        Assert.Contains(LocalizationService.GetString("Clean_LogCleanEnd"), vm.LogText, StringComparison.Ordinal);
        Assert.True(vm.HasLog);
        Assert.Empty(Directory.GetFiles(_roots.SystemRoot, "*", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task CleanViewModel_reports_a_failure_without_staying_busy()
    {
        using var iso = new IsolatedServices();
        SystemCleanService.EmptyRecycleBinOverride = () => throw new IOException("corbeille indisponible");
        var vm = new CleanViewModel(iso.Container)
        {
            TempWin = false,
            TempUser = false,
            Edge = false,
            Chrome = false,
            Firefox = false,
        };

        await vm.AnalyzeAsync(); // la corbeille seule suffit à autoriser le nettoyage
        await vm.CleanAsync();

        Assert.False(vm.IsBusy);
        Assert.Contains("corbeille indisponible", vm.LogText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CleanViewModel_without_selection_only_shows_the_hint()
    {
        using var iso = new IsolatedServices();
        var vm = new CleanViewModel(iso.Container)
        {
            TempWin = false,
            TempUser = false,
            Recycle = false,
            Edge = false,
            Chrome = false,
            Firefox = false,
        };

        await vm.AnalyzeAsync();
        await vm.CleanAsync(); // refusé : rien d'analysé

        Assert.False(vm.CanClean);
        Assert.Contains(LocalizationService.GetString("Clean_LogHint"), vm.LogText, StringComparison.Ordinal);
    }
}
