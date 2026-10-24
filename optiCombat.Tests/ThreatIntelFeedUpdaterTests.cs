using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Text;
using optiCombat.Services;
using optiCombat.Services.OptiCombat;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

public sealed class ThreatIntelFeedUpdaterTests : IDisposable
{
    private const string Key = "0123456789abcdefABCDEF0123456789abcdef0123456789";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "oc_ti_" + Guid.NewGuid().ToString("N"));
    private readonly FakeHttpHandler _http = new();
    private readonly UserPreferences _prefs = new() { AbuseChAuthKey = Key };
    private DateTime _now = new(2026, 10, 23, 12, 0, 0, DateTimeKind.Utc);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private ThreatIntelFeedUpdater Create() =>
        new(new FixedPreferencesAccessor(_prefs), _dir, new HttpClient(_http), () => _now);

    private static string Url(int feed, string key = Key) =>
        ThreatIntelFeedUpdater.BuildUrl(ThreatIntelFeedUpdater.Feeds[feed], key);

    private static HttpResponseMessage Text(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "text/csv") };

    private static HttpResponseMessage Bytes(byte[] body) =>
        new(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };

    private const string BazaarCsv =
        "################################################################\n" +
        "# MalwareBazaar recent malware samples (CSV)\n" +
        "\"2026-10-23 10:00:00\", \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"m\", \"s\", \"r\", \"a.exe\", \"exe\", \"mime\", \"AgentTesla\", \"n/a\"\n" +
        "\"2026-10-23 09:00:00\", \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\", \"m\", \"s\", \"r\", \"b.exe\", \"exe\", \"mime\", \"Formbook\", \"n/a\"\n";

    private const string UrlhausCsv =
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n" +
        "\"1\",\"2026-10-23 10:00:00\",\"http://drop.example.net/a.exe\",\"online\",\"\",\"malware_download\",\"exe\",\"https://urlhaus.abuse.ch/url/1/\",\"r\"\n";

    private const string ThreatFoxCsv =
        "# \"first_seen_utc\",\"ioc_id\",\"ioc_value\",\"ioc_type\"\n" +
        "\"2026-10-23 10:00:00\", \"1\", \"c2.example.com\", \"domain\", \"botnet_cc\", \"win.x\", \"None\", \"XWorm\", \"\", \"90\"\n" +
        "\"2026-10-23 09:00:00\", \"2\", \"1.2.3.4:4444\", \"ip:port\", \"botnet_cc\", \"win.y\", \"None\", \"Remcos\", \"\", \"75\"\n";

    private static byte[] Zip(string entryName, string content)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var e = zip.CreateEntry(entryName);
            using var w = new StreamWriter(e.Open(), new UTF8Encoding(false));
            w.Write(content);
        }
        return ms.ToArray();
    }

    private void RouteAllFeeds()
    {
        _http.Routes[Url(0)] = () => Text(BazaarCsv);
        _http.Routes[Url(1)] = () => Text(UrlhausCsv);
        _http.Routes[Url(2)] = () => Bytes(Zip("full.csv", ThreatFoxCsv));
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("short", false)]
    [InlineData("0123456789abcdef", true)]
    [InlineData("  0123456789abcdef  ", true)]
    [InlineData("0123456789abcdef/../x", false)]
    [InlineData("0123456789abcdef?q=1", false)]
    [InlineData("0123456789abcdéf0123", false)]
    public void IsValidAuthKey_accepts_only_alphanumeric_keys(string? key, bool expected) =>
        Assert.Equal(expected, ThreatIntelFeedUpdater.IsValidAuthKey(key));

    [Fact]
    public void IsValidAuthKey_rejects_overlong_keys() =>
        Assert.False(ThreatIntelFeedUpdater.IsValidAuthKey(new string('a', 129)));

    [Fact]
    public void BuildUrl_puts_the_key_in_the_path_and_Redact_hides_it()
    {
        var url = Url(2);
        Assert.Equal($"https://threatfox-api.abuse.ch/v2/files/exports/{Key}/full.csv.zip", url);
        Assert.DoesNotContain(Key, ThreatIntelFeedUpdater.Redact($"échec {url}", Key));
        Assert.Equal("x", ThreatIntelFeedUpdater.Redact("x", ""));
    }

    [Fact]
    public void Feed_file_names_match_the_rust_loader()
    {
        var names = ThreatIntelFeedUpdater.Feeds.Select(f => f.LocalFile).ToArray();
        Assert.Equal(new[] { "malwarebazaar.csv", "urlhaus.csv", "threatfox.csv" }, names);
        Assert.All(ThreatIntelFeedUpdater.Feeds, f => Assert.EndsWith(".abuse.ch", f.Host, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Without_key_no_request_is_sent()
    {
        _prefs.AbuseChAuthKey = "";
        var updater = Create();
        Assert.False(updater.HasValidAuthKey);

        var result = await updater.UpdateAsync(force: true);

        Assert.True(result.Skipped);
        Assert.True(result.Success);
        Assert.Empty(_http.Requests);
        Assert.False(Directory.Exists(_dir));
    }

    [Fact]
    public async Task Downloads_all_feeds_unzips_threatfox_and_records_the_date()
    {
        RouteAllFeeds();
        var updater = Create();
        ThreatIntelUpdateResult? raised = null;
        updater.FeedsUpdated += (_, r) => raised = r;

        var result = await updater.UpdateAsync();

        Assert.True(result.Success, result.Message);
        Assert.False(result.Skipped);
        Assert.Equal(3, result.FeedsUpdated);
        Assert.Empty(result.Errors);
        Assert.Same(result, raised);
        Assert.Equal(_now, updater.LastUpdateUtc);
        Assert.Contains("AgentTesla", File.ReadAllText(Path.Combine(_dir, "malwarebazaar.csv")));
        Assert.Contains("drop.example.net", File.ReadAllText(Path.Combine(_dir, "urlhaus.csv")));
        var tf = File.ReadAllText(Path.Combine(_dir, "threatfox.csv"));
        Assert.Contains("c2.example.com", tf);
        Assert.StartsWith("# ", tf, StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp"));
        Assert.Empty(Directory.GetFiles(_dir, "*.download"));

        // La date survit à un redémarrage (fichier méta).
        Assert.Equal(_now, Create().LastUpdateUtc);
    }

    [Fact]
    public async Task Recent_update_is_skipped_unless_forced()
    {
        RouteAllFeeds();
        var updater = Create();
        await updater.UpdateAsync();
        var before = _http.Requests.Count;

        _now = _now.AddHours(1);
        var skipped = await updater.UpdateAsync();
        Assert.True(skipped.Skipped);
        Assert.Equal(before, _http.Requests.Count);

        var forced = await updater.UpdateAsync(force: true);
        Assert.False(forced.Skipped);
        Assert.Equal(before + 3, _http.Requests.Count);

        _now = _now.AddHours(7);
        var stale = await updater.UpdateAsync();
        Assert.False(stale.Skipped);
    }

    [Fact]
    public async Task Rejected_key_keeps_previous_files_and_reports_without_leaking_the_key()
    {
        RouteAllFeeds();
        var updater = Create();
        await updater.UpdateAsync();
        var previous = File.ReadAllText(Path.Combine(_dir, "malwarebazaar.csv"));

        _http.Routes[Url(0)] = () => new HttpResponseMessage(HttpStatusCode.Unauthorized);
        _http.Routes[Url(1)] = () => new HttpResponseMessage(HttpStatusCode.Forbidden);
        _http.Routes[Url(2)] = () => new HttpResponseMessage(HttpStatusCode.InternalServerError);
        var raised = 0;
        updater.FeedsUpdated += (_, _) => raised++;

        var result = await updater.UpdateAsync(force: true);

        Assert.False(result.Success);
        Assert.Equal(0, result.FeedsUpdated);
        Assert.Equal(3, result.Errors.Count);
        Assert.Contains(result.Errors, e => e.Contains("HTTP 500", StringComparison.Ordinal));
        Assert.DoesNotContain(Key, result.Message, StringComparison.Ordinal);
        Assert.Equal(0, raised);
        Assert.Equal(previous, File.ReadAllText(Path.Combine(_dir, "malwarebazaar.csv")));
    }

    [Fact]
    public async Task Html_or_empty_response_is_not_accepted_as_a_feed()
    {
        _http.Routes[Url(0)] = () => Text("<html><body>Login required</body></html>");
        _http.Routes[Url(1)] = () => Text("# only comments\n\n");
        _http.Routes[Url(2)] = () => Bytes(Zip("readme.txt", "nothing"));
        var updater = Create();

        var result = await updater.UpdateAsync();

        Assert.False(result.Success);
        Assert.Equal(0, result.FeedsUpdated);
        Assert.Null(updater.LastUpdateUtc);
        Assert.False(File.Exists(Path.Combine(_dir, "malwarebazaar.csv")));
        Assert.False(File.Exists(Path.Combine(_dir, "urlhaus.csv")));
        Assert.False(File.Exists(Path.Combine(_dir, "threatfox.csv")));
    }

    [Fact]
    public async Task Partial_success_updates_the_working_feeds()
    {
        _http.Routes[Url(1)] = () => Text(UrlhausCsv);
        var updater = Create();
        var raised = 0;
        updater.FeedsUpdated += (_, _) => raised++;

        var result = await updater.UpdateAsync();

        Assert.False(result.Success);
        Assert.Equal(1, result.FeedsUpdated);
        Assert.Equal(2, result.Errors.Count);
        Assert.Equal(1, raised);
        Assert.True(File.Exists(Path.Combine(_dir, "urlhaus.csv")));
    }

    [Fact]
    public async Task Declared_oversize_content_is_refused()
    {
        _http.Routes[Url(0)] = () =>
        {
            var r = Text(BazaarCsv);
            r.Content.Headers.ContentLength = ThreatIntelFeedUpdater.MaxDownloadBytes + 1;
            return r;
        };
        var result = await Create().UpdateAsync();
        Assert.Contains(result.Errors, e => e.StartsWith("MalwareBazaar", StringComparison.Ordinal));
        Assert.False(File.Exists(Path.Combine(_dir, "malwarebazaar.csv")));
    }

    [Fact]
    public async Task Network_failure_is_reported_per_feed()
    {
        var handler = new ThrowingHandler(new HttpRequestException($"connexion refusée {Url(0)}"));
        var updater = new ThreatIntelFeedUpdater(new FixedPreferencesAccessor(_prefs), _dir, new HttpClient(handler), () => _now);

        var result = await updater.UpdateAsync();

        Assert.False(result.Success);
        Assert.Equal(3, result.Errors.Count);
        Assert.All(result.Errors, e => Assert.DoesNotContain(Key, e, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Cancellation_propagates()
    {
        RouteAllFeeds();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Create().UpdateAsync(ct: cts.Token));
    }

    [Fact]
    public async Task CopyCappedAsync_refuses_streams_above_the_cap()
    {
        using var src = new MemoryStream(new byte[100]);
        using var dst = new MemoryStream();
        await Assert.ThrowsAsync<ThreatIntelDownloadException>(() =>
            ThreatIntelFeedUpdater.CopyCappedAsync(src, dst, 50, CancellationToken.None));

        using var ok = new MemoryStream(new byte[40]);
        using var dst2 = new MemoryStream();
        await ThreatIntelFeedUpdater.CopyCappedAsync(ok, dst2, 50, CancellationToken.None);
        Assert.Equal(40, dst2.Length);
    }

    [Fact]
    public void CopyCsvLines_caps_data_lines_skips_overlong_and_normalizes_line_endings()
    {
        Directory.CreateDirectory(_dir);
        var target = Path.Combine(_dir, "out.csv");
        var sb = new StringBuilder();
        sb.Append("# header\r\n");
        sb.Append(new string('x', ThreatIntelFeedUpdater.MaxLineChars + 10)).Append(",y\n");
        for (var i = 0; i < 5; i++)
            sb.Append("a,").Append(i).Append("\r\n");
        sb.Append("no comma line\n");
        sb.Append("last,line"); // sans fin de ligne

        using var src = new MemoryStream(Encoding.UTF8.GetBytes(sb.ToString()));
        var n = ThreatIntelFeedUpdater.CopyCsvLines(src, target, maxDataLines: 3);

        Assert.Equal(3, n);
        var lines = File.ReadAllLines(target);
        Assert.Equal(new[] { "# header", "a,0", "a,1", "a,2" }, lines);
        Assert.DoesNotContain('\r', File.ReadAllText(target));

        using var src2 = new MemoryStream(Encoding.UTF8.GetBytes("a,1\nlast,line"));
        Assert.Equal(2, ThreatIntelFeedUpdater.CopyCsvLines(src2, target, maxDataLines: 10));
        Assert.Equal("last,line", File.ReadAllLines(target)[^1]);
    }

    [Fact]
    public async Task Concurrent_update_is_skipped()
    {
        var gate = new TaskCompletionSource();
        var handler = new GateHandler(gate.Task, () => Text(BazaarCsv));
        var updater = new ThreatIntelFeedUpdater(new FixedPreferencesAccessor(_prefs), _dir, new HttpClient(handler), () => _now);

        var first = updater.UpdateAsync();
        await Eventually.TrueAsync(() => updater.IsUpdating);
        var second = await updater.UpdateAsync();
        Assert.True(second.Skipped);

        gate.SetResult();
        var done = await first;
        Assert.False(done.Skipped);
        Assert.False(updater.IsUpdating);
    }

    [Fact]
    public async Task Auto_update_timer_toggles_and_scheduled_run_never_throws()
    {
        var updater = Create();
        Assert.False(updater.IsAutoUpdateEnabled);
        updater.EnableAutoUpdate(TimeSpan.FromHours(6));
        Assert.True(updater.IsAutoUpdateEnabled);
        updater.EnableAutoUpdate();
        Assert.True(updater.IsAutoUpdateEnabled);
        updater.DisableAutoUpdate();
        Assert.False(updater.IsAutoUpdateEnabled);

        // Toutes les routes répondent 503 : l'exécution planifiée journalise sans lever.
        await updater.RunScheduledAsync();
        _prefs.AbuseChAuthKey = "";
        await updater.RunScheduledAsync();
    }

    [Fact]
    public void Corrupt_meta_file_is_ignored()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, ".opticombat-intel-meta.txt"), "pas une date");
        Assert.Null(Create().LastUpdateUtc);
    }

    [Fact]
    public void Default_directory_is_under_local_app_data()
    {
        Assert.EndsWith("threat_intel", ThreatIntelFeedUpdater.DefaultDirectory, StringComparison.Ordinal);
        var updater = new ThreatIntelFeedUpdater(new FixedPreferencesAccessor(new UserPreferences()));
        // Pas d'égalité stricte : d'autres collections redirigent les racines de données en parallèle.
        Assert.EndsWith("threat_intel", updater.FeedDirectory, StringComparison.Ordinal);
        Assert.False(updater.HasValidAuthKey);
    }

    private sealed class ThrowingHandler(Exception ex) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromException<HttpResponseMessage>(ex);
    }

    private sealed class GateHandler(Task gate, Func<HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            return respond();
        }
    }
}

public sealed class OptiCombatThreatIntelBridgeTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "oc_bridge_" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    [Fact]
    public void Missing_directory_loads_nothing_without_calling_native()
    {
        var calls = 0;
        var engine = new OptiCombatScanEngine
        {
            ThreatIntelDirectory = _dir,
            NativeLoadThreatIntel = _ => { calls++; return 9; },
        };
        Assert.Equal(-1, engine.ThreatIntelEntries);
        Assert.Equal(0, engine.ReloadThreatIntel());
        Assert.Equal(0, calls);
        Assert.Equal(0, engine.ThreatIntelEntries);
    }

    [Fact]
    public void Loads_once_then_again_after_invalidation()
    {
        Directory.CreateDirectory(_dir);
        var seen = new List<string>();
        var engine = new OptiCombatScanEngine
        {
            ThreatIntelDirectory = _dir,
            NativeLoadThreatIntel = d => { seen.Add(d); return 42; },
        };

        engine.EnsureThreatIntelLoaded();
        engine.EnsureThreatIntelLoaded();
        Assert.Single(seen);
        Assert.Equal(_dir, seen[0]);
        Assert.Equal(42, engine.ThreatIntelEntries);

        engine.InvalidateThreatIntel();
        engine.EnsureThreatIntelLoaded();
        Assert.Equal(2, seen.Count);
    }

    [Fact]
    public void Native_refusal_and_missing_dll_are_reported_not_thrown()
    {
        Directory.CreateDirectory(_dir);
        var engine = new OptiCombatScanEngine { ThreatIntelDirectory = _dir, NativeLoadThreatIntel = _ => -1 };
        Assert.Equal(-1, engine.ReloadThreatIntel());

        engine.NativeLoadThreatIntel = _ => throw new DllNotFoundException("opticombat");
        Assert.Equal(-1, engine.ReloadThreatIntel());
        Assert.Equal(-1, engine.ThreatIntelEntries);

        engine.NativeLoadThreatIntel = _ => throw new EntryPointNotFoundException("opticombat_load_threat_intel");
        Assert.Equal(-1, engine.ReloadThreatIntel());
    }

    [Fact]
    public async Task Scan_triggers_the_lazy_load()
    {
        Directory.CreateDirectory(_dir);
        var file = Path.Combine(_dir, "excluded.txt");
        File.WriteAllText(file, "x");
        var calls = 0;
        var engine = new OptiCombatScanEngine
        {
            ThreatIntelDirectory = _dir,
            NativeLoadThreatIntel = _ => { calls++; return 1; },
            ExclusionFilter = _ => true, // aucun appel natif de scan
        };

        var result = await engine.ScanFileAsync(file);
        Assert.Equal(1, result.FilesSkipped);
        await engine.ScanFolderAsync(_dir);
        Assert.Equal(1, calls);
    }

    [Theory]
    [InlineData("clamav", null, "ClamAV")]
    [InlineData("yara", null, "YARA")]
    [InlineData("reputation", "MalwareBazaar:Emotet", "MalwareBazaar")]
    [InlineData("reputation", "Blacklist", "optiCombat")]
    [InlineData("ioc", "IOC.ThreatFox", "optiCombat")]
    public void MapEngine_names_the_source(string engine, string? name, string expected) =>
        Assert.Equal(expected, OptiCombatScanEngine.MapEngine(engine, name));
}
