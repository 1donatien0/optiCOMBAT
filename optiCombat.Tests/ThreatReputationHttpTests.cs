using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary>Consultation VirusTotal contre un faux serveur HTTP (aucun réseau réel).</summary>
[Collection("Localization")]
public sealed class ThreatReputationHttpTests : IDisposable
{
    private readonly string _file = Path.Combine(Path.GetTempPath(), "oc_vt_" + Guid.NewGuid().ToString("N") + ".bin");
    private readonly FakeHttpHandler _http = new();

    public ThreatReputationHttpTests()
    {
        File.WriteAllText(_file, "échantillon VT " + Guid.NewGuid());
        ThreatReputationService.ResetCacheForTests();
    }

    public void Dispose()
    {
        ThreatReputationService.ResetCacheForTests();
        try { File.Delete(_file); } catch { }
    }

    private string Url => "https://www.virustotal.com/api/v3/files/"
                          + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(_file))).ToLowerInvariant();

    private ThreatReputationService Create(string key = "vt-key") =>
        new(new HttpClient(_http), new FixedPreferencesAccessor(new UserPreferences { VirusTotalApiKey = key }));

    private const string Report =
        """{"data":{"attributes":{"last_analysis_stats":{"malicious":42,"suspicious":1,"harmless":2,"undetected":25}}}}""";

    [Fact]
    public async Task Successful_lookup_is_parsed_and_cached()
    {
        var hits = 0;
        _http.Routes[Url] = () =>
        {
            hits++;
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Report, Encoding.UTF8, "application/json") };
        };
        var svc = Create();

        var r = await svc.LookupFileAsync(_file);
        Assert.True(r.Success, r.Summary);
        Assert.Contains("42", r.Summary, StringComparison.Ordinal);
        Assert.StartsWith("https://www.virustotal.com/gui/file/", r.Permalink, StringComparison.Ordinal);

        var again = await svc.LookupFileAsync(_file);
        Assert.Same(r, again);
        Assert.Equal(1, hits);
    }

    [Fact]
    public async Task Http_error_and_invalid_body_are_errors()
    {
        _http.Routes[Url] = () => new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        var r = await Create().LookupFileAsync(_file);
        Assert.False(r.Success);
        Assert.True(r.IsError);
        Assert.Contains("429", r.Summary, StringComparison.Ordinal);

        _http.Routes[Url] = () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") };
        var bad = await Create().LookupFileAsync(_file);
        Assert.True(bad.IsError);
    }

    [Fact]
    public async Task Missing_key_or_unreadable_file_short_circuits()
    {
        var noKey = await Create("  ").LookupFileAsync(_file);
        Assert.True(noKey.IsError);
        Assert.Empty(_http.Requests);

        var missing = await Create().LookupFileAsync(Path.Combine(Path.GetTempPath(), "oc_vt_absent.bin"));
        Assert.True(missing.IsError);
        Assert.Empty(_http.Requests);
    }

    [Fact]
    public void Permalink_falls_back_to_self_link()
    {
        var json = """{"data":{"links":{"self":"https://www.virustotal.com/gui/file/abc"},"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":5,"undetected":60}}}}""";
        var r = ThreatReputationService.ParseFileLookupJson(json);
        Assert.Equal("https://www.virustotal.com/gui/file/abc", r.Permalink);
        var none = ThreatReputationService.ParseFileLookupJson(
            """{"data":{"links":{"self":"https://api/x"},"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":0,"undetected":0}}}}""");
        Assert.Null(none.Permalink);
    }
}
