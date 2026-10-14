using System.Net;
using System.Net.Http;
using System.Text;
using optiCombat.Localization;
using optiCombat.Services;

namespace optiCombat.Tests;

[Collection("OpticombatPrefs")]
public sealed class ThreatReputationServiceTests
{
    [Fact]
    public void ParseFileLookupJson_extracts_stats_and_link()
    {
        const string json = """
            {
              "data": {
                "attributes": {
                  "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "harmless": 50,
                    "undetected": 10
                  }
                },
                "links": { "self": "https://www.virustotal.com/gui/file/abc" }
              }
            }
            """;

        var result = ThreatReputationService.ParseFileLookupJson(json, "abc");

        Assert.True(result.Success);
        Assert.False(result.IsError);
        Assert.Contains("2", result.Summary);
        Assert.Equal("https://www.virustotal.com/gui/file/abc", result.Permalink);
    }

    [Fact]
    public async Task LookupFileAsync_without_api_key_returns_error()
    {
        var prev = UserPreferences.Current.VirusTotalApiKey;
        try
        {
            UserPreferences.Current.VirusTotalApiKey = string.Empty;
            UserPreferences.Current.Save();

            var svc = new ThreatReputationService(new HttpClient(new NoNetworkHandler()));
            var result = await svc.LookupFileAsync(Path.GetTempFileName());

            Assert.False(result.Success);
            Assert.True(result.IsError);
            Assert.Equal(LocalizationService.GetString("VT_NoApiKey"), result.Summary);
        }
        finally
        {
            UserPreferences.Current.VirusTotalApiKey = prev;
            UserPreferences.Current.Save();
        }
    }

    private sealed class NoNetworkHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
    }
}
