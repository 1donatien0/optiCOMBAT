using System.Net;
using System.Net.Http;
using System.Text;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

public sealed class UpdateServiceTests : IDisposable
{
    private readonly string _staging = Path.Combine(Path.GetTempPath(), "oc_upd_" + Guid.NewGuid().ToString("N"));
    private readonly FakeHttpHandler _http = new();

    public void Dispose()
    {
        try { Directory.Delete(_staging, true); } catch { }
    }

    private UpdateService Create() => new(new HttpClient(_http), _staging);

    private void Release(string json) =>
        _http.Routes[UpdateService.LatestReleaseApiUrl] = () =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    [Fact]
    public async Task Newer_release_is_reported_with_its_page()
    {
        Release("""{"tag_name":"v99.1.0","html_url":"https://github.com/1donatien0/optiCOMBAT/releases/tag/v99.1.0","draft":false,"prerelease":false}""");

        var r = await Create().CheckForUpdatesAsync();

        Assert.Equal(AppUpdateChannelStatus.UpdateAvailable, r.Status);
        Assert.True(r.Success);
        Assert.Equal("99.1.0", r.LatestVersion);
        Assert.Equal("https://github.com/1donatien0/optiCOMBAT/releases/tag/v99.1.0", r.ReleaseUrl);
        Assert.Contains("99.1.0", r.UserMessage, StringComparison.Ordinal);
        Assert.True(Directory.Exists(_staging));
    }

    [Fact]
    public async Task Same_or_older_release_is_up_to_date()
    {
        Release("""{"tag_name":"v0.0.1","html_url":"https://github.com/x/y/releases/tag/v0.0.1"}""");
        var r = await Create().CheckForUpdatesAsync();
        Assert.Equal(AppUpdateChannelStatus.UpToDate, r.Status);
        Assert.True(r.Success);
        Assert.False(string.IsNullOrWhiteSpace(r.UserMessage));
    }

    [Fact]
    public async Task Missing_release_falls_back_to_manual_message()
    {
        _http.Routes[UpdateService.LatestReleaseApiUrl] = () => new HttpResponseMessage(HttpStatusCode.NotFound);
        var r = await Create().CheckForUpdatesAsync();
        Assert.Equal(AppUpdateChannelStatus.NotConfigured, r.Status);
        Assert.True(r.Success);
        Assert.Equal(string.Empty, r.ReleaseUrl);
    }

    [Fact]
    public async Task Draft_or_prerelease_is_ignored()
    {
        Release("""{"tag_name":"v99.0.0","prerelease":true}""");
        Assert.Equal(AppUpdateChannelStatus.NotConfigured, (await Create().CheckForUpdatesAsync()).Status);
        Release("""{"tag_name":"v99.0.0","draft":true}""");
        Assert.Equal(AppUpdateChannelStatus.NotConfigured, (await Create().CheckForUpdatesAsync()).Status);
        Release("""{"tag_name":""}""");
        Assert.Equal(AppUpdateChannelStatus.NotConfigured, (await Create().CheckForUpdatesAsync()).Status);
    }

    [Fact]
    public async Task Server_error_and_invalid_json_are_check_failures()
    {
        var r = await Create().CheckForUpdatesAsync(); // 503 par défaut
        Assert.Equal(AppUpdateChannelStatus.CheckFailed, r.Status);
        Assert.False(r.Success);
        Assert.Contains("503", r.UserMessage, StringComparison.Ordinal);

        Release("pas du json");
        Assert.Equal(AppUpdateChannelStatus.CheckFailed, (await Create().CheckForUpdatesAsync()).Status);
        Release("[1,2]");
        Assert.Equal(AppUpdateChannelStatus.CheckFailed, (await Create().CheckForUpdatesAsync()).Status);
    }

    [Fact]
    public async Task Non_github_release_page_is_replaced_by_the_official_page()
    {
        Release("""{"tag_name":"v99.0.0","html_url":"https://evil.example/download"}""");
        var r = await Create().CheckForUpdatesAsync();
        Assert.Equal("https://github.com/1donatien0/optiCOMBAT/releases", r.ReleaseUrl);
    }

    [Fact]
    public async Task Unusable_staging_directory_is_reported()
    {
        var file = Path.Combine(Path.GetTempPath(), "oc_upd_file_" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(file, "x");
        try
        {
            var r = await new UpdateService(new HttpClient(_http), Path.Combine(file, "sub")).CheckForUpdatesAsync();
            Assert.Equal(AppUpdateChannelStatus.StagingError, r.Status);
            Assert.False(r.Success);
            Assert.Empty(_http.Requests);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Theory]
    [InlineData("1.0.1", "1.0.0", true)]
    [InlineData("v1.1", "1.0.9", true)]
    [InlineData("2", "1.9.9", true)]
    [InlineData("1.0.0", "1.0.0", false)]
    [InlineData("1.0.0-rc1", "1.0.0", false)]
    [InlineData("1.0.0+build7", "0.9.0", true)]
    [InlineData("garbage", "1.0.0", false)]
    [InlineData("1.0.0", "garbage", false)]
    public void IsNewer_compares_numerically(string latest, string current, bool expected) =>
        Assert.Equal(expected, UpdateService.IsNewer(latest, current));

    [Fact]
    public void NormalizeTag_strips_leading_v() =>
        Assert.Equal(new[] { "1.2.3", "1.2.3", "1.2.3" },
            new[] { "v1.2.3", "V1.2.3", " 1.2.3 " }.Select(UpdateService.NormalizeTag).ToArray());
}
