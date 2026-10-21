using System.Net.Http;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Strings;
using optiCombat.Tests.TestSupport;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.Tests;

/// <summary>Flux complet de mise à jour YARA-Forge contre une fausse API GitHub.</summary>
[Collection("Localization")]
public sealed class YaraForgeUpdateFlowTests : IDisposable
{
    private const string PackageUrl = "https://downloads.example.test/yara-forge-rules-core.zip";
    private readonly string _rules = Path.Combine(Path.GetTempPath(), "opticombat_yf_" + Guid.NewGuid().ToString("N"));
    private readonly FakeHttpHandler _http = new();

    public YaraForgeUpdateFlowTests() => LocalizationService.ApplyCulture("fr-FR");

    public void Dispose()
    {
        try { Directory.Delete(_rules, recursive: true); }
        catch { /* best effort */ }
    }

    internal static byte[] BuildRulesZip()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, body) in new[]
                     {
                         ("packages/core/rule_a.yar", "rule A { condition: true }"),
                         ("packages/core/rule_b.YAR", "rule B { condition: false }"),
                         ("README.md", "ignored"),
                     })
            {
                using var w = new StreamWriter(zip.CreateEntry(name).Open());
                w.Write(body);
            }
        }
        return ms.ToArray();
    }

    internal static string ReleaseJson(string tag, byte[]? zip, string? digestOverride = null, bool includeAsset = true)
    {
        var assets = new JsonArray();
        if (includeAsset)
        {
            var asset = new JsonObject
            {
                ["name"] = "yara-forge-rules-core.zip",
                ["browser_download_url"] = PackageUrl,
            };
            if (zip != null)
                asset["size"] = zip.Length;
            var digest = digestOverride ?? (zip == null ? null : "sha256:" + Convert.ToHexString(SHA256.HashData(zip)));
            if (digest != null)
                asset["digest"] = digest;
            assets.Add(asset);
        }
        assets.Add(new JsonObject { ["name"] = "yara-forge-rules-full.zip", ["browser_download_url"] = "https://x.test/full.zip" });
        return new JsonObject { ["tag_name"] = tag, ["assets"] = assets }.ToJsonString();
    }

    private void ServeRelease(string json) =>
        _http.Routes[OpticombatStrings.Urls.YaraForgeApiLatest] = () => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };

    private void ServePackage(byte[] bytes) =>
        _http.Routes[PackageUrl] = () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };

    private YaraForgeUpdater Create() => new(_rules, new HttpClient(_http));

    [Fact]
    public async Task Successful_update_installs_yar_files_then_reports_up_to_date()
    {
        var zip = BuildRulesZip();
        ServeRelease(ReleaseJson("20261001", zip));
        ServePackage(zip);
        Directory.CreateDirectory(_rules);
        File.WriteAllText(Path.Combine(_rules, "_compiled.yarc"), "stale");
        var updater = Create();
        var progress = new List<string>();
        RulesUpdateResult? completed = null;
        updater.UpdateCompleted += (_, r) => completed = r;

        var result = await updater.UpdateAsync(new InlineProgress(progress));

        Assert.True(result.Success, result.Message);
        Assert.Equal(2, result.FilesInstalled);
        Assert.Equal("20261001", result.Version);
        Assert.True(File.Exists(Path.Combine(_rules, "rule_a.yar")));
        Assert.False(File.Exists(Path.Combine(_rules, "README.md")));
        Assert.False(File.Exists(Path.Combine(_rules, "_compiled.yarc")));
        Assert.Same(result, completed);
        Assert.NotNull(result.FinishedAt);
        Assert.Contains(LocalizationService.GetString("YaraForge_Installing"), progress);
        Assert.Equal("20261001", updater.GetRulesPackVersionDisplay());

        // Le méta persistant est relu par une nouvelle instance.
        Assert.Equal("20261001", new YaraForgeUpdater(_rules, new HttpClient(_http)).GetRulesPackVersionDisplay());

        var again = await updater.UpdateAsync();
        Assert.True(again.Success);
        Assert.True(again.AlreadyUpToDate);
    }

    [Fact]
    public async Task Api_failure_is_reported()
    {
        var output = new List<string>();
        var updater = Create();
        updater.UpdateOutput += (_, line) => output.Add(line);

        var result = await updater.UpdateAsync();

        Assert.False(result.Success);
        Assert.False(updater.IsUpdating);
        Assert.NotEmpty(output);
    }

    [Fact]
    public async Task Missing_core_package_is_reported()
    {
        ServeRelease(ReleaseJson("20261002", BuildRulesZip(), includeAsset: false));

        var result = await Create().UpdateAsync();

        Assert.False(result.Success);
        Assert.Equal(LocalizationService.GetString("YaraForge_PackageNotFound"), result.Message);
    }

    [Fact]
    public async Task Asset_without_digest_is_refused()
    {
        ServeRelease(ReleaseJson("20261003", zip: null));

        var result = await Create().UpdateAsync();

        Assert.Equal(LocalizationService.GetString("YaraForge_IntegrityUnavailable"), result.Message);
    }

    [Fact]
    public async Task Digest_mismatch_is_refused_before_installation()
    {
        var zip = BuildRulesZip();
        ServeRelease(ReleaseJson("20261004", zip, digestOverride: "sha256:" + new string('0', 64)));
        ServePackage(zip);

        var result = await Create().UpdateAsync();

        Assert.False(result.Success);
        Assert.Equal(LocalizationService.GetString("YaraForge_IntegrityMismatch"), result.Message);
        Assert.False(Directory.Exists(_rules) && Directory.GetFiles(_rules, "*.yar").Length > 0);
    }

    [Fact]
    public async Task Download_failure_is_reported()
    {
        ServeRelease(ReleaseJson("20261005", BuildRulesZip()));

        var result = await Create().UpdateAsync();

        Assert.False(result.Success);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
        Assert.Contains(_http.Requests, u => u.EndsWith(".zip", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Invalid_release_json_is_reported_as_error()
    {
        ServeRelease("{ pas du json");

        var result = await Create().UpdateAsync();

        Assert.False(result.Success);
    }

    private sealed class InlineProgress(List<string> sink) : IProgress<string>
    {
        public void Report(string value) => sink.Add(value);
    }
}

[Collection("OpticombatPrefs")]
public sealed class AntivirusSignatureUpdateTests : IDisposable
{
    private readonly IsolatedServices _env = new();

    public void Dispose() => _env.Dispose();

    [Fact]
    public async Task UpdateSignatures_runs_both_updaters_and_logs_progress()
    {
        var zip = YaraForgeUpdateFlowTests.BuildRulesZip();
        _env.Http.Routes[OpticombatStrings.Urls.YaraForgeApiLatest] = () => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(YaraForgeUpdateFlowTests.ReleaseJson("20261010", zip)),
        };
        _env.Http.Routes["https://downloads.example.test/yara-forge-rules-core.zip"] =
            () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(zip) };
        var vm = new AntivirusViewModel(_env.Container);
        await Eventually.TrueAsync(() => !vm.IsInitializing, 15000);
        var updatingSeen = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(vm.IsUpdating) && vm.IsUpdating)
                updatingSeen = true;
        };

        await vm.UpdateSignaturesAsync();

        Assert.True(updatingSeen);
        Assert.False(vm.IsUpdating);
        Assert.False(string.IsNullOrWhiteSpace(vm.SignatureLog));
        Assert.Equal("20261010", vm.YaraVersion);
        Assert.Contains(_env.Http.Requests, u => u.Contains("yara-forge", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task UpdateSignatures_with_offline_rules_finishes_with_errors()
    {
        var vm = new AntivirusViewModel(_env.Container);
        await Eventually.TrueAsync(() => !vm.IsInitializing, 15000);

        await vm.UpdateSignaturesAsync();

        Assert.False(vm.IsUpdating);
        Assert.Equal(OpticombatStrings.StatusUpdates.FullSignaturesUpdateFinishedWithErrors, vm.StatusMessage);
    }
}
