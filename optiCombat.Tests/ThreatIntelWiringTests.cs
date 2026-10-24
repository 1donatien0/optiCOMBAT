using System.Net;
using System.Net.Http;
using System.Text;
using Moq;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;
using optiCombat.WinUI.ViewModels;

namespace optiCombat.Tests;

public sealed class ThreatIntelPolicyTests
{
    [Fact]
    public void ApplyAutoUpdateTimers_drives_the_threat_intel_target_too()
    {
        var freshclam = new Mock<ISignatureAutoUpdateTarget>();
        var rules = new Mock<ISignatureAutoUpdateTarget>();
        var intel = new Mock<ISignatureAutoUpdateTarget>(MockBehavior.Strict);
        intel.Setup(i => i.EnableAutoUpdate(It.IsAny<TimeSpan?>()));
        intel.Setup(i => i.DisableAutoUpdate());
        var prefs = new FixedPreferencesAccessor(new UserPreferences { AggressiveSignatureUpdates = false });

        SignatureUpdatePolicy.ApplyAutoUpdateTimers(freshclam.Object, rules.Object, true, prefs, intel.Object);
        intel.Verify(i => i.EnableAutoUpdate(TimeSpan.FromHours(12)), Times.Once);

        prefs.Current.AggressiveSignatureUpdates = true;
        SignatureUpdatePolicy.ApplyAutoUpdateTimers(freshclam.Object, rules.Object, true, prefs, intel.Object);
        intel.Verify(i => i.EnableAutoUpdate(TimeSpan.FromHours(6)), Times.Once);

        SignatureUpdatePolicy.ApplyAutoUpdateTimers(freshclam.Object, rules.Object, false, prefs, intel.Object);
        intel.Verify(i => i.DisableAutoUpdate(), Times.Once);
    }

    [Fact]
    public async Task Coordinator_without_key_logs_the_step_and_stays_successful()
    {
        var dir = Path.Combine(Path.GetTempPath(), "oc_coord_" + Guid.NewGuid().ToString("N"));
        var http = new FakeHttpHandler();
        var intel = new ThreatIntelFeedUpdater(
            new FixedPreferencesAccessor(new UserPreferences()), dir, new HttpClient(http), () => DateTime.UtcNow);
        var log = new List<string>();

        var ok = await SignatureUpdateCoordinator.RunFullSignatureUpdateAsync(null, null, log.Add, default, intel);

        Assert.True(ok);
        Assert.Empty(http.Requests);
        Assert.Contains(log, l => l.Contains("abuse.ch", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Coordinator_reports_failed_feed_download()
    {
        var dir = Path.Combine(Path.GetTempPath(), "oc_coord_" + Guid.NewGuid().ToString("N"));
        var http = new FakeHttpHandler(); // 503 partout
        var intel = new ThreatIntelFeedUpdater(
            new FixedPreferencesAccessor(new UserPreferences { AbuseChAuthKey = "testtesttesttest" }),
            dir, new HttpClient(http), () => DateTime.UtcNow);
        var runner = new SignatureUpdateUiRunner();
        var log = new List<string>();

        var ok = await runner.RunFullUpdateAsync(null, null, log.Add, default, intel);

        Assert.False(ok);
        Assert.Equal(3, http.Requests.Count);
        Assert.Contains(log, l => l.Contains("HTTP 503", StringComparison.Ordinal));
        try { Directory.Delete(dir, true); } catch { }
    }
}

[Collection("OpticombatPrefs")]
public sealed class ThreatIntelContainerTests : IDisposable
{
    private const string Key = "testtesttesttest";
    private readonly IsolatedServices _env = new();

    public void Dispose() => _env.Dispose();

    private OptionsViewModel Options() => new(_env.Container, new NullTheme());

    [Fact]
    public void Container_exposes_an_isolated_updater_driven_by_auto_update()
    {
        var updater = _env.Container.ThreatIntelUpdater;
        Assert.StartsWith(_env.Root, updater.FeedDirectory, StringComparison.Ordinal);

        _env.Container.ApplySignatureAutoUpdate(true);
        Assert.True(updater.IsAutoUpdateEnabled);
        _env.Container.ApplySignatureAutoUpdate(false);
        Assert.False(updater.IsAutoUpdateEnabled);
    }

    [Fact]
    public void Options_status_reflects_missing_then_invalid_key()
    {
        _env.Prefs.AbuseChAuthKey = "";
        var vm = Options();
        Assert.Equal(string.Empty, vm.AbuseChAuthKey);
        var noKey = vm.ThreatIntelStatus;
        Assert.False(string.IsNullOrWhiteSpace(noKey));

        Assert.False(vm.SaveAbuseChAuthKey("trop-court"));
        Assert.Equal("trop-court", _env.Prefs.AbuseChAuthKey);
        Assert.NotEqual(noKey, vm.ThreatIntelStatus);
        Assert.Null(vm.LastThreatIntelUpdate);
        Assert.Empty(_env.Http.Requests);

        Assert.True(vm.SaveAbuseChAuthKey("  "));
        Assert.Equal(string.Empty, _env.Prefs.AbuseChAuthKey);
    }

    [Fact]
    public async Task Saving_a_valid_key_downloads_the_feeds_once()
    {
        var vm = Options();
        var changes = new List<string?>();
        vm.PropertyChanged += (_, e) => changes.Add(e.PropertyName);

        Assert.True(vm.SaveAbuseChAuthKey($" {Key} "));
        Assert.Equal(Key, _env.Prefs.AbuseChAuthKey);
        Assert.NotNull(vm.LastThreatIntelUpdate);
        await vm.LastThreatIntelUpdate!;

        Assert.Equal(3, _env.Http.Requests.Count);
        Assert.All(_env.Http.Requests, u => Assert.Contains(Key, u, StringComparison.Ordinal));
        Assert.Contains("HTTP 503", vm.ThreatIntelStatus, StringComparison.Ordinal);
        Assert.Contains(nameof(OptionsViewModel.ThreatIntelStatus), changes);

        // Même clé : pas de nouveau téléchargement.
        var previous = vm.LastThreatIntelUpdate;
        Assert.True(vm.SaveAbuseChAuthKey(Key));
        Assert.Same(previous, vm.LastThreatIntelUpdate);
        Assert.Equal(3, _env.Http.Requests.Count);
    }

    [Fact]
    public async Task Successful_refresh_shows_the_last_update_date()
    {
        _env.Prefs.AbuseChAuthKey = Key;
        foreach (var feed in ThreatIntelFeedUpdater.Feeds)
        {
            _env.Http.Routes[ThreatIntelFeedUpdater.BuildUrl(feed, Key)] = () =>
                new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("a,b\n", Encoding.UTF8) };
        }
        var vm = Options();
        var before = vm.ThreatIntelStatus;

        await vm.RefreshThreatIntelAsync(force: true);

        Assert.NotNull(_env.Container.ThreatIntelUpdater.LastUpdateUtc);
        Assert.NotEqual(before, vm.ThreatIntelStatus);
        Assert.True(File.Exists(Path.Combine(_env.Container.ThreatIntelUpdater.FeedDirectory, "threatfox.csv")));
    }

    private sealed class NullTheme : IShellThemeController
    {
        public bool IsDarkTheme => false;

        public void ApplyExplicit(bool dark) { }

        public void SetSyncWithWindows(bool sync) { }

        public void SetHighContrast(bool enabled) { }

        public void SetThemePreset(string presetId) { }

        public void SetCustomAccentColor(string? hexColor) { }
    }
}
