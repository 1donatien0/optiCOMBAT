using System.Globalization;
using optiCombat.Localization;
using optiCombat.Services;

namespace optiCombat.Tests;

/// <summary>Chemins hors réseau de <see cref="FreshclamUpdater"/> et <see cref="YaraForgeUpdater"/>.</summary>
[Collection("Localization")]
public sealed class SignatureUpdatersOfflineTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "opticombat_sig_" + Guid.NewGuid().ToString("N"));
    private readonly string _bin;
    private readonly string _db;

    public SignatureUpdatersOfflineTests()
    {
        LocalizationService.ApplyCulture("fr-FR");
        _bin = Path.Combine(_root, "clamav");
        _db = Path.Combine(_bin, "database");
        Directory.CreateDirectory(_db);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch { /* best effort */ }
    }

    [Fact]
    public async Task Update_without_freshclam_is_a_silent_success()
    {
        var updater = new FreshclamUpdater(_bin);
        var output = new List<string>();
        updater.UpdateOutput += (_, line) => output.Add(line);

        var result = await updater.UpdateAsync();

        Assert.True(result.Success);
        Assert.True(result.AlreadyUpToDate);
        Assert.Equal(LocalizationService.GetString("Freshclam_ExeNotFound"), result.Message);
        Assert.NotEmpty(output);
        Assert.False(updater.IsUpdating);
    }

    [Fact]
    public async Task Database_version_is_read_from_cvd_header()
    {
        File.WriteAllText(Path.Combine(_db, "daily.cvd"), "ClamAV-VDB:12 Oct 2026 08-00 +0000:27790:2100000:90:...");

        Assert.Equal("27790", await new FreshclamUpdater(_bin).GetLocalDatabaseVersionAsync());
    }

    [Fact]
    public async Task Database_version_falls_back_to_version_tag_then_unknown()
    {
        File.WriteAllText(Path.Combine(_db, "main.cld"), "header without vdb\nversion: 62");
        Assert.Equal("62", await new FreshclamUpdater(_bin).GetLocalDatabaseVersionAsync());

        File.WriteAllText(Path.Combine(_db, "main.cld"), "rien d'exploitable");
        Assert.Equal(VersionDisplayHelper.UnknownLabel, await new FreshclamUpdater(_bin).GetLocalDatabaseVersionAsync());
    }

    [Fact]
    public void Last_signature_update_uses_newest_database_file()
    {
        var updater = new FreshclamUpdater(_bin);
        Assert.Null(updater.GetLastSignatureUpdateTime());
        Assert.Equal("—", updater.GetLastSignatureChangeDisplay());

        var daily = Path.Combine(_db, "daily.cld");
        var main = Path.Combine(_db, "main.cvd");
        File.WriteAllText(daily, "x");
        File.WriteAllText(main, "y");
        var newest = new DateTime(2026, 10, 15, 8, 30, 0, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(daily, newest);
        File.SetLastWriteTimeUtc(main, newest.AddDays(-3));

        Assert.Equal(newest.ToLocalTime(), updater.GetLastSignatureUpdateTime());
        Assert.Equal(newest.ToLocalTime().ToString("dd/MM/yyyy HH:mm"), updater.GetLastSignatureChangeDisplay());
    }

    [Fact]
    public void Freshclam_auto_update_timer_toggles_and_cancel_is_safe_when_idle()
    {
        var updater = new FreshclamUpdater(_bin);

        updater.CancelUpdate();
        updater.EnableAutoUpdate(TimeSpan.FromHours(6));
        Assert.True(updater.IsAutoUpdateEnabled);
        updater.EnableAutoUpdate();
        updater.DisableAutoUpdate();
        Assert.False(updater.IsAutoUpdateEnabled);
    }

    [Fact]
    public void Yara_meta_file_is_loaded_at_startup()
    {
        var rules = Path.Combine(_root, "rules");
        Directory.CreateDirectory(rules);
        var when = new DateTime(2026, 9, 30, 12, 0, 0, DateTimeKind.Utc);
        File.WriteAllLines(Path.Combine(rules, ".opticombat-yara-meta.txt"),
            new[] { " 20260930 ", when.ToString("o", CultureInfo.InvariantCulture) });

        var updater = new YaraForgeUpdater(rules);

        Assert.Equal("20260930", updater.GetRulesPackVersionDisplay());
        Assert.Equal(when.ToLocalTime().ToString("dd/MM/yyyy HH:mm", CultureInfo.CurrentCulture), updater.GetRulesLastUpdateDisplay());
    }

    [Fact]
    public void Yara_without_meta_shows_dashes_and_timer_toggles()
    {
        var updater = new YaraForgeUpdater(Path.Combine(_root, "empty-rules"));

        Assert.Equal("—", updater.GetRulesPackVersionDisplay());
        Assert.Equal("—", updater.GetRulesLastUpdateDisplay());

        updater.CancelUpdate();
        updater.EnableAutoUpdate(TimeSpan.FromHours(12));
        Assert.True(updater.IsAutoUpdateEnabled);
        updater.DisableAutoUpdate();
        Assert.False(updater.IsAutoUpdateEnabled);
    }
}
