using optiCombat.Strings;
using optiCombat.Localization;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary><see cref="FreshclamUpdater"/> contre un processus « freshclam » factice.</summary>
// Collection non parallélisée : la configuration de repli freshclam est écrite sous la racine de test.
[Collection("OpticombatPrefs")]
public sealed class FreshclamProcessTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "oc_fc_" + Guid.NewGuid().ToString("N"));
    private readonly string _bin;
    private readonly string _db;
    private readonly string _exe;

    public FreshclamProcessTests()
    {
        LocalizationService.ApplyCulture("fr-FR");
        OpticombatDataRoots.TestRootOverride = _root;
        _bin = Path.Combine(_root, "clamav");
        _db = Path.Combine(_bin, "database");
        Directory.CreateDirectory(_db);
        // Certificat de signature CVD présent : aucun téléchargement pendant les tests.
        Directory.CreateDirectory(Path.Combine(_bin, "certs"));
        File.WriteAllText(Path.Combine(_bin, "certs", "clamav.crt"), new string('C', 300));
        _exe = FakeTools.Install(_bin, "freshclam.exe");
    }

    public void Dispose()
    {
        OpticombatDataRoots.TestRootOverride = TestDataRoot.Session;
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private FreshclamUpdater Create(List<string>? log = null)
    {
        var u = new FreshclamUpdater(_bin);
        if (log != null)
            u.UpdateOutput += (_, l) => { lock (log) log.Add(l); };
        return u;
    }

    [Fact]
    public async Task Successful_update_reads_the_new_database_version()
    {
        FakeTools.Script(_exe,
            stdout: "daily.cld updated (version: 27800)",
            stderr: "WARNING: avertissement",
            writes: (Path.Combine(_db, "daily.cld"), "ClamAV-VDB:23 Oct 2026 08-00 +0000:27800:2100000:90:x"));
        var log = new List<string>();
        var updater = Create(log);
        UpdateResult? completed = null;
        updater.UpdateCompleted += (_, r) => completed = r;

        var result = await updater.UpdateAsync();

        Assert.True(result.Success, result.Message);
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("27800", result.Version);
        Assert.Equal("27800", updater.DatabaseVersion);
        Assert.NotNull(updater.LastUpdateTime);
        Assert.Same(result, completed);
        Assert.False(updater.IsUpdating);
        lock (log)
        {
            Assert.Contains(log, l => l.Contains("27800", StringComparison.Ordinal));
            Assert.Contains(log, l => l.StartsWith("[ERR]", StringComparison.Ordinal));
        }

        var call = Assert.Single(FakeTools.Calls(_exe));
        Assert.Contains("--show-progress", call);
        Assert.Contains(call, a => a.StartsWith("--datadir=", StringComparison.Ordinal));
        Assert.Contains(call, a => a.StartsWith("--config-file=", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Exit_code_one_means_already_up_to_date()
    {
        FakeTools.Script(_exe, exit: 1, stdout: "daily.cvd database is up-to-date (version: 27801)");
        var result = await Create().UpdateAsync();
        Assert.True(result.Success);
        Assert.True(result.AlreadyUpToDate);
        Assert.Equal(1, result.ExitCode);
    }

    [Fact]
    public async Task Error_exit_code_is_a_failure()
    {
        FakeTools.Script(_exe, exit: 2, stderr: "ERROR: config");
        var updater = Create();
        var result = await updater.UpdateAsync();
        Assert.False(result.Success);
        Assert.Equal(2, result.ExitCode);
        Assert.Contains("2", result.Message, StringComparison.Ordinal);
        Assert.Null(updater.LastUpdateTime);
    }

    [Fact]
    public async Task User_cancellation_kills_the_process()
    {
        FakeTools.Script(_exe, delayMs: 20_000);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(800));
        var log = new List<string>();

        var result = await Create(log).UpdateAsync(cts.Token);

        Assert.False(result.Success);
        Assert.False(string.IsNullOrEmpty(result.Message));
    }

    [Fact]
    public async Task CancelUpdate_interrupts_a_running_update_and_concurrent_call_is_refused()
    {
        FakeTools.Script(_exe, delayMs: 20_000);
        var updater = Create();
        var running = updater.UpdateAsync();
        await Eventually.TrueAsync(() => FakeTools.Calls(_exe).Count == 1, 15_000);

        var second = await updater.UpdateAsync();
        Assert.False(second.Success);
        Assert.True(updater.IsUpdating);

        updater.CancelUpdate();
        var result = await running;
        Assert.False(result.Success);
        Assert.False(updater.IsUpdating);
    }

    [Fact]
    public async Task Stale_locks_and_partial_downloads_are_removed_before_running()
    {
        var pid = Path.Combine(_db, "freshclam.pid");
        var recent = Path.Combine(_db, "mirrors.dat.lock");
        File.WriteAllText(pid, "1234");
        File.SetLastWriteTime(pid, DateTime.Now.AddHours(-1));
        File.WriteAllText(recent, "x");
        Directory.CreateDirectory(Path.Combine(_db, "tmp.abc123"));
        FakeTools.Script(_exe, exit: 1);
        var log = new List<string>();

        await Create(log).UpdateAsync();

        Assert.False(File.Exists(pid));
        Assert.True(File.Exists(recent), "un verrou récent est conservé");
        Assert.False(Directory.Exists(Path.Combine(_db, "tmp.abc123")));
        lock (log)
            Assert.Contains(log, l => l.Contains("freshclam.pid", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Version_comes_from_freshclam_when_no_database_file_exists()
    {
        FakeTools.Script(_exe, "version", stdout: "ClamAV 1.4.1/27795/Thu Oct 23 08:00:00 2026");
        Assert.Equal("27795", await Create().GetLocalDatabaseVersionAsync());

        FakeTools.Script(_exe, "version", stdout: "sortie inattendue");
        Assert.Equal(VersionDisplayHelper.UnknownLabel, await Create().GetLocalDatabaseVersionAsync());
    }

    [Fact]
    public async Task No_network_fails_fast_without_starting_freshclam()
    {
        var updater = Create();
        updater.NetworkProbeOverride = () => false;

        var result = await updater.UpdateAsync();

        Assert.False(result.Success);
        Assert.Equal(LocalizationService.GetString("Freshclam_NoNetwork"), result.Message);
        // Seule la lecture de version (« --version ») a lieu : aucune mise à jour lancée.
        Assert.DoesNotContain(FakeTools.Calls(_exe), c => c.Any(a => a.StartsWith("--datadir=", StringComparison.Ordinal)));
        Assert.False(updater.IsUpdating);
    }

    [Fact]
    public async Task Unwritable_certs_folder_falls_back_and_downloads_the_root_certificate()
    {
        // « certs » devient un fichier : le dossier d'installation est inutilisable (Program Files en lecture seule).
        Directory.Delete(Path.Combine(_bin, "certs"), recursive: true);
        File.WriteAllText(Path.Combine(_bin, "certs"), "pas un dossier");
        var http = new FakeHttpHandler();
        http.Routes[OpticombatStrings.Urls.ClamAvRootCertRaw] = () =>
            new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[400]) };
        FakeTools.Script(_exe, exit: 1, stdout: "up-to-date");
        var log = new List<string>();
        var updater = Create(log);
        updater.NetworkProbeOverride = () => true;
        updater.CertificateHttpOverride = new HttpClient(http);

        var result = await updater.UpdateAsync();

        Assert.True(result.Success, result.Message);
        var fallback = Path.Combine(_root, "local", "clamav", "cvd-certs", "clamav.crt");
        Assert.Equal(400, new FileInfo(fallback).Length);
        Assert.Single(http.Requests);
        lock (log)
            Assert.Contains(log, l => l.Contains("cvd-certs", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Truncated_certificate_download_is_ignored_and_reported()
    {
        Directory.Delete(Path.Combine(_bin, "certs"), recursive: true);
        File.WriteAllText(Path.Combine(_bin, "certs"), "pas un dossier");
        var http = new FakeHttpHandler();
        http.Routes[OpticombatStrings.Urls.ClamAvRootCertRaw] = () =>
            new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[10]) };
        FakeTools.Script(_exe, exit: 1);
        var log = new List<string>();
        var updater = Create(log);
        updater.NetworkProbeOverride = () => true;
        updater.CertificateHttpOverride = new HttpClient(http);

        await updater.UpdateAsync();

        Assert.False(File.Exists(Path.Combine(_root, "local", "clamav", "cvd-certs", "clamav.crt")));
        lock (log)
            Assert.Contains(log, l => l.Contains(LocalizationService.GetString("Freshclam_LogCvdCertMissing"), StringComparison.Ordinal));
    }

    [Fact]
    public void Last_update_time_comes_from_the_newest_database_file()
    {
        var updater = Create();
        Assert.Equal("—", updater.GetLastSignatureChangeDisplay());

        var daily = Path.Combine(_db, "daily.cld");
        var main = Path.Combine(_db, "main.cvd");
        File.WriteAllText(daily, "d");
        File.WriteAllText(main, "m");
        var newest = new DateTime(2026, 10, 20, 8, 30, 0, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(daily, newest);
        File.SetLastWriteTimeUtc(main, newest.AddDays(-3));

        Assert.Equal(newest.ToLocalTime(), updater.GetLastSignatureUpdateTime());
        Assert.Equal(newest.ToLocalTime().ToString("dd/MM/yyyy HH:mm"), updater.GetLastSignatureChangeDisplay());
    }

    [Fact]
    public void Auto_update_can_be_enabled_replaced_and_disabled()
    {
        var updater = Create();
        updater.NetworkProbeOverride = () => false;
        updater.EnableAutoUpdate(TimeSpan.FromHours(1));
        updater.EnableAutoUpdate(TimeSpan.FromHours(2));
        updater.DisableAutoUpdate();
        updater.DisableAutoUpdate();
        Assert.False(updater.IsUpdating);
    }
}
