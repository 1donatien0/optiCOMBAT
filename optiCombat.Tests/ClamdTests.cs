using System.Net;
using System.Net.Sockets;
using System.Text;
using optiCombat.Localization;
using optiCombat.Models;
using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary>Faux démon clamd (TCP local) : PING, SCAN, CONTSCAN.</summary>
internal sealed class FakeClamdServer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public FakeClamdServer(Func<string, string> respond)
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _loop = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false); }
                catch { return; }
                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        var stream = client.GetStream();
                        using var reader = new StreamReader(stream, Encoding.UTF8, false, 1024, leaveOpen: true);
                        var cmd = await reader.ReadLineAsync().ConfigureAwait(false) ?? string.Empty;
                        lock (Commands)
                            Commands.Add(cmd);
                        var reply = Encoding.UTF8.GetBytes(respond(cmd));
                        await stream.WriteAsync(reply).ConfigureAwait(false);
                        await stream.FlushAsync().ConfigureAwait(false);
                    }
                });
            }
        });
    }

    public int Port { get; }

    public List<string> Commands { get; } = new();

    public ClamdClient Client() => new("127.0.0.1", Port);

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
        try { _loop.Wait(2000); } catch { }
        _cts.Dispose();
    }
}

[Collection("OpticombatPrefs")]
public sealed class ClamdTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "oc_clamd_" + Guid.NewGuid().ToString("N"));
    private readonly string _samples;
    private readonly FixedPreferencesAccessor _prefs = new(new UserPreferences { UseClamdEngine = true });
    private readonly FixedExclusionsAccessor _exclusions = new(new ExclusionSettings());

    public ClamdTests()
    {
        LocalizationService.ApplyCulture("fr-FR");
        OpticombatDataRoots.TestRootOverride = _root;
        _samples = Path.Combine(_root, "samples");
        Directory.CreateDirectory(_samples);
    }

    public void Dispose()
    {
        OpticombatDataRoots.TestRootOverride = TestDataRoot.Session;
        try { Directory.Delete(_root, true); } catch { }
    }

    private string Sample(string name)
    {
        var p = Path.Combine(_samples, name);
        File.WriteAllText(p, "x");
        return p;
    }

    private ClamdEngine Engine(FakeClamdServer server, bool ready = true) =>
        new(_prefs, _exclusions, _ => Task.FromResult(ready), server.Client, new ClamAvEngine(Path.Combine(_root, "none"), _exclusions));

    [Fact]
    public async Task Client_ping_scan_and_contscan()
    {
        using var server = new FakeClamdServer(cmd => cmd switch
        {
            "PING" => "PONG\n",
            _ when cmd.StartsWith("SCAN ", StringComparison.Ordinal) => cmd[5..] + ": OK\n",
            _ => "a: OK\nb: Win.Test FOUND\n",
        });
        using var client = server.Client();

        Assert.True(await client.PingAsync());
        var file = Sample("one.txt");
        Assert.Equal(file + ": OK", await client.ScanFileAsync(file));
        var multi = await client.ScanRecursiveAsync(_samples);
        Assert.Contains("Win.Test FOUND", multi, StringComparison.Ordinal);
        Assert.Equal(2, multi.Split('\n').Length);
        Assert.Contains(server.Commands, c => c.StartsWith("CONTSCAN ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Engine_file_and_folder_scans_parse_clamd_output()
    {
        var bad = Sample("bad.bin");
        var ok = Sample("ok.txt");
        using var server = new FakeClamdServer(cmd => cmd.StartsWith("SCAN ", StringComparison.Ordinal)
            ? $"{bad}: Win.Test.Clamd FOUND\n"
            : $"{ok}: OK\n{bad}: Win.Test.Clamd FOUND\n");
        var engine = Engine(server);

        var file = await engine.ScanFileAsync(bad);
        Assert.Equal(ScanStatus.Completed, file.Status);
        Assert.Equal("Win.Test.Clamd", Assert.Single(file.Threats).VirusName);
        Assert.Equal("clamd", ClamdEngine.LastMode);

        var folder = await engine.ScanFolderAsync(_samples);
        Assert.Single(folder.Threats);
        Assert.Equal(1, folder.FilesScanned);

        var list = await engine.ScanFileListAsync(new[] { bad, ok, Path.Combine(_samples, "absent") }, _samples);
        Assert.Equal(2, list.Threats.Count); // un SCAN par fichier existant
        Assert.Equal(2, list.FilesScanned);

        var empty = await engine.ScanFileListAsync(Array.Empty<string>(), _samples);
        Assert.Equal(0, empty.FilesScanned);
    }

    [Fact]
    public async Task Engine_not_ready_or_disabled_throws_and_missing_targets_are_rejected()
    {
        using var server = new FakeClamdServer(_ => "PONG\n");
        var notReady = Engine(server, ready: false);
        await Assert.ThrowsAsync<InvalidOperationException>(() => notReady.ScanFileAsync(Sample("n.txt")));
        await Assert.ThrowsAsync<InvalidOperationException>(() => notReady.ScanFileListAsync(new[] { Sample("m.txt") }, _samples));
        await Assert.ThrowsAsync<FileNotFoundException>(() => notReady.ScanFileAsync(Path.Combine(_samples, "absent")));
        await Assert.ThrowsAsync<DirectoryNotFoundException>(() => notReady.ScanFolderAsync(Path.Combine(_samples, "absent")));

        _prefs.Current.UseClamdEngine = false;
        Assert.False(await Engine(server).TryEnsureReadyAsync());
        Assert.False(Engine(server).IsClamAvInstalled());
    }

    [Fact]
    public async Task Unreachable_daemon_marks_the_scan_as_error()
    {
        int port;
        using (var probe = new TcpListener(IPAddress.Loopback, 0))
        {
            probe.Start();
            port = ((IPEndPoint)probe.LocalEndpoint).Port;
        }
        var engine = new ClamdEngine(_prefs, _exclusions, _ => Task.FromResult(true),
            () => new ClamdClient("127.0.0.1", port), new ClamAvEngine(Path.Combine(_root, "none"), _exclusions));

        var result = await engine.ScanFileAsync(Sample("e.txt"));

        Assert.Equal(ScanStatus.Error, result.Status);
        Assert.False(string.IsNullOrEmpty(result.ErrorMessage));
    }

    [Fact]
    public async Task Host_starts_clamd_then_waits_for_pong_and_stops_it()
    {
        var bin = Path.Combine(_root, "clamav");
        var clamd = FakeTools.Install(bin, "clamd.exe");
        FakeTools.Script(clamd, delayMs: 30_000); // reste actif comme un démon
        var pings = 0;
        using var host = new ClamdHost(bin, Path.Combine(_root, "db"),
            _ => Task.FromResult(Interlocked.Increment(ref pings) > 2), TimeSpan.FromSeconds(10));

        Assert.True(host.IsBinaryPresent);
        Assert.True(await host.EnsureRunningAsync());
        Assert.True(host.IsProcessRunning);
        Assert.True(File.Exists(ClamdConfSupport.GetConfPath()));
        Assert.StartsWith(_root, ClamdConfSupport.GetConfPath(), StringComparison.Ordinal);
        var call = Assert.Single(FakeTools.Calls(clamd));
        Assert.StartsWith("--config-file=", call[0], StringComparison.Ordinal);

        Assert.True(await host.EnsureRunningAsync()); // déjà joignable : pas de relance
        Assert.Single(FakeTools.Calls(clamd));

        host.Stop();
        Assert.False(host.IsProcessRunning);
    }

    [Fact]
    public async Task Host_without_binary_or_pong_gives_up()
    {
        using var missing = new ClamdHost(Path.Combine(_root, "none"), _root, _ => Task.FromResult(false), TimeSpan.FromSeconds(1));
        Assert.False(missing.IsBinaryPresent);
        Assert.False(await missing.EnsureRunningAsync());

        var bin = Path.Combine(_root, "clamav2");
        var clamd = FakeTools.Install(bin, "clamd.exe");
        FakeTools.Script(clamd, delayMs: 30_000);
        using var silent = new ClamdHost(bin, _root, _ => Task.FromResult(false), TimeSpan.FromMilliseconds(900));
        Assert.False(await silent.EnsureRunningAsync());
        silent.Dispose();
        silent.Dispose(); // idempotent
        Assert.False(silent.IsProcessRunning);
    }

    [Fact]
    public void Conf_is_written_with_excludes_under_the_redirected_root()
    {
        var db = Path.Combine(_root, "db");
        Directory.CreateDirectory(db);
        ClamdConfSupport.EnsureConf(db, new[] { "skip", " ", "also" });
        var conf = ClamdConfSupport.GetConfPath();
        Assert.StartsWith(_root, conf, StringComparison.Ordinal);
        var text = File.ReadAllText(conf);
        Assert.Contains("TCPSocket " + ClamdConfSupport.DefaultTcpPort, text);
        Assert.Contains("ExcludePath skip", text);
        Assert.DoesNotContain("ExcludePath  ", text);
        Assert.StartsWith(_root, ClamdConfSupport.GetPidPath(), StringComparison.Ordinal);
        Assert.StartsWith(_root, ClamdConfSupport.GetLogPath(), StringComparison.Ordinal);
        ClamdConfSupport.EnsureConf(db);
    }
}
