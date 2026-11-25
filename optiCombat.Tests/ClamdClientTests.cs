using System.Net;
using System.Net.Sockets;
using System.Text;
using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ClamdClientTests
{
    [Fact]
    public async Task PingAsync_returns_true_on_PONG()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var accept = listener.AcceptTcpClientAsync();

        using var client = new ClamdClient("127.0.0.1", port);
        var pingTask = client.PingAsync();

        var server = await accept;
        await using var stream = server.GetStream();
        var buffer = new byte[64];
        int read = await stream.ReadAsync(buffer);
        var cmd = Encoding.UTF8.GetString(buffer, 0, read).Trim();
        Assert.Equal("PING", cmd);

        var pong = Encoding.UTF8.GetBytes("PONG\n");
        await stream.WriteAsync(pong);

        Assert.True(await pingTask);
        listener.Stop();
    }

    [Fact]
    public async Task PingAsync_returns_false_when_the_reply_has_no_newline()
    {
        var (listener, port) = StartListener();
        using var client = new ClamdClient("127.0.0.1", port);
        var ping = client.PingAsync();

        using var server = await listener.AcceptTcpClientAsync();
        await using var stream = server.GetStream();
        await ReadCommandAsync(stream);
        await stream.WriteAsync(Encoding.UTF8.GetBytes("PONG"));
        server.Client.Shutdown(SocketShutdown.Send);

        Assert.False(await ping);
        listener.Stop();
    }

    [Fact]
    public async Task ScanFileAsync_keeps_the_detection_when_the_line_is_complete()
    {
        var (listener, port) = StartListener();
        using var client = new ClamdClient("127.0.0.1", port);
        var scan = client.ScanFileAsync(Path.GetTempPath());

        using var server = await listener.AcceptTcpClientAsync();
        await using var stream = server.GetStream();
        var command = await ReadCommandAsync(stream);
        Assert.StartsWith("nSCAN ", command, StringComparison.Ordinal);

        await stream.WriteAsync(Encoding.UTF8.GetBytes("C:\\data\\evil.exe: Win.Test.EICAR_HDB-1 FOUND\n"));

        var response = await scan;
        Assert.True(response.Completed);
        Assert.Contains("FOUND", response.Text, StringComparison.Ordinal);
        listener.Stop();
    }

    [Fact]
    public async Task ScanFileAsync_reports_incomplete_when_clamd_closes_mid_line()
    {
        var (listener, port) = StartListener();
        using var client = new ClamdClient("127.0.0.1", port);
        var scan = client.ScanFileAsync(Path.GetTempPath());

        using var server = await listener.AcceptTcpClientAsync();
        await using var stream = server.GetStream();
        await ReadCommandAsync(stream);
        await stream.WriteAsync(Encoding.UTF8.GetBytes("C:\\data\\evil.exe: Win.Test.EICAR_HDB-1 FOUN"));
        server.Client.Shutdown(SocketShutdown.Send);

        var response = await scan;
        Assert.False(response.Completed);
        listener.Stop();
    }

    [Fact]
    public async Task ScanRecursiveAsync_waits_for_a_slow_clamd_and_keeps_the_detection()
    {
        // clamd peut rester silencieux plusieurs secondes sur un gros dossier :
        // la détection envoyée ensuite doit être lue, pas perdue.
        var (listener, port) = StartListener();
        using var client = new ClamdClient("127.0.0.1", port);
        var scan = client.ScanRecursiveAsync(Path.GetTempPath());

        using var server = await listener.AcceptTcpClientAsync();
        await using var stream = server.GetStream();
        var command = await ReadCommandAsync(stream);
        Assert.StartsWith("nCONTSCAN ", command, StringComparison.Ordinal);

        await Task.Delay(1500);
        await stream.WriteAsync(Encoding.UTF8.GetBytes("C:\\data\\evil.exe: Win.Test.EICAR_HDB-1 FOUND\n"));
        server.Client.Shutdown(SocketShutdown.Send);

        var response = await scan;
        Assert.True(response.Completed);
        Assert.Contains("FOUND", response.Text, StringComparison.Ordinal);
        listener.Stop();
    }

    [Fact]
    public async Task ScanRecursiveAsync_reports_incomplete_when_clamd_closes_mid_line()
    {
        var (listener, port) = StartListener();
        using var client = new ClamdClient("127.0.0.1", port);
        var scan = client.ScanRecursiveAsync(Path.GetTempPath());

        using var server = await listener.AcceptTcpClientAsync();
        await using var stream = server.GetStream();
        await ReadCommandAsync(stream);
        await stream.WriteAsync(Encoding.UTF8.GetBytes("C:\\data\\a.exe: O"));
        server.Client.Shutdown(SocketShutdown.Send);

        var response = await scan;
        Assert.False(response.Completed);
        listener.Stop();
    }

    [Fact]
    public async Task ScanRecursiveAsync_reports_incomplete_when_clamd_sends_nothing()
    {
        var (listener, port) = StartListener();
        using var client = new ClamdClient("127.0.0.1", port);
        var scan = client.ScanRecursiveAsync(Path.GetTempPath());

        using var server = await listener.AcceptTcpClientAsync();
        await using var stream = server.GetStream();
        await ReadCommandAsync(stream);
        server.Client.Shutdown(SocketShutdown.Send);

        var response = await scan;
        Assert.False(response.Completed);
        Assert.Equal(string.Empty, response.Text);
        listener.Stop();
    }

    private static (TcpListener Listener, int Port) StartListener()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return (listener, ((IPEndPoint)listener.LocalEndpoint).Port);
    }

    private static async Task<string> ReadCommandAsync(NetworkStream stream)
    {
        var buffer = new byte[4096];
        var sb = new StringBuilder();
        while (!sb.ToString().Contains('\n', StringComparison.Ordinal))
        {
            var read = await stream.ReadAsync(buffer);
            if (read <= 0)
                break;
            sb.Append(Encoding.UTF8.GetString(buffer, 0, read));
        }

        return sb.ToString().Trim();
    }
}
