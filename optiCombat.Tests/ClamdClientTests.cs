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
}
