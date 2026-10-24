using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using optiCombat.Platform;

namespace optiCombat.Tests;

/// <summary>
/// Client IPC contre un serveur de pipe nommé minimal côté test (sans ACL : seul le client est
/// testé ici ; le vrai serveur et son ACL sont couverts par ProtectionPipeServerTests sous Windows).
/// </summary>
[Collection(nameof(ProtectionPipeClientTests))]
public sealed class ProtectionPipeClientTests : IDisposable
{
    private readonly string _pipe = "oc-test-" + Guid.NewGuid().ToString("N");
    private readonly CancellationTokenSource _cts = new();
    private readonly List<ProtectionPipeRequest> _requests = new();
    private readonly string _tokenDir = Path.Combine(Path.GetTempPath(), "oc_pipetok_" + Guid.NewGuid().ToString("N"));
    private readonly string _previousToken = ProtectionPipeShutdownToken.TokenFilePath;
    private Task? _server;

    public void Dispose()
    {
        _cts.Cancel();
        try { _server?.Wait(3000); } catch { }
        _cts.Dispose();
        ProtectionPipeShutdownToken.TokenFilePath = _previousToken;
        try { Directory.Delete(_tokenDir, true); } catch { }
    }

    private NamedPipeServerStream CreateInstance() => new(
        _pipe, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
        PipeTransmissionMode.Byte, PipeOptions.Asynchronous);

    /// <summary>
    /// Faux serveur. Chaque instance du tube existe AVANT que le client puisse en avoir besoin :
    /// la première est créée avant le retour de <c>Serve</c>, la suivante dès qu'une connexion est
    /// acceptée. Auparavant elles étaient créées dans la tâche de fond : le client pouvait se
    /// connecter avant (test instable, environ une exécution sur trois sous Linux).
    /// </summary>
    private void Serve(Func<ProtectionPipeRequest, ProtectionPipeResponse> respond, int connections)
    {
        var first = CreateInstance();
        _server = Task.Run(async () =>
        {
            var next = first;
            for (var i = 0; i < connections && !_cts.IsCancellationRequested; i++)
            {
                await using var server = next;
                using var connect = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                connect.CancelAfter(TimeSpan.FromSeconds(8));
                await server.WaitForConnectionAsync(connect.Token).ConfigureAwait(false);
                next = i + 1 < connections ? CreateInstance() : null!;
                var text = await ProtectionPipeJsonFraming.ReadJsonPayloadAsync(server, _cts.Token).ConfigureAwait(false);
                var request = JsonSerializer.Deserialize<ProtectionPipeRequest>(text, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
                lock (_requests)
                    _requests.Add(request);
                var reply = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(respond(request)));
                await server.WriteAsync(reply, _cts.Token).ConfigureAwait(false);
                await server.FlushAsync(_cts.Token).ConfigureAwait(false);
                // WaitForPipeDrain bloque indéfiniment si le client a déjà fermé le tube
                // (course habituelle sous Windows). On attend plutôt la déconnexion, avec un délai.
                using var closed = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                closed.CancelAfter(TimeSpan.FromSeconds(5));
                try
                {
                    var tail = new byte[1];
                    await server.ReadAsync(tail, closed.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { }
                catch (IOException) { }
            }
            next?.Dispose();
        });
    }

    [Fact]
    public async Task Ping_scan_buffer_and_status_roundtrip()
    {
        Serve(r => r.Operation switch
        {
            ProtectionPipeOperations.ScanBuffer => ProtectionPipeResponse.Threat("Buf.Test", "yara"),
            _ => ProtectionPipeResponse.SuccessClean(),
        }, connections: 4);
        using var client = new ProtectionPipeClient(_pipe, TimeSpan.FromSeconds(10));

        Assert.True(client.IsServiceReachable());
        var buf = await client.ScanBufferAsync(Encoding.UTF8.GetBytes("abc"), "mem.bin");
        Assert.False(buf.Clean);
        Assert.Equal("Buf.Test", buf.ThreatName);
        Assert.True((await client.GetStatusAsync()).Ok);
        Assert.True((await client.ScanPathAsync("/tmp/x")).Clean);

        lock (_requests)
        {
            Assert.Equal(Convert.ToBase64String(Encoding.UTF8.GetBytes("abc")), _requests[1].BufferBase64);
            Assert.Equal("mem.bin", _requests[1].ContentName);
            Assert.Equal("/tmp/x", _requests[3].Path);
        }
    }

    [Fact]
    public async Task Shutdown_sends_the_persisted_token_and_is_skipped_without_one()
    {
        ProtectionPipeShutdownToken.TokenFilePath = Path.Combine(_tokenDir, "ipc_shutdown.token");
        using var client = new ProtectionPipeClient(_pipe, TimeSpan.FromSeconds(10));
        await client.RequestShutdownAsync(); // pas de jeton : aucune connexion tentée

        var token = ProtectionPipeShutdownToken.Generate();
        ProtectionPipeShutdownToken.Persist(token);
        // Persist pose une ACL administrateurs. Sans élévation, le même processus ne peut
        // plus relire le fichier : on republie le jeton dans un fichier lisible pour exercer l'envoi.
        if (!ProtectionPipeShutdownToken.TryRead(out _))
        {
            var readableDir = Path.Combine(Path.GetTempPath(), "oc_pipe_readable_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(readableDir);
            var readable = Path.Combine(readableDir, "ipc_shutdown.token");
            File.WriteAllText(readable, token);
            ProtectionPipeShutdownToken.TokenFilePath = readable;
        }
        Serve(_ => ProtectionPipeResponse.SuccessClean(), connections: 1);
        await client.RequestShutdownAsync();
        await _server!;

        lock (_requests)
        {
            var r = Assert.Single(_requests);
            Assert.Equal(ProtectionPipeOperations.Shutdown, r.Operation);
            Assert.Equal(token, r.AuthToken);
        }
    }

    [Fact]
    public void Unreachable_service_is_reported()
    {
        using var client = new ProtectionPipeClient(_pipe + "-absent", TimeSpan.FromMilliseconds(300));
        Assert.False(client.IsServiceReachable());
    }
}
