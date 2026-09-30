using System.IO;
using System.Net.Sockets;
using System.Text;

namespace optiCombat.Services
{
    /// <summary>Client TCP minimal pour le protocole clamd (PING, SCAN, CONTSCAN).</summary>
    internal sealed class ClamdClient : IDisposable
    {
        private readonly string _host;
        private readonly int _port;
        private TcpClient? _client;
        private NetworkStream? _stream;
        private StreamReader? _reader;
        private readonly SemaphoreSlim _session = new(1, 1);

        public ClamdClient(string host = "127.0.0.1", int port = ClamdConfSupport.DefaultTcpPort)
        {
            _host = host;
            _port = port;
        }

        public async Task<bool> PingAsync(CancellationToken ct = default)
        {
            var response = await SendCommandAsync("PING", ct).ConfigureAwait(false);
            return response.Trim().Equals("PONG", StringComparison.OrdinalIgnoreCase);
        }

        public async Task<string> ScanFileAsync(string filePath, CancellationToken ct = default)
        {
            var path = Path.GetFullPath(filePath);
            return await SendCommandAsync("SCAN " + path, ct).ConfigureAwait(false);
        }

        public async Task<string> ScanRecursiveAsync(string directoryPath, CancellationToken ct = default)
        {
            var path = Path.GetFullPath(directoryPath);
            return await SendCommandAsync("CONTSCAN " + path, ct).ConfigureAwait(false);
        }

        public async Task<string> SendCommandAsync(string command, CancellationToken ct = default)
        {
            await _session.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await EnsureConnectedAsync(ct).ConfigureAwait(false);

                if (_stream == null || _reader == null)
                    throw new InvalidOperationException("Connexion clamd indisponible.");

                var payload = Encoding.UTF8.GetBytes(command + "\n");
                await _stream.WriteAsync(payload, ct).ConfigureAwait(false);
                await _stream.FlushAsync(ct).ConfigureAwait(false);

                return await ReadResponseAsync(command, ct).ConfigureAwait(false);
            }
            finally
            {
                _session.Release();
            }
        }

        private async Task EnsureConnectedAsync(CancellationToken ct)
        {
            if (_client?.Connected == true) return;

            DisposeSocket();

            _client = new TcpClient();
            await _client.ConnectAsync(_host, _port, ct).ConfigureAwait(false);
            _stream = _client.GetStream();
            _reader = new StreamReader(_stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        }

        private async Task<string> ReadResponseAsync(string command, CancellationToken ct)
        {
            var reader = _reader;
            if (reader == null)
                return string.Empty;

            var singleLine = command.Equals("PING", StringComparison.OrdinalIgnoreCase)
                || command.StartsWith("SCAN ", StringComparison.OrdinalIgnoreCase);

            var sb = new StringBuilder();
            try
            {
                if (singleLine)
                {
                    var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                    if (line != null)
                        sb.Append(line);
                    return sb.ToString();
                }

                while (!ct.IsCancellationRequested)
                {
                    using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    idle.CancelAfter(TimeSpan.FromMilliseconds(400));
                    try
                    {
                        var line = await reader.ReadLineAsync(idle.Token).ConfigureAwait(false);
                        if (line == null)
                            break;
                        if (sb.Length > 0)
                            sb.AppendLine();
                        sb.Append(line);
                    }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                    {
                        break;
                    }
                }
            }
            finally
            {
                DisposeSocket();
            }

            return sb.ToString();
        }

        private void DisposeSocket()
        {
            try { _reader?.Dispose(); } catch { /* ignore */ }
            try { _stream?.Dispose(); } catch { /* ignore */ }
            try { _client?.Dispose(); } catch { /* ignore */ }
            _reader = null;
            _stream = null;
            _client = null;
        }

        public void Dispose()
        {
            DisposeSocket();
            _session.Dispose();
        }
    }
}

