using System.IO;
using System.Net.Sockets;
using System.Text;

namespace optiCombat.Services
{
    /// <summary>Réponse d'une commande clamd.</summary>
    /// <param name="Text">Texte reçu (sans le saut de ligne final).</param>
    /// <param name="Completed">
    /// Vrai seulement si clamd a terminé sa réponse : saut de ligne vu pour PING/nSCAN,
    /// fin de connexion après un dernier saut de ligne pour nCONTSCAN. Faux = réponse
    /// tronquée ou absente : le scan ne doit jamais être présenté comme « propre ».
    /// </param>
    internal readonly record struct ClamdResponse(string Text, bool Completed);

    /// <summary>Réponse clamd incomplète : le scan correspondant n'est pas fiable.</summary>
    internal sealed class ClamdIncompleteResponseException : IOException
    {
        public ClamdIncompleteResponseException(string message) : base(message) { }
    }

    /// <summary>Client TCP minimal pour le protocole clamd (PING, nSCAN, nCONTSCAN).</summary>
    internal sealed class ClamdClient : IDisposable
    {
        /// <summary>Plafond d'une réponse multi-lignes (nCONTSCAN) gardée en mémoire.</summary>
        internal const int MaxResponseChars = 16 * 1024 * 1024;

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
            return response.Completed
                && response.Text.Trim().Equals("PONG", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Analyse un fichier. Préfixe « n » : la réponse est une ligne terminée par un saut de ligne.
        /// Sans ce saut, la ligne est incomplète (connexion coupée au milieu) et le scan n'est pas fiable.
        /// </summary>
        public async Task<ClamdResponse> ScanFileAsync(string filePath, CancellationToken ct = default)
        {
            var path = Path.GetFullPath(filePath);
            return await SendCommandAsync("nSCAN " + path, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// Analyse récursive. Préfixe « n » : chaque ligne se termine par un saut de ligne et
        /// clamd ferme la connexion à la fin. On lit jusqu'à cette fermeture, sans délai
        /// d'inactivité : clamd peut rester silencieux longtemps sur un gros dossier.
        /// </summary>
        public async Task<ClamdResponse> ScanRecursiveAsync(string directoryPath, CancellationToken ct = default)
        {
            var path = Path.GetFullPath(directoryPath);
            return await SendCommandAsync("nCONTSCAN " + path, ct).ConfigureAwait(false);
        }

        public async Task<ClamdResponse> SendCommandAsync(string command, CancellationToken ct = default)
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

        private async Task<ClamdResponse> ReadResponseAsync(string command, CancellationToken ct)
        {
            var reader = _reader;
            if (reader == null)
                return new ClamdResponse(string.Empty, false);

            var singleLine = command.Equals("PING", StringComparison.OrdinalIgnoreCase)
                || command.StartsWith("nSCAN ", StringComparison.OrdinalIgnoreCase)
                || command.StartsWith("SCAN ", StringComparison.OrdinalIgnoreCase);

            try
            {
                if (singleLine)
                    return await ReadSingleLineAsync(reader, ct).ConfigureAwait(false);

                // Lecture jusqu'à la fermeture par clamd. Seul l'appelant (ct) peut
                // interrompre : une annulation remonte en OperationCanceledException.
                var sb = new StringBuilder();
                var buffer = new char[8192];
                while (true)
                {
                    var read = await reader.ReadAsync(buffer.AsMemory(), ct).ConfigureAwait(false);
                    if (read <= 0)
                        break;
                    sb.Append(buffer, 0, read);
                    if (sb.Length > MaxResponseChars)
                    {
                        AppLogger.Warn("ClamdClient", $"Réponse clamd au-delà de {MaxResponseChars} caractères : tronquée.");
                        return new ClamdResponse(sb.ToString(), false);
                    }
                }

                var text = sb.ToString();
                var completed = text.Length > 0 && text.EndsWith('\n');
                return new ClamdResponse(text.TrimEnd('\r', '\n'), completed);
            }
            finally
            {
                DisposeSocket();
            }
        }

        /// <summary>
        /// Une ligne PING ou nSCAN. <see cref="StreamReader.ReadLineAsync"/> renvoie aussi le
        /// texte quand la socket se ferme sans saut de ligne : ce cas doit rester incomplet.
        /// On s'arrête au premier saut de ligne, sans attendre la fermeture (clamd peut garder
        /// la connexion ouverte après PONG).
        /// </summary>
        private static async Task<ClamdResponse> ReadSingleLineAsync(StreamReader reader, CancellationToken ct)
        {
            var sb = new StringBuilder();
            var buffer = new char[1024];
            while (true)
            {
                var read = await reader.ReadAsync(buffer.AsMemory(), ct).ConfigureAwait(false);
                if (read <= 0)
                    return new ClamdResponse(TrimTrailingCr(sb), false);

                var newlineAt = Array.IndexOf(buffer, '\n', 0, read);
                if (newlineAt >= 0)
                {
                    sb.Append(buffer, 0, newlineAt);
                    return new ClamdResponse(TrimTrailingCr(sb), true);
                }

                sb.Append(buffer, 0, read);
                if (sb.Length > MaxResponseChars)
                {
                    AppLogger.Warn("ClamdClient", $"Réponse clamd au-delà de {MaxResponseChars} caractères : tronquée.");
                    return new ClamdResponse(sb.ToString(), false);
                }
            }
        }

        private static string TrimTrailingCr(StringBuilder sb)
        {
            if (sb.Length > 0 && sb[^1] == '\r')
                sb.Length--;
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
