using optiCombat.Platform;
using System.IO;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace optiCombat.Services;

/// <summary>Serveur IPC du moteur de protection (mode --service-host / AMSI / UI distante).</summary>
[SupportedOSPlatform("windows")]
public sealed class ProtectionPipeServer : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    // Borne anti-DoS : le pipe est accessible aux utilisateurs authentifiés (cf. ProtectionPipeAcl),
    // donc on plafonne la taille d'un buffer AMSI/IPC pour éviter qu'un client local n'épuise
    // la mémoire ou le disque. ~96 Mo de base64 ≈ ~72 Mo décodés, large pour un scan AMSI légitime.
    private const int MaxScanBufferBase64Length = 96 * 1024 * 1024;

    /// <summary>Taille max d'une requête IPC (buffer base64 + enveloppe JSON).</summary>
    private const int MaxRequestBytes = MaxScanBufferBase64Length + 64 * 1024;

    /// <summary>
    /// Délai max de réception d'une requête : le serveur traite un client à la fois, un client
    /// connecté qui n'envoie rien bloquait auparavant tout l'IPC indéfiniment.
    /// </summary>
    private static readonly TimeSpan RequestReadTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Durée max d'un scan IPC synchrone (fichier ou buffer). Au-delà, annulation et
    /// libération du lease concurrent — évite qu'un scan bloqué monopolise les slots.
    /// </summary>
    public static readonly TimeSpan DefaultIpcScanTimeout = TimeSpan.FromSeconds(IpcScanRateLimiter.DefaultMaxLeaseHoldSeconds);

    /// <summary>Message renvoyé quand le plafond de scans IPC est atteint.</summary>
    public const string RateLimitedMessage = "Trop de requêtes";

    /// <summary>Message renvoyé quand le scan IPC dépasse <see cref="DefaultIpcScanTimeout"/>.</summary>
    public const string ScanTimeoutMessage = "Délai de scan dépassé";

    private readonly ScanOrchestrator _orchestrator;
    private readonly string _pipeName;
    private readonly string? _shutdownTokenOverride;
    private readonly Action? _onShutdown;
    private readonly IpcScanRateLimiter _scanRateLimiter;
    private readonly TimeSpan _scanTimeout;
    private string? _shutdownToken;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;

    public ProtectionPipeServer(
        ScanOrchestrator orchestrator,
        string? pipeName = null,
        string? shutdownToken = null,
        Action? onShutdown = null,
        IpcScanRateLimiter? scanRateLimiter = null,
        TimeSpan? scanTimeout = null)
    {
        _scanRateLimiter = scanRateLimiter ?? new IpcScanRateLimiter();
        _orchestrator = orchestrator;
        _pipeName = pipeName ?? ProtectionPipeNames.Protection;
        _shutdownTokenOverride = shutdownToken;
        _onShutdown = onShutdown;
        _scanTimeout = scanTimeout ?? DefaultIpcScanTimeout;
        if (_scanTimeout <= TimeSpan.Zero)
            _scanTimeout = DefaultIpcScanTimeout;
    }

    public void Start()
    {
        if (_listenTask != null)
            return;

        _shutdownToken = _shutdownTokenOverride ?? ProtectionPipeShutdownToken.Generate();
        try { ProtectionPipeShutdownToken.Persist(_shutdownToken); }
        catch (Exception ex) { AppLogger.Warn("ProtectionPipeServer", "Persist shutdown token", ex); }

        _cts = new CancellationTokenSource();
        _listenTask = Task.Run(() => ListenLoopAsync(_cts.Token));
        AppLogger.Info("ProtectionPipeServer", $"IPC démarré ({_pipeName})");
    }

    public async Task StopAsync()
    {
        if (_cts == null)
            return;

        _cts.Cancel();
        try
        {
            if (_listenTask != null)
                await _listenTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }

        _cts.Dispose();
        _cts = null;
        _listenTask = null;
    }

    /// <summary>
    /// Boucle d'écoute. La première instance est créée avec <c>FILE_FLAG_FIRST_PIPE_INSTANCE</c>,
    /// et l'instance suivante est toujours créée <b>avant</b> de libérer la courante : le nom du
    /// pipe n'est jamais libre, un processus local ne peut donc pas s'y substituer au serveur
    /// (audit 360 — auparavant l'instance était recréée après chaque client).
    /// </summary>
    private async Task ListenLoopAsync(CancellationToken ct)
    {
        NamedPipeServerStream? pipe;
        try
        {
            pipe = ProtectionPipeAcl.CreateListeningStream(_pipeName, firstInstance: true);
        }
        catch (Exception ex)
        {
            AppLogger.Error("ProtectionPipeServer",
                $"Pipe {_pipeName} déjà détenu par un autre processus ou inaccessible — IPC non démarré", ex);
            return;
        }

        try
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("ProtectionPipeServer", "WaitForConnection", ex);
                    pipe = await ReplaceInstanceAsync(pipe, ct).ConfigureAwait(false);
                    if (pipe == null)
                        return;
                    continue;
                }

                // Instance suivante prête avant de traiter (et de libérer) celle-ci.
                var current = pipe;
                pipe = TryCreateNextInstance();
                try
                {
                    await HandleClientAsync(current, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("ProtectionPipeServer", "HandleClient", ex);
                }
                finally
                {
                    await DisposeInstanceAsync(current).ConfigureAwait(false);
                }

                if (pipe == null)
                {
                    await Task.Delay(250, ct).ConfigureAwait(false);
                    pipe = TryCreateNextInstance();
                    if (pipe == null)
                        return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // arrêt demandé
        }
        finally
        {
            if (pipe != null)
                await DisposeInstanceAsync(pipe).ConfigureAwait(false);
        }
    }

    private NamedPipeServerStream? TryCreateNextInstance()
    {
        try
        {
            return ProtectionPipeAcl.CreateListeningStream(_pipeName);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ProtectionPipeServer", "Création de l'instance de pipe suivante", ex);
            return null;
        }
    }

    /// <summary>Remplace une instance en erreur en créant d'abord la suivante.</summary>
    private async Task<NamedPipeServerStream?> ReplaceInstanceAsync(NamedPipeServerStream broken, CancellationToken ct)
    {
        var next = TryCreateNextInstance();
        await DisposeInstanceAsync(broken).ConfigureAwait(false);
        if (next == null)
        {
            try { await Task.Delay(250, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return null; }
            next = TryCreateNextInstance();
        }
        return next;
    }

    private static async Task DisposeInstanceAsync(NamedPipeServerStream pipe)
    {
        try
        {
            if (pipe.IsConnected)
                pipe.Disconnect();
        }
        catch { /* best effort */ }
        await pipe.DisposeAsync().ConfigureAwait(false);
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        ProtectionPipeResponse response;
        try
        {
            string text;
            using (var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                readCts.CancelAfter(RequestReadTimeout);
                try
                {
                    text = await ProtectionPipeJsonFraming.ReadJsonPayloadAsync(pipe, readCts.Token, MaxRequestBytes)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    AppLogger.Warn("ProtectionPipeServer", "Client IPC sans requête complète — délai dépassé");
                    return;
                }
            }
            var request = JsonSerializer.Deserialize<ProtectionPipeRequest>(text, JsonOptions)
                ?? throw new InvalidOperationException("Requête IPC vide");
            response = await DispatchAsync(request, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            response = ProtectionPipeResponse.Error(ex.Message);
        }

        var outBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response, JsonOptions));
        await pipe.WriteAsync(outBytes, ct).ConfigureAwait(false);
        await pipe.FlushAsync(ct).ConfigureAwait(false);
    }

    private Task<ProtectionPipeResponse> DispatchAsync(ProtectionPipeRequest request, CancellationToken ct) =>
        Task.FromResult(Dispatch(request));

    private ProtectionPipeResponse Dispatch(ProtectionPipeRequest request)
    {
        switch (request.Operation)
        {
            case ProtectionPipeOperations.Ping:
                return ProtectionPipeResponse.SuccessClean();

            case ProtectionPipeOperations.GetStatus:
                return new ProtectionPipeResponse
                {
                    Ok = true,
                    Clean = true,
                    Message = _orchestrator.IsOptiCombatAvailable
                        ? "engine=opticombat;native=1"
                        : $"clam={_orchestrator.IsClamAvAvailable};yara={_orchestrator.IsYaraAvailable}",
                };

            case ProtectionPipeOperations.Shutdown:
                if (!ProtectionPipeShutdownToken.Validate(_shutdownToken, request.AuthToken))
                    return ProtectionPipeResponse.Error("Non autorisé");
                if (_onShutdown != null)
                    _onShutdown();
                else
                    _ = Task.Run(() => Environment.Exit(0));
                return ProtectionPipeResponse.SuccessClean();

            case ProtectionPipeOperations.ScanPath:
                if (!ScanPathValidation.IsSyntacticallyAcceptable(request.Path) || !File.Exists(request.Path))
                    return ProtectionPipeResponse.Error("Chemin invalide");
                if (!ScanPathValidation.TryNormalizeScanTarget(request.Path, out var fullPath, allowSensitive: false)
                    || !File.Exists(fullPath))
                    return ProtectionPipeResponse.Error("Chemin refusé");
                return WithRateLimit(ct => ScanPath(fullPath, ct));

            case ProtectionPipeOperations.ScanBuffer:
                if (string.IsNullOrWhiteSpace(request.BufferBase64))
                    return ProtectionPipeResponse.Error("Buffer vide");
                if (request.BufferBase64.Length > MaxScanBufferBase64Length)
                    return ProtectionPipeResponse.Error("Buffer trop volumineux");
                var buffer = request.BufferBase64;
                var contentName = request.ContentName ?? "amsi_buffer";
                return WithRateLimit(ct => ScanBuffer(buffer, contentName, ct));

            default:
                return ProtectionPipeResponse.Error($"Opération inconnue : {request.Operation}");
        }
    }

    private ProtectionPipeResponse WithRateLimit(Func<CancellationToken, ProtectionPipeResponse> scan)
    {
        if (!_scanRateLimiter.TryEnter(out var lease))
        {
            // Journalisation échantillonnée pour ne pas transformer le DoS en flood de log.
            if (_scanRateLimiter.RejectedCount % 100 == 1)
                AppLogger.Warn("ProtectionPipeServer", $"Scan IPC refusé (débit) — total refusés : {_scanRateLimiter.RejectedCount}");
            return ProtectionPipeResponse.Error(RateLimitedMessage);
        }

        using (lease)
        using (var timeoutCts = new CancellationTokenSource(_scanTimeout))
        {
            try
            {
                return scan(timeoutCts.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException
                                       || ex.GetBaseException() is OperationCanceledException)
            {
                AppLogger.Warn("ProtectionPipeServer", $"Scan IPC annulé après {_scanTimeout.TotalSeconds:0}s");
                return ProtectionPipeResponse.Error(ScanTimeoutMessage);
            }
        }
    }

    private ProtectionPipeResponse ScanPath(string path, CancellationToken ct)
    {
        var result = _orchestrator.ScanFileAsync(path, ct: ct).GetAwaiter().GetResult();
        ct.ThrowIfCancellationRequested();
        if (result.Threats.Count == 0)
            return ProtectionPipeResponse.SuccessClean();

        var threat = result.Threats[0];
        return ProtectionPipeResponse.Threat(threat.VirusName, threat.DetectedBy);
    }

    private ProtectionPipeResponse ScanBuffer(string bufferBase64, string contentName, CancellationToken ct)
    {
        var bytes = Convert.FromBase64String(bufferBase64);
        var tempDir = Path.Combine(Path.GetTempPath(), "opticombat_ipc_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var tempFile = Path.Combine(tempDir, Path.GetFileName(contentName));
        if (string.IsNullOrWhiteSpace(Path.GetFileName(tempFile)))
            tempFile = Path.Combine(tempDir, "amsi_buffer.bin");

        try
        {
            File.WriteAllBytes(tempFile, bytes);
            return ScanPath(tempFile, ct);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    public void Dispose() => _ = StopAsync();
}
