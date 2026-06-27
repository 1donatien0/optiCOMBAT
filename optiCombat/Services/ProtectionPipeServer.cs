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

    private readonly ScanOrchestrator _orchestrator;
    private readonly string _pipeName;
    private readonly string? _shutdownTokenOverride;
    private readonly Action? _onShutdown;
    private string? _shutdownToken;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;

    public ProtectionPipeServer(ScanOrchestrator orchestrator, string? pipeName = null, string? shutdownToken = null, Action? onShutdown = null)
    {
        _orchestrator = orchestrator;
        _pipeName = pipeName ?? ProtectionPipeNames.Protection;
        _shutdownTokenOverride = shutdownToken;
        _onShutdown = onShutdown;
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

    private async Task ListenLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var pipe = ProtectionPipeAcl.CreateListeningStream(_pipeName);
            try
            {
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
                await HandleClientAsync(pipe, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("ProtectionPipeServer", "ListenLoop", ex);
                await Task.Delay(250, ct).ConfigureAwait(false);
            }
            finally
            {
                try
                {
                    if (pipe.IsConnected)
                        pipe.Disconnect();
                }
                catch { /* best effort */ }
                await pipe.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        ProtectionPipeResponse response;
        try
        {
            var text = await ProtectionPipeJsonFraming.ReadJsonPayloadAsync(pipe, ct).ConfigureAwait(false);
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
                if (string.IsNullOrWhiteSpace(request.Path) || !File.Exists(request.Path))
                    return ProtectionPipeResponse.Error("Chemin invalide");
                var fullPath = Path.GetFullPath(request.Path);
                if (QuarantineManager.IsSensitivePath(fullPath))
                    return ProtectionPipeResponse.Error("Chemin refusé");
                return ScanPath(fullPath);

            case ProtectionPipeOperations.ScanBuffer:
                if (string.IsNullOrWhiteSpace(request.BufferBase64))
                    return ProtectionPipeResponse.Error("Buffer vide");
                if (request.BufferBase64.Length > MaxScanBufferBase64Length)
                    return ProtectionPipeResponse.Error("Buffer trop volumineux");
                return ScanBuffer(request.BufferBase64, request.ContentName ?? "amsi_buffer");

            default:
                return ProtectionPipeResponse.Error($"Opération inconnue : {request.Operation}");
        }
    }

    private ProtectionPipeResponse ScanPath(string path)
    {
        var result = _orchestrator.ScanFileAsync(path).GetAwaiter().GetResult();
        if (result.Threats.Count == 0)
            return ProtectionPipeResponse.SuccessClean();

        var threat = result.Threats[0];
        return ProtectionPipeResponse.Threat(threat.VirusName, threat.DetectedBy);
    }

    private ProtectionPipeResponse ScanBuffer(string bufferBase64, string contentName)
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
            return ScanPath(tempFile);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    public void Dispose() => _ = StopAsync();
}
