using optiCombat.Models;
using optiCombat.Platform;
using System.Runtime.Versioning;

namespace optiCombat.Services;

/// <summary>
/// Point d'entrée unifié pour les scans RTP / processus / USB :
/// tente d'abord le moteur distant via IPC (<see cref="ProtectionServiceHost"/>),
/// puis repli sur <see cref="ScanOrchestrator"/> (cœur Rust in-process si DLL présente).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProtectionScanGateway
{
    /// <summary>Processus --service-host : scans in-process (évite la boucle IPC vers soi-même).</summary>
    public static bool IsServiceHostProcess { get; set; }

    private readonly ScanOrchestrator _orchestrator;
    private readonly IUserPreferencesAccessor _prefs;
    private static readonly TimeSpan IpcScanTimeout = TimeSpan.FromSeconds(90);

    public ProtectionScanGateway(
        ScanOrchestrator orchestrator,
        IUserPreferencesAccessor? preferences = null)
    {
        _orchestrator = orchestrator;
        _prefs = preferences ?? new DefaultUserPreferencesAccessor();
    }

    /// <summary>Le service IPC est joignable (ProtectionServiceHost actif).</summary>
    public bool IsRemoteEngineReachable()
    {
        try
        {
            using var client = new ProtectionPipeClient(timeout: TimeSpan.FromSeconds(5));
            return client.IsServiceReachable();
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Scan via service-host IPC si disponible, sinon orchestrateur local.</summary>
    public async Task<ScanResult> ScanFileAsync(string filePath, CancellationToken ct = default)
    {
        if (ShouldPreferRemoteScan() && await TryScanViaIpcAsync(filePath, ct).ConfigureAwait(false) is { } ipc)
            return ipc;

        return await _orchestrator.ScanFileAsync(filePath, ct: ct).ConfigureAwait(false);
    }

    private bool ShouldPreferRemoteScan()
    {
        if (IsServiceHostProcess)
            return false;

        if (_prefs.Current.UsePlatformProtectionService)
        {
            PlatformProtectionBootstrap.EnsurePlatformProtectionRunning();
            return true;
        }

        return IsRemoteEngineReachable();
    }

    private static async Task<ScanResult?> TryScanViaIpcAsync(string filePath, CancellationToken ct)
    {
        try
        {
            using var client = new ProtectionPipeClient(timeout: IpcScanTimeout);
            var ping = await client.SendAsync(
                new ProtectionPipeRequest { Operation = ProtectionPipeOperations.Ping }, ct)
                .ConfigureAwait(false);
            if (!ping.Ok)
                return null;

            var response = await client.ScanPathAsync(filePath, ct).ConfigureAwait(false);
            return MapIpcResponse(filePath, response);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ProtectionScanGateway", $"IPC indisponible pour {filePath}", ex);
            return null;
        }
    }

    internal static ScanResult MapIpcResponse(string filePath, ProtectionPipeResponse response)
    {
        var result = new ScanResult
        {
            Type = ScanType.File,
            TargetPath = filePath,
            StartedAt = DateTime.Now,
            FinishedAt = DateTime.Now,
            FilesScanned = 1,
            Status = response.Ok ? ScanStatus.Completed : ScanStatus.Error,
            ErrorMessage = response.Ok ? null : response.Message,
        };

        if (response.Ok && !response.Clean && !string.IsNullOrWhiteSpace(response.ThreatName))
        {
            result.Threats.Add(new ThreatInfo
            {
                FilePath = filePath,
                VirusName = response.ThreatName,
                DetectedBy = MapEngine(response.Engine),
                Status = ThreatStatus.Detected,
            });
        }

        return result;
    }

    private static string MapEngine(string? engine) => engine switch
    {
        "optiCombat" or "opticombat" or "yara" or "clamav" or "ml" => engine ?? "optiCombat",
        null or "" => "optiCombat",
        _ => engine,
    };
}
