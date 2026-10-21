using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace optiCombat.Services;

/// <summary>Pont user-mode vers le minifilter noyau (quand optiCombat.Minifilter.sys est chargé).</summary>
[SupportedOSPlatform("windows")]
public static class MinifilterUserBridge
{
    private const uint OpticombatFltPortName = 0;
    private static ScanOrchestrator? _orchestrator;
    private static CancellationTokenSource? _cts;
    private static Task? _worker;

    public static void TryStart(ScanOrchestrator orchestrator)
    {
        if (_worker != null)
            return;

        _orchestrator = orchestrator;
        _cts = new CancellationTokenSource();
        _worker = Task.Run(() => WorkerLoopAsync(_cts.Token));
    }

    public static void Stop()
    {
        _cts?.Cancel();
        _worker = null;
        _orchestrator = null;
    }

    private static async Task WorkerLoopAsync(CancellationToken ct)
    {
        // Le port de communication kernel sera branché lorsque le driver est signé et chargé.
        // Le stub noyau documente l'interface ; le pont reste inactif sans driver signé.
        AppLogger.Info("MinifilterUserBridge", "Pont minifilter prêt (attente driver)");
        try
        {
            await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
    }

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(
        string portName,
        uint options,
        IntPtr context,
        ushort sizeOfContext,
        IntPtr securityAttributes,
        out IntPtr port);
}
