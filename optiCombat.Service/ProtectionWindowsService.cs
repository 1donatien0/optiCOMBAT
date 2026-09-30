using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using optiCombat.Platform;
using System.Diagnostics;

namespace optiCombat.Service;

public sealed class ProtectionWindowsService : BackgroundService
{
    private const string EventSourceName = "optiCombat Protection";
    private const string EventLogName = "Application";

    private readonly ServiceHostRestartPolicy _restartPolicy = new();
    private Process? _hostProcess;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var exe = Path.Combine(AppContext.BaseDirectory, "optiCombat.exe");
        if (!File.Exists(exe))
        {
            WriteEvent("optiCombat.exe introuvable dans " + AppContext.BaseDirectory, EventLogEntryType.Error);
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            if (_hostProcess is { HasExited: false })
            {
                _restartPolicy.OnHostHealthy();
                await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken).ConfigureAwait(false);
                continue;
            }

            if (_hostProcess is { HasExited: true })
            {
                var code = _hostProcess.ExitCode;
                _restartPolicy.OnHostExit();
                WriteEvent(
                    $"Hôte --service-host terminé (exit={code}). Échecs consécutifs={_restartPolicy.ConsecutiveFailures}, relances/h={_restartPolicy.RestartsInWindow}",
                    EventLogEntryType.Warning);
            }

            if (!_restartPolicy.CanRestart())
            {
                WriteEvent(
                    $"Limite de relances atteinte ({ServiceHostRestartPolicy.MaxRestartsPerHour}/h). Pause 5 min.",
                    EventLogEntryType.Error);
                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken).ConfigureAwait(false);
                continue;
            }

            var delay = _restartPolicy.GetBackoffDelay();
            if (delay > TimeSpan.Zero)
                await Task.Delay(delay, stoppingToken).ConfigureAwait(false);

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = exe,
                    WorkingDirectory = AppContext.BaseDirectory,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                psi.ArgumentList.Add("--service-host");
                _hostProcess = Process.Start(psi);

                if (_hostProcess == null)
                {
                    _restartPolicy.OnHostExit();
                    WriteEvent("Process.Start a retourné null pour --service-host", EventLogEntryType.Error);
                }
                else
                {
                    WriteEvent($"Hôte --service-host démarré (PID {_hostProcess.Id})", EventLogEntryType.Information);
                }
            }
            catch (Exception ex)
            {
                _restartPolicy.OnHostExit();
                WriteEvent("Échec démarrage --service-host : " + ex.Message, EventLogEntryType.Error);
            }

            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var client = new ProtectionPipeClient();
            await client.RequestShutdownAsync(cancellationToken).ConfigureAwait(false);
        }
        catch { /* ignore */ }

        try
        {
            if (_hostProcess is { HasExited: false })
                _hostProcess.Kill(entireProcessTree: true);
        }
        catch { /* ignore */ }

        WriteEvent("Service Windows arrêté", EventLogEntryType.Information);
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    private static void WriteEvent(string message, EventLogEntryType type)
    {
        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            if (!EventLog.SourceExists(EventSourceName))
                EventLog.CreateEventSource(EventSourceName, EventLogName);

            EventLog.WriteEntry(EventSourceName, message, type);
        }
        catch
        {
            try { EventLog.WriteEntry("optiCombat.Service", message, type); }
            catch { /* ignore */ }
        }
    }
}
