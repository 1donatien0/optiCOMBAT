using optiCombat.Models;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;

namespace optiCombat.Services;

/// <summary>
/// Remédiation avancée : sauvegarde, quarantaine, et recours Defender pour les cas non réparables par ClamAV.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ThreatRepairService
{
    public sealed class RepairResult
    {
        public bool Success { get; init; }
        public string Message { get; init; } = string.Empty;
        public bool UsedDefenderFallback { get; init; }
    }

    public static RepairResult TryRemediate(
        ThreatInfo threat,
        QuarantineManager quarantine,
        IUserPreferencesAccessor? preferences = null)
    {
        if ((preferences ?? new DefaultUserPreferencesAccessor()).Current.BackupBeforeQuarantine)
            ThreatRemediationService.TryCreateSafetyCopy(threat);

        if (quarantine.Quarantine(threat))
        {
            return new RepairResult
            {
                Success = true,
                Message = Localization.LocalizationService.GetString("Repair_Quarantined"),
            };
        }

        return new RepairResult
        {
            Success = false,
            Message = Localization.LocalizationService.GetString("Repair_QuarantineFailed"),
        };
    }

    /// <summary>Lance une analyse Defender ciblée (MpCmdRun) si disponible — complément cloud Microsoft.</summary>
    public static RepairResult TryDefenderTargetedScan(string filePath)
    {
        try
        {
            var mp = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Windows Defender", "MpCmdRun.exe");

            if (!File.Exists(mp))
                return new RepairResult { Success = false, Message = "Defender indisponible" };

            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = mp,
                Arguments = $"-Scan -ScanType 3 -File \"{filePath}\" -DisableRemediation",
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            proc?.WaitForExit(120_000);
            return new RepairResult
            {
                Success = proc?.ExitCode == 0,
                UsedDefenderFallback = true,
                Message = $"Defender MpCmdRun exit={proc?.ExitCode}",
            };
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ThreatRepairService", "TryDefenderTargetedScan", ex);
            return new RepairResult { Success = false, Message = ex.Message };
        }
    }
}
