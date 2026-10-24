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
        // La copie de sécurité (préférence BackupBeforeQuarantine) est faite par QuarantineManager :
        // la faire aussi ici produisait deux copies par menace.
        _ = preferences;

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

    /// <summary>Tests uniquement : emplacement de MpCmdRun.exe.</summary>
    internal static string? MpCmdRunPathOverride { get; set; }

    /// <summary>Lance une analyse Defender ciblée (MpCmdRun) si disponible — complément cloud Microsoft.</summary>
    public static RepairResult TryDefenderTargetedScan(string filePath)
    {
        try
        {
            var mp = MpCmdRunPathOverride ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Windows Defender", "MpCmdRun.exe");

            if (!File.Exists(mp))
                return new RepairResult { Success = false, Message = "Defender indisponible" };

            // ArgumentList : un chemin contenant des guillemets ne peut pas injecter d'options MpCmdRun.
            var psi = new ProcessStartInfo
            {
                FileName = mp,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (var arg in new[] { "-Scan", "-ScanType", "3", "-File", filePath, "-DisableRemediation" })
                psi.ArgumentList.Add(arg);
            var outcome = SystemShell.Current.Run(psi, 120_000);
            return new RepairResult
            {
                Success = outcome.Succeeded,
                UsedDefenderFallback = true,
                Message = $"Defender MpCmdRun exit={outcome.ExitCode}",
            };
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ThreatRepairService", "TryDefenderTargetedScan", ex);
            return new RepairResult { Success = false, Message = ex.Message };
        }
    }
}
