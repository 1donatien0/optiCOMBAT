using optiCombat.Localization;
using optiCombat.Models;
using System.IO;

namespace optiCombat.Services
{
    /// <summary>
    /// Fusionne les résultats d'une série de scans par dossier (quick/full multi-répertoires).
    /// Évite la duplication entre <see cref="ClamAvEngine"/> et <see cref="ScanOrchestrator"/>.
    /// </summary>
    internal static class MultiTargetScanAggregator
    {
        /// <param name="skipIfDirectoryMissing">Si true, ignore les cibles dont le dossier n'existe pas.</param>
        /// <param name="reportTargetProgress">Si true, émet une progression « Cible i/n ».</param>
        public static async Task<ScanResult> AggregateAsync(
            ScanType type,
            IReadOnlyList<string> targets,
            Func<string, IProgress<ScanProgress>?, CancellationToken, Task<ScanResult>> scanOneAsync,
            CancellationToken ct,
            IProgress<ScanProgress>? progress = null,
            bool skipIfDirectoryMissing = false,
            bool reportTargetProgress = false)
        {
            var merged = new ScanResult
            {
                Type = type,
                TargetPath = string.Join(", ", targets),
                StartedAt = DateTime.Now,
                Status = ScanStatus.Running
            };

            int denom = targets.Count;
            int idx = 0;
            int filesBaseline = 0;

            foreach (var target in targets)
            {
                if (ct.IsCancellationRequested) break;
                if (skipIfDirectoryMissing && !Directory.Exists(target))
                    continue;

                idx++;
                if (reportTargetProgress && progress != null && denom > 0)
                {
                    progress.Report(new ScanProgress
                    {
                        Message = LocalizationService.Format("Scan_Zone_Starting", idx, denom, target),
                        Phase = ScanPhase.Scanning,
                        CurrentFilePath = target,
                        FilesScanned = filesBaseline,
                    });
                }

                var relay = new ScanProgressRelay(filesBaseline);
                var sub = await scanOneAsync(target, relay.ToParent(progress), ct).ConfigureAwait(false);

                filesBaseline = Math.Max(filesBaseline, Math.Max(relay.FilesScannedHigh, sub.FilesScanned));
                merged.FilesScanned = filesBaseline;
                merged.FilesSkipped += sub.FilesSkipped;
                merged.TotalBytesScanned += sub.TotalBytesScanned;
                foreach (var t in sub.Threats)
                    ScanThreatMerger.AddOrMergeThreat(merged.Threats, t);

                if (progress != null)
                {
                    progress.Report(new ScanProgress
                    {
                        Message = LocalizationService.Format("Scan_Zone_Done", idx, denom, filesBaseline),
                        Phase = ScanPhase.Scanning,
                        FilesScanned = filesBaseline,
                        ThreatsFound = merged.Threats.Count,
                        CurrentFilePath = target,
                    });
                }
            }

            merged.FinishedAt = DateTime.Now;
            merged.Status = ct.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
            return merged;
        }

    }
}
