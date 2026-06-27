using optiCombat.Localization;
using optiCombat.Models;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;

namespace optiCombat.Services
{
    /// <summary>
    /// Centralise les actions exécutables depuis l'UI antivirus.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class AntivirusActions
    {
        private readonly QuarantineManager _quarantine;
        private readonly ISignatureUpdateCanceller? _freshclam;
        private readonly ISignatureUpdateCanceller? _rules;
        private readonly Func<string, ThreatInfo?>? _threatLookup;
        private readonly IExclusionSettingsAccessor _exclusions;

        public AntivirusActions(ServiceContainer container)
            : this(
                container.Quarantine,
                container.FreshclamUpdater,
                container.RulesUpdater,
                container.FindKnownThreat,
                ((IProtectionServiceHostDependencies)container).ExclusionSettingsAccessor)
        {
        }

        /// <summary>Constructeur de test (répertoire quarantaine isolé via <see cref="InternalsVisibleTo"/>).</summary>
        internal AntivirusActions(
            QuarantineManager quarantine,
            ISignatureUpdateCanceller? freshclam = null,
            ISignatureUpdateCanceller? rules = null,
            Func<string, ThreatInfo?>? threatLookup = null,
            IExclusionSettingsAccessor? exclusions = null)
        {
            _quarantine = quarantine;
            _freshclam = freshclam;
            _rules = rules;
            _threatLookup = threatLookup;
            _exclusions = exclusions ?? new DefaultExclusionSettingsAccessor();
        }

        public event EventHandler<ActionResult>? ActionCompleted;

        public ActionResult QuarantineThreat(string filePath, Guid sourceSessionId = default) =>
            QuarantineThreat(ResolveThreatForPath(filePath), sourceSessionId);

        public ActionResult QuarantineThreat(ThreatInfo threat, Guid sourceSessionId = default)
        {
            if (string.IsNullOrEmpty(threat.FilePath))
                return Complete(false, LocalizationService.GetString("Av_Action_InvalidPath"), isError: true);

            var existing = _quarantine.GetEntries().FirstOrDefault(e =>
                string.Equals(e.OriginalPath, threat.FilePath, StringComparison.OrdinalIgnoreCase));
            if (existing != null)
                return Complete(true,
                    LocalizationService.Format("Av_Action_AlreadyQuarantined", Path.GetFileName(threat.FilePath)),
                    isWarning: true);

            if (!File.Exists(threat.FilePath))
            {
                var root = Path.GetPathRoot(threat.FilePath);
                if (!string.IsNullOrEmpty(root) && root.Length >= 2 && !Directory.Exists(root))
                {
                    return Complete(false,
                        LocalizationService.Format("Av_Action_DriveUnavailable", root.TrimEnd('\\')),
                        isError: true);
                }

                return Complete(false,
                    LocalizationService.Format("Av_Action_FileNotFound", Path.GetFileName(threat.FilePath)),
                    isError: true);
            }

            if (threat.FileSize < 0)
                threat.FileSize = SafeFileSize(threat.FilePath);
            if (string.IsNullOrWhiteSpace(threat.VirusName))
                threat.VirusName = LocalizationService.GetString("Av_Action_DetectedDefault");
            threat.Status = ThreatStatus.Detected;

            bool ok = _quarantine.Quarantine(threat, sourceSessionId);
            return Complete(ok,
                ok ? LocalizationService.Format("Av_Action_QuarantineOk", Path.GetFileName(threat.FilePath))
                   : LocalizationService.Format("Av_Action_QuarantineFail", Path.GetFileName(threat.FilePath)));
        }

        private ThreatInfo ResolveThreatForPath(string filePath)
        {
            var known = _threatLookup?.Invoke(filePath);
            if (known != null)
                return known.Clone();

            return new ThreatInfo
            {
                FilePath = filePath,
                VirusName = LocalizationService.GetString("Av_Action_DetectedDefault"),
                DetectedAt = DateTime.Now,
                Status = ThreatStatus.Detected,
                FileSize = SafeFileSize(filePath),
            };
        }

        public ActionResult IgnoreThreat(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                return Complete(false, LocalizationService.GetString("Av_Action_InvalidPath"), isError: true);

            if (!_exclusions.Current.AddFile(filePath))
            {
                if (_exclusions.Current.IsFileExcluded(filePath))
                    return Complete(true,
                        LocalizationService.Format("Av_Action_AlreadyExcluded", Path.GetFileName(filePath)),
                        isWarning: true);

                return Complete(false,
                    LocalizationService.Format("Av_Action_ExcludeFail", Path.GetFileName(filePath)),
                    isError: true);
            }

            AppLogger.Info("AntivirusActions", $"Fichier exclu des analyses : {filePath}");
            return Complete(true,
                LocalizationService.Format("Av_Action_ExcludedOk", Path.GetFileName(filePath)),
                isWarning: true);
        }

        public ActionResult DeleteThreatFile(string filePath)
        {
            try
            {
                // Refus identique à la restauration quarantaine : pas de suppression dans System32, Windows, etc.
                if (QuarantineManager.IsSensitivePath(filePath))
                    return Complete(false,
                        LocalizationService.Format("Av_Action_DeleteSensitive", Path.GetFileName(filePath)),
                        isError: true);

                if (File.Exists(filePath))
                {
                    var attrs = File.GetAttributes(filePath);
                    if (attrs.HasFlag(FileAttributes.ReadOnly))
                        File.SetAttributes(filePath, attrs & ~FileAttributes.ReadOnly);
                    File.Delete(filePath);
                    return Complete(true,
                        LocalizationService.Format("Av_Action_DeleteOk", Path.GetFileName(filePath)));
                }
                return Complete(false,
                    LocalizationService.Format("Av_Action_DeleteMissing", Path.GetFileName(filePath)));
            }
            catch (Exception ex)
            {
                AppLogger.Error("AntivirusActions", $"DeleteThreatFile {filePath}", ex);
                return Complete(false,
                    LocalizationService.Format("Av_Action_DeleteError", ex.Message),
                    isError: true);
            }
        }

        public ActionResult RestoreFromQuarantine(string quarantineId)
        {
            bool ok = _quarantine.Restore(quarantineId);
            return Complete(ok,
                ok ? LocalizationService.GetString("Ui_RestoreOk")
                   : LocalizationService.GetString("Ui_RestoreError"),
                isError: !ok);
        }

        public ActionResult DeleteFromQuarantine(string quarantineId)
        {
            bool ok = _quarantine.DeletePermanently(quarantineId);
            return Complete(ok,
                ok ? LocalizationService.GetString("Ui_DeleteOk")
                   : LocalizationService.GetString("Ui_DeleteError"),
                isError: !ok);
        }

        public void StopAllUpdates()
        {
            if (_freshclam != null)
            {
                try { _freshclam.CancelUpdate(); }
                catch (Exception ex) { AppLogger.Warn("AntivirusActions", "Cancel freshclam", ex); }
            }

            if (_rules != null)
            {
                try { _rules.CancelUpdate(); }
                catch (Exception ex) { AppLogger.Warn("AntivirusActions", "Cancel rules", ex); }
            }

            Complete(true, LocalizationService.GetString("Av_Action_UpdateStopped"));
        }

        private static long SafeFileSize(string path)
        {
            try { return new FileInfo(path).Length; }
            catch { return 0; }
        }

        private ActionResult Complete(bool success, string message, bool isError = false, bool isWarning = false)
        {
            var result = new ActionResult
            {
                Success = success,
                Message = message,
                IsError = isError,
                IsWarning = isWarning,
            };
            ActionCompleted?.Invoke(this, result);
            return result;
        }
    }

    public sealed class ActionResult
    {
        public bool Success { get; init; }
        public string Message { get; init; } = string.Empty;
        public bool IsError { get; init; }
        public bool IsWarning { get; init; }
    }
}
