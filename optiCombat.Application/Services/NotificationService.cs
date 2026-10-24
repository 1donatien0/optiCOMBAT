using Microsoft.Toolkit.Uwp.Notifications;
using optiCombat.Localization;
using optiCombat.Models;

namespace optiCombat.Services
{
    /// <summary>
    /// Notifications toast Windows natives.
    /// Les actions (quarantaine, ignorer, navigation…) sont traitées via <see cref="ToastActivated"/>.
    /// </summary>
    public class NotificationService
    {
        private static NotificationService? _activationTarget;

        private bool _toastsEnabled = true;
        private static bool _activationHooked;

        /// <summary>Émis sur le thread du callback toolkit — le handler doit marshaler vers le thread UI.</summary>
        public event EventHandler<ToastActivationEventArgs>? ToastActivated;

        private readonly IUserPreferencesAccessor _prefs;

        public NotificationService(IUserPreferencesAccessor? preferences = null)
        {
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _activationTarget = this;
            EnsureActivationHook();
        }

        public bool IsEnabled
        {
            get => _toastsEnabled;
            set => _toastsEnabled = value;
        }

        /// <summary>Aligne l'état sur <see cref="UserPreferences.ActionNotificationsEnabled"/>.</summary>
        public void SyncFromUserPreferences()
        {
            _toastsEnabled = _prefs.Current.ActionNotificationsEnabled;
        }

        private static void EnsureActivationHook()
        {
            if (_activationHooked) return;
            try
            {
                ToastNotificationManagerCompat.OnActivated += SurActivationToastStatic;
                _activationHooked = true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("NotificationService", "Toast OnActivated indisponible (COM/debug)", ex);
            }
        }

        /// <summary>Réinitialise l'enregistrement du hook toast (tests unitaires uniquement).</summary>
        internal static void ResetActivationHookForTests()
        {
            _activationHooked = false;
            _activationTarget = null;
        }

        private static void SurActivationToastStatic(ToastNotificationActivatedEventArgsCompat e) =>
            HandleActivationArgument(e.Argument);

        /// <summary>Décode l'argument d'un toast cliqué et le transmet à l'instance active.</summary>
        internal static void HandleActivationArgument(string argument)
        {
            try
            {
                var parsed = ToastArguments.Parse(argument);
                // TryGetValue : « Get » lève KeyNotFoundException si la clé manque — les boutons
                // « Ouvrir » / « Historique » ne portent que « action ».
                var action = parsed.TryGetValue("action", out string? a) ? a ?? string.Empty : string.Empty;
                var file = parsed.TryGetValue("file", out string? f) ? f : null;
                var virus = parsed.TryGetValue("virus", out string? v) ? v : null;

                var args = new ToastActivationEventArgs(action, file, virus);
                _activationTarget?.DispatchActivation(args);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("NotificationService", "OnActivated", ex);
            }
        }

        internal void DispatchActivation(ToastActivationEventArgs args) =>
            ToastActivated?.Invoke(this, args);

        public void ShowThreatDetected(ThreatInfo threat)
        {
            if (!ShouldShowToast()) return;

            try
            {
                var severity = RiskScoringService.GetSeverityLevel(threat);

                Present(new ToastContentBuilder()
                    .AddArgument("action", "threat")
                    .AddArgument("file", threat.FilePath)
                    .AddArgument("virus", threat.VirusName)
                    .AddText(LocalizationService.GetString("Notif_ThreatTitle"))
                    .AddText(threat.VirusName)
                    .AddText($"{threat.FileName} • {severity}")
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_QuarantineBtn"))
                        .AddArgument("action", "quarantine")
                        .AddArgument("file", threat.FilePath)
                        .AddArgument("virus", threat.VirusName))
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_IgnoreBtn"))
                        .AddArgument("action", "ignore")
                        .AddArgument("file", threat.FilePath))
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_OpenAntivirus"))
                        .AddArgument("action", "openav"))
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_OpenApp"))
                        .AddArgument("action", "open"))
                    .SetToastDuration(ToastDuration.Long)
                    );
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowThreatDetected", ex);
            }
        }

        /// <summary>Tests uniquement : reçoit chaque toast construit au lieu de l'afficher (pas de COM).</summary>
        internal Action<ToastContentBuilder>? PresentOverride { get; set; }

        private void Present(ToastContentBuilder toast)
        {
            if (PresentOverride is { } capture)
                capture(toast);
            else
                toast.Show();
        }

        internal bool ShouldShowToast() =>
            _toastsEnabled && !DistractionFreeMonitor.ShouldSuppressNotifications();

        public void ShowQuarantined(ThreatInfo threat)
        {
            if (!ShouldShowToast()) return;

            try
            {
                Present(new ToastContentBuilder()
                    .AddArgument("action", "quarantined")
                    .AddText(LocalizationService.GetString("Notif_QuarantinedTitle"))
                    .AddText($"{threat.FileName} → {threat.VirusName}")
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_ViewQuarantine"))
                        .AddArgument("action", "showquarantine"))
                    );
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowQuarantined", ex);
            }
        }

        public void ShowRemovableDriveScanStarted(string driveLabel)
        {
            if (!ShouldShowToast()) return;

            try
            {
                Present(new ToastContentBuilder()
                    .AddArgument("action", "usbscanstart")
                    .AddArgument("drive", driveLabel)
                    .AddText(LocalizationService.GetString("Notif_UsbScanStartedTitle"))
                    .AddText(LocalizationService.Format("Notif_UsbScanStartedBody", driveLabel))
                    .SetToastDuration(ToastDuration.Short)
                    );
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowRemovableDriveScanStarted", ex);
            }
        }

        public void ShowRemovableDriveScanCompleted(string driveLabel, int threatsFound, int filesScanned)
        {
            if (!ShouldShowToast()) return;

            try
            {
                if (threatsFound == 0)
                {
                    Present(new ToastContentBuilder()
                        .AddArgument("action", "usbscanok")
                        .AddArgument("drive", driveLabel)
                        .AddText(LocalizationService.Format("Notif_UsbScanOkTitle", driveLabel))
                        .AddText(LocalizationService.Format("Notif_UsbScanOkBody", driveLabel, filesScanned))
                        .AddButton(new ToastButton()
                            .SetContent(LocalizationService.GetString("Notif_OpenAntivirus"))
                            .AddArgument("action", "openav"))
                        );
                }
                else
                {
                    Present(new ToastContentBuilder()
                        .AddArgument("action", "usbscanthreats")
                        .AddArgument("drive", driveLabel)
                        .AddArgument("threats", threatsFound.ToString())
                        .AddText(LocalizationService.Format("Notif_UsbScanThreatsTitle", driveLabel, threatsFound))
                        .AddText(LocalizationService.Format("Notif_UsbScanThreatsBody", driveLabel, threatsFound, filesScanned))
                        .AddButton(new ToastButton()
                            .SetContent(LocalizationService.GetString("Notif_OpenAntivirus"))
                            .AddArgument("action", "openav"))
                        .AddButton(new ToastButton()
                            .SetContent(LocalizationService.GetString("Notif_HistoryBtn"))
                            .AddArgument("action", "history"))
                        );
                }
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowRemovableDriveScanCompleted", ex);
            }
        }

        public void ShowScanCompleted(int threatsFound, int filesScanned)
        {
            if (!ShouldShowToast()) return;

            try
            {
                if (threatsFound == 0)
                {
                    Present(new ToastContentBuilder()
                        .AddArgument("action", "scanok")
                        .AddText(LocalizationService.GetString("Notif_ScanOkTitle"))
                        .AddText(LocalizationService.Format("Notif_ScanOkBody", filesScanned))
                        .AddButton(new ToastButton()
                            .SetContent(LocalizationService.GetString("Notif_OpenAntivirus"))
                            .AddArgument("action", "openav"))
                        );
                }
                else
                {
                    Present(new ToastContentBuilder()
                        .AddArgument("action", "scanthreats")
                        .AddArgument("threats", threatsFound.ToString())
                        .AddText(LocalizationService.Format("Notif_ScanThreatsTitle", threatsFound))
                        .AddText(LocalizationService.GetString("Notif_ScanThreatsBody"))
                        .AddButton(new ToastButton()
                            .SetContent(LocalizationService.GetString("Notif_OpenAntivirus"))
                            .AddArgument("action", "openav"))
                        .AddButton(new ToastButton()
                            .SetContent(LocalizationService.GetString("Notif_HistoryBtn"))
                            .AddArgument("action", "history"))
                        .AddButton(new ToastButton()
                            .SetContent(LocalizationService.GetString("Notif_OpenApp"))
                            .AddArgument("action", "open"))
                        );
                }
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowScanCompleted", ex);
            }
        }

        public void ShowUpdateAvailable(string version)
        {
            if (!ShouldShowToast()) return;

            try
            {
                Present(new ToastContentBuilder()
                    .AddArgument("action", "update")
                    .AddText(LocalizationService.GetString("Notif_UpdateTitle"))
                    .AddText(LocalizationService.Format("Notif_UpdateBody", version))
                    .AddButton(new ToastButton()
                        .SetContent(LocalizationService.GetString("Notif_UpdateBtn"))
                        .AddArgument("action", "update"))
                    );
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowUpdateAvailable", ex);
            }
        }

        public void ShowRealTimeProtectionStarted()
        {
            if (!ShouldShowToast()) return;

            try
            {
                Present(new ToastContentBuilder()
                    .AddArgument("action", "rtpstarted")
                    .AddText(LocalizationService.GetString("Notif_RtpStartedTitle"))
                    .AddText(LocalizationService.GetString("Notif_RtpStartedBody"))
                    .SetToastDuration(ToastDuration.Short)
                    );
            }
            catch (Exception ex)
            {
                AppLogger.Error("NotificationService", "ShowRealTimeProtectionStarted", ex);
            }
        }
    }

    /// <summary>Action demandée depuis un toast Windows.</summary>
    public sealed class ToastActivationEventArgs : EventArgs
    {
        public ToastActivationEventArgs(string action, string? filePath, string? virusName)
        {
            Action = action ?? string.Empty;
            FilePath = filePath;
            VirusName = virusName;
        }

        public string Action { get; }
        public string? FilePath { get; }
        public string? VirusName { get; }
    }
}
