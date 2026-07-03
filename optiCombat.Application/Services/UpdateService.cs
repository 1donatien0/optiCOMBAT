using System.IO;
using optiCombat.Localization;
using optiCombat.Strings;

namespace optiCombat.Services
{
    /// <summary>État du contrôle de mise à jour du binaire optiCombat (pas des signatures).</summary>
    public enum AppUpdateChannelStatus
    {
        /// <summary>Dossier de staging prêt ; aucun flux OTA distant configuré.</summary>
        NotConfigured,

        /// <summary>Erreur d'accès au dossier local de préparation.</summary>
        StagingError,
    }

    /// <summary>Résultat explicite — évite les MessageBox codés en dur dans l'UI.</summary>
    public sealed class AppUpdateCheckResult
    {
        public AppUpdateChannelStatus Status { get; init; }
        public string CurrentVersion { get; init; } = string.Empty;
        public string ReleaseLabel { get; init; } = string.Empty;
        public string StagingDirectory { get; init; } = string.Empty;
        public string UserMessage { get; init; } = string.Empty;
        public bool Success => Status == AppUpdateChannelStatus.NotConfigured;
    }

    /// <summary>
    /// Mises à jour du binaire optiCombat. Les signatures sont gérées par
    /// <see cref="FreshclamUpdater"/> et <see cref="YaraForgeUpdater"/>.
    /// </summary>
    /// <remarks>
    /// OTA non implémenté volontairement : pas de téléchargement ni de signature de manifeste
    /// tant qu'un canal de distribution n'est pas défini. Cette classe prépare le staging
    /// local et retourne un message utilisateur cohérent.
    /// </remarks>
    public class UpdateService
    {
        private readonly string _localUpdatePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiCombat", "Updates");

        /// <summary>
        /// Prépare le dossier de staging et décrit l'état du canal applicatif.
        /// </summary>
        public Task<AppUpdateCheckResult> CheckForUpdatesAsync()
        {
            var version = ProductVersionInfo.SemVer;
            var release = ProductVersionInfo.ReleaseLabel;

            try
            {
                if (!Directory.Exists(_localUpdatePath))
                    Directory.CreateDirectory(_localUpdatePath);

                AppLogger.Info("UpdateService",
                    $"Canal OTA applicatif non configuré — version locale {release} ({version}), staging : {_localUpdatePath}");

                return Task.FromResult(new AppUpdateCheckResult
                {
                    Status = AppUpdateChannelStatus.NotConfigured,
                    CurrentVersion = version,
                    ReleaseLabel = release,
                    StagingDirectory = _localUpdatePath,
                    UserMessage = LocalizationService.Format(
                        "Upd_NotConfigured",
                        release,
                        version,
                        OpticombatStrings.Urls.OpticombatSourceForge,
                        _localUpdatePath),
                });
            }
            catch (Exception ex)
            {
                AppLogger.Error("UpdateService", "Préparation dossier mises à jour", ex);
                return Task.FromResult(new AppUpdateCheckResult
                {
                    Status = AppUpdateChannelStatus.StagingError,
                    CurrentVersion = version,
                    ReleaseLabel = release,
                    StagingDirectory = _localUpdatePath,
                    UserMessage = LocalizationService.Format(
                        "Upd_StagingError",
                        release,
                        version,
                        ex.Message,
                        OpticombatStrings.Urls.OpticombatSourceForge),
                });
            }
        }
    }
}
