using System.Runtime.Versioning;

namespace optiCombat.Services;

/// <summary>
/// Cohabitation avec Windows Defender. Deux antivirus temps réel sur les mêmes fichiers doublent la charge
/// et peuvent se bloquer mutuellement : le mode « complément » laisse le temps réel à Defender et garde
/// dans optiCOMBAT les analyses à la demande, planifiées et USB.
/// Choix explicite de l'utilisateur (Options) — jamais appliqué automatiquement.
/// </summary>
[SupportedOSPlatform("windows")]
public static class DefenderCoexistenceService
{
    /// <summary>Defender installé et service <c>WinDefend</c> démarré.</summary>
    public static bool IsDefenderActive()
    {
        if (!OperatingSystem.IsWindows() || !WindowsDefenderExclusionService.IsWindowsDefenderPresent())
            return false;
        try
        {
            using var sc = new System.ServiceProcess.ServiceController("WinDefend");
            return sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
        }
        catch (Exception ex)
        {
            AppLogger.Debug("DefenderCoexistence", $"WinDefend illisible : {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Active (<paramref name="complement"/> = vrai) ou quitte le mode complément.
    /// Les callbacks persistent et appliquent les réglages (ex. <c>ServiceContainer.ApplyRealtimeProtection</c>).
    /// </summary>
    public static void Apply(
        bool complement,
        IUserPreferencesAccessor preferences,
        Action<bool> applyRealtimeProtection,
        Action<bool> applyProcessMonitor)
    {
        preferences.Current.DefenderComplementModeEnabled = complement;
        // applyProcessMonitor persiste les préférences (dont le mode ci-dessus).
        applyProcessMonitor(!complement);
        applyRealtimeProtection(!complement);
        AppLogger.Info("DefenderCoexistence", complement
            ? "Mode complément Defender : temps réel laissé à Windows Defender"
            : "Protection temps réel optiCOMBAT réactivée");
    }
}
