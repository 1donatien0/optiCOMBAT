namespace optiCombat.Services
{
    /// <summary>
    /// Sonde la date de dernière mise à jour Windows réussie (registre, WMI, agent WUA).
    /// Injectable pour les tests et pour limiter les faux négatifs sur Windows 11.
    /// </summary>
    public interface IWindowsUpdateProbe
    {
        /// <summary>UTC de la dernière installation réussie connue, ou <c>null</c> si indéterminé.</summary>
        DateTime? TryGetLastSuccessfulInstallUtc();

        /// <summary><c>true</c> si une date connue est dans la fenêtre (UTC).</summary>
        bool HasRecentSuccessfulInstall(TimeSpan maxAge);
    }
}
