namespace optiCombat.Services;

/// <summary>
/// Services exposés au panneau Options (préférences de protection).
/// <see cref="ServiceContainer"/> l'implémente ; assigner via <c>Bind()</c> depuis <see cref="MainWindow"/>.
/// </summary>
public interface IOptionsServices : IViewServices
{
    void ApplySignatureAutoUpdate(bool enabled);

    void ApplyRealtimeProtection(bool enabled);

    void ApplyProcessMonitor(bool enabled);

    void ApplyTamperProtection(bool enabled);

    void ApplyPlatformProtectionService(bool enabled);

    void ApplyRemovableDriveScan(bool enabled);

    void ApplyAutoQuarantine(bool enabled);
}
