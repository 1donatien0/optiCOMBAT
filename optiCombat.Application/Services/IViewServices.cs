using optiCombat.Models;

namespace optiCombat.Services;

/// <summary>
/// Services et bus UI exposés aux vues WPF (sans accès au singleton complet).
/// <see cref="ServiceContainer"/> l'implémente ; assigner via <c>Bind()</c> depuis <see cref="optiCombat.MainWindow"/>.
/// </summary>
public interface IViewServices : IUiEventBus
{
    INavigationService? Navigation { get; }

    AntivirusActions Actions { get; }

    QuarantineManager Quarantine { get; }

    ScanLogManager Logger { get; }

    ThreatReputationService ThreatReputation { get; }

    IScheduledScanService ScheduledScan { get; }

    NotificationService Notifications { get; }

    IUserPreferencesAccessor UserPreferencesAccessor { get; }

    IExclusionSettingsAccessor ExclusionSettingsAccessor { get; }

    ThreatInfo? FindKnownThreat(string filePath);
}
