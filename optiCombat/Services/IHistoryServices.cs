namespace optiCombat.Services;

/// <summary>
/// Services exposés à <see cref="optiCombat.Views.HistoryControl"/> (sans <see cref="ServiceContainer"/> complet).
/// <see cref="ServiceContainer"/> l'implémente ; assigner via <c>Bind()</c> depuis <see cref="optiCombat.MainWindow"/>.
/// </summary>
public interface IHistoryServices : IViewServices
{
    ActivityLogService ActivityLog { get; }
}
