using Microsoft.Extensions.DependencyInjection;
using optiCombat.Services.DependencyInjection;

namespace optiCombat.Services.DependencyInjection;

/// <summary>Services WPF-only complémentaires à <see cref="ServiceRegistration"/>.</summary>
public static class WpfServiceRegistration
{
    public static IServiceCollection AddOpticombatWpfServices(this IServiceCollection services)
    {
        services.AddSingleton<IHistoryExportService, HistoryExportService>();
        services.AddSingleton<HistoryExportService>(sp =>
            (HistoryExportService)sp.GetRequiredService<IHistoryExportService>());
        return services;
    }
}
