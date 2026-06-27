using Microsoft.Extensions.DependencyInjection;
using optiCombat.Services.OptiCombat;

namespace optiCombat.Services.DependencyInjection;

/// <summary>Enregistrement DI Microsoft.Extensions pour optiCombat.</summary>
public static class ServiceRegistration
{
    public static IServiceCollection AddOpticombatCoreServices(this IServiceCollection services)
    {
        services.AddSingleton<IUserPreferencesAccessor, DefaultUserPreferencesAccessor>();
        services.AddSingleton<IExclusionSettingsAccessor, DefaultExclusionSettingsAccessor>();
        services.AddSingleton<UiEventBus>();
        services.AddSingleton<IUiEventBus>(sp => sp.GetRequiredService<UiEventBus>());
        services.AddSingleton<ClamAvEngine>(sp =>
            new ClamAvEngine(exclusions: sp.GetRequiredService<IExclusionSettingsAccessor>()));
        services.AddSingleton<ClamdEngine>(sp =>
            new ClamdEngine(
                sp.GetRequiredService<IUserPreferencesAccessor>(),
                sp.GetRequiredService<IExclusionSettingsAccessor>()));
        services.AddSingleton<CompositeClamAvBackend>(sp =>
            new CompositeClamAvBackend(sp.GetRequiredService<ClamdEngine>(), sp.GetRequiredService<ClamAvEngine>()));
        services.AddSingleton<YaraEngine>(sp =>
            new YaraEngine(exclusions: sp.GetRequiredService<IExclusionSettingsAccessor>()));
        services.AddSingleton<FreshclamUpdater>();
        services.AddSingleton<YaraForgeUpdater>();
        services.AddSingleton<QuarantineManager>(sp =>
            new QuarantineManager(preferences: sp.GetRequiredService<IUserPreferencesAccessor>()));
        services.AddSingleton<ScanLogManager>();
        services.AddSingleton<ActivityLogService>(sp =>
            new ActivityLogService(sp.GetRequiredService<ScanLogManager>()));
        services.AddSingleton<NotificationService>(sp =>
            new NotificationService(sp.GetRequiredService<IUserPreferencesAccessor>()));
        services.AddSingleton<ClamAvScanEngineAdapter>(sp =>
            new ClamAvScanEngineAdapter(sp.GetRequiredService<ClamAvEngine>()));
        services.AddSingleton<IScanEngine>(sp => sp.GetRequiredService<ClamAvScanEngineAdapter>());
        // ── optiCombat v1 : bascule sur le cœur Rust (repli ClamAV si DLL absente) ──
        services.UseOptiCombatEngine();
        services.AddSingleton<ScanOrchestrator>(sp =>
            new ScanOrchestrator(
                sp.GetRequiredService<CompositeClamAvBackend>(),
                sp.GetRequiredService<YaraEngine>(),
                sp.GetRequiredService<IUserPreferencesAccessor>(),
                sp.GetRequiredService<IExclusionSettingsAccessor>(),
                sp.GetRequiredService<OptiCombatScanEngine>()));
        services.AddSingleton<ThreatReputationService>(sp =>
            new ThreatReputationService(preferences: sp.GetRequiredService<IUserPreferencesAccessor>()));
        services.AddSingleton<IThreatReputationService>(sp => sp.GetRequiredService<ThreatReputationService>());
        services.AddSingleton<CloudThreatIntelService>();
        services.AddSingleton<ISecurityPostureService, SecurityPostureService>();
        services.AddSingleton<SignatureStatusService>(sp =>
            new SignatureStatusService(
                sp.GetRequiredService<FreshclamUpdater>(),
                sp.GetRequiredService<YaraForgeUpdater>(),
                sp.GetRequiredService<YaraEngine>()));
        services.AddSingleton<ProtectionScanGateway>(sp =>
            new ProtectionScanGateway(
                sp.GetRequiredService<ScanOrchestrator>(),
                sp.GetRequiredService<IUserPreferencesAccessor>()));
        services.AddSingleton<RealTimeProtection>(sp =>
            new RealTimeProtection(
                sp.GetRequiredService<ProtectionScanGateway>(),
                sp.GetRequiredService<QuarantineManager>(),
                sp.GetRequiredService<NotificationService>(),
                sp.GetRequiredService<IUserPreferencesAccessor>(),
                sp.GetRequiredService<IExclusionSettingsAccessor>()));
        services.AddSingleton<ProcessStartMonitor>(sp =>
        {
            var rtp = sp.GetRequiredService<RealTimeProtection>();
            return new ProcessStartMonitor(
                sp.GetRequiredService<ProtectionScanGateway>(),
                sp.GetRequiredService<QuarantineManager>(),
                sp.GetRequiredService<NotificationService>(),
                () => rtp.IsPaused,
                sp.GetRequiredService<IUserPreferencesAccessor>(),
                sp.GetRequiredService<IExclusionSettingsAccessor>());
        });
        services.AddSingleton<TamperProtectionService>(sp =>
            new TamperProtectionService(
                sp.GetRequiredService<IUserPreferencesAccessor>(),
                sp.GetRequiredService<IExclusionSettingsAccessor>()));
        services.AddSingleton<RemovableDriveScanService>(sp =>
            new RemovableDriveScanService(
                sp.GetRequiredService<ScanOrchestrator>(),
                sp.GetRequiredService<QuarantineManager>(),
                sp.GetRequiredService<NotificationService>(),
                sp.GetRequiredService<ScanLogManager>(),
                sp.GetRequiredService<RealTimeProtection>(),
                sp.GetRequiredService<IUiEventBus>(),
                sp.GetRequiredService<IUserPreferencesAccessor>(),
                sp.GetRequiredService<IExclusionSettingsAccessor>()));
        services.AddSingleton<IHistoryExportService, HistoryExportService>();
        services.AddSingleton<HistoryExportService>(sp =>
            (HistoryExportService)sp.GetRequiredService<IHistoryExportService>());
        services.AddSingleton<ScheduledScanService>();
        return services;
    }
}
