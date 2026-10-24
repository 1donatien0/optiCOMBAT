using optiCombat.Services;
using optiCombat.Tests.TestSupport;

namespace optiCombat.Tests;

/// <summary>
/// Bascule entre la protection locale (RTP in-process) et le service de protection, avec un
/// service simulé (sonde IPC) et un shell enregistreur pour sc.exe.
/// </summary>
[Collection("OpticombatPrefs")]
public sealed class ContainerPlatformModeTests : IDisposable
{
    private readonly IsolatedServices _iso = new();

    public ContainerPlatformModeTests()
    {
        _iso.Exclusions.RealTimeEnabled = true;
        _iso.Prefs.UsePlatformProtectionService = true;
        PlatformProtectionBootstrap.Initialize(_iso.PrefsAccessor);
        PlatformProtectionBootstrap.BaseDirectoryOverride = Path.Combine(_iso.Root, "bin");
        PlatformProtectionBootstrap.StartPollDelay = TimeSpan.Zero;
    }

    public void Dispose()
    {
        PlatformProtectionBootstrap.RemoteProbeOverride = null;
        PlatformProtectionBootstrap.BaseDirectoryOverride = null;
        PlatformProtectionBootstrap.StartPollDelay = TimeSpan.FromMilliseconds(500);
        _iso.Dispose();
    }

    [Fact]
    public void Reachable_service_takes_over_real_time_protection()
    {
        using var shell = RecordingShell.Install();
        PlatformProtectionBootstrap.RemoteProbeOverride = () => true;
        var refreshed = 0;
        _iso.Container.ProtectionStateRefreshRequested += (_, _) => refreshed++;

        _iso.Container.ApplyRealtimeProtection(true);

        Assert.False(_iso.Container.RealTimeProtection.IsEnabled);
        Assert.Equal(1, refreshed);
        Assert.Empty(shell.Runs); // service déjà joignable : aucun sc.exe
    }

    [Fact]
    public void Unreachable_service_falls_back_to_local_protection()
    {
        using var shell = RecordingShell.Install();
        PlatformProtectionBootstrap.RemoteProbeOverride = () => false;

        _iso.Container.ApplyRealtimeProtection(true);
        Assert.True(_iso.Container.RealTimeProtection.IsEnabled);

        _iso.Container.ApplyRealtimeProtection(false);
        Assert.False(_iso.Container.RealTimeProtection.IsEnabled);
    }

    [Fact]
    public void Startup_with_a_reachable_service_skips_local_protection()
    {
        using var shell = RecordingShell.Install();
        PlatformProtectionBootstrap.RemoteProbeOverride = () => true;

        _iso.Container.ApplyPreferencesOnStartup();

        Assert.False(_iso.Container.RealTimeProtection.IsEnabled);
    }

    [Fact]
    public void Startup_with_an_unreachable_service_starts_local_protection()
    {
        using var shell = RecordingShell.Install();
        PlatformProtectionBootstrap.RemoteProbeOverride = () => false;

        _iso.Container.ApplyPreferencesOnStartup();

        Assert.True(_iso.Container.RealTimeProtection.IsEnabled);
        // Tentatives de démarrage du service puis repli : sc.exe interrogé, jamais exécuté pour de vrai.
        Assert.Contains(shell.CommandLines, l => l.StartsWith("sc.exe query", StringComparison.Ordinal));
    }

    [Fact]
    public void Enabling_platform_mode_is_refused_while_the_feature_gate_is_closed()
    {
        using var shell = RecordingShell.Install();
        PlatformProtectionBootstrap.RemoteProbeOverride = () => false;

        _iso.Container.ApplyPlatformProtectionService(true);

        Assert.Equal(PlatformProtectionFeatureGate.IsUserActivatable, _iso.Prefs.UsePlatformProtectionService);
        if (!PlatformProtectionFeatureGate.IsUserActivatable)
            Assert.True(_iso.Container.RealTimeProtection.IsEnabled); // repli local
        Assert.DoesNotContain(shell.CommandLines, l => l.Contains(" create ", StringComparison.Ordinal));
    }
}
