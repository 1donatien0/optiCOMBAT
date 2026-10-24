using optiCombat.Services;

namespace optiCombat.Tests;

/// <summary>Décision du statut plateforme avec sondes factices (aucun registre, fltmc ni service lu).</summary>
public sealed class PlatformProtectionStatusLogicTests
{
    private static PlatformProtectionStatusService.Probes Probes(
        bool activatable = true, bool ipc = false, bool dll = false, bool amsi = false,
        bool defender = false, bool sys = false, bool flt = false) => new()
        {
            IsUserActivatable = () => activatable,
            IsIpcActive = () => ipc,
            FileExists = p => p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? dll : sys,
            IsAmsiRegistered = _ => amsi,
            IsDefenderRunning = () => defender,
            IsMinifilterLoaded = () => flt,
        };

    private static string[] Keys(PlatformProtectionStatusReport r) => r.Components.Select(c => c.LabelKey).ToArray();

    [Fact]
    public void Feature_gate_closed_reports_a_single_planned_item()
    {
        var r = PlatformProtectionStatusService.Evaluate(new UserPreferences(), Probes(activatable: false));
        Assert.Equal(["Platform_PlannedUnavailable"], Keys(r));
        Assert.False(r.HasWarnings);
    }

    [Fact]
    public void Production_entry_point_stays_on_the_planned_status_while_the_gate_is_closed()
    {
        var r = PlatformProtectionStatusService.Evaluate(new TestSupport.FixedPreferencesAccessor(new UserPreferences()));
        Assert.Equal(PlatformProtectionFeatureGate.IsUserActivatable ? r.Components.Count : 1, r.Components.Count);
    }

    [Fact]
    public void Everything_active_has_no_warning()
    {
        var r = PlatformProtectionStatusService.Evaluate(
            new UserPreferences { UsePlatformProtectionService = true },
            Probes(ipc: true, dll: true, amsi: true, sys: true, flt: true));

        Assert.Equal(["Platform_IpcActive", "Platform_AmsiRegistered", "Platform_MinifilterLoaded"], Keys(r));
        Assert.All(r.Components, c => Assert.Equal(PlatformComponentState.Active, c.State));
        Assert.False(r.HasWarnings);
    }

    [Fact]
    public void Nothing_installed_reports_each_missing_piece()
    {
        var r = PlatformProtectionStatusService.Evaluate(
            new UserPreferences { UsePlatformProtectionService = true }, Probes());

        Assert.Equal(["Platform_IpcInactive", "Platform_AmsiDllMissing", "Platform_MinifilterAbsent"], Keys(r));
        Assert.True(r.HasWarnings);
        Assert.Equal(PlatformComponentState.Inactive, r.Components[^1].State);
    }

    [Fact]
    public void Present_but_not_registered_or_loaded_are_warnings()
    {
        var r = PlatformProtectionStatusService.Evaluate(
            new UserPreferences { UsePlatformProtectionService = false }, Probes(dll: true, sys: true));

        Assert.Equal(["Platform_IpcDisabled", "Platform_AmsiNotRegistered", "Platform_MinifilterNotLoaded"], Keys(r));
        Assert.Equal(PlatformComponentState.NotApplicable, r.Components[0].State);
        Assert.True(r.HasWarnings);
    }

    [Fact]
    public void Defender_running_alongside_our_amsi_provider_is_flagged()
    {
        var withDefender = PlatformProtectionStatusService.Evaluate(
            new UserPreferences(), Probes(dll: true, amsi: true, defender: true, flt: true));
        Assert.Contains("Platform_DefenderMayOverride", Keys(withDefender));
        Assert.True(withDefender.HasWarnings);

        // Sans fournisseur AMSI enregistré, Defender n'est même pas interrogé.
        var asked = false;
        var probes = new PlatformProtectionStatusService.Probes
        {
            IsUserActivatable = () => true,
            FileExists = _ => false,
            IsAmsiRegistered = _ => false,
            IsDefenderRunning = () => asked = true,
            IsMinifilterLoaded = () => false,
        };
        PlatformProtectionStatusService.Evaluate(new UserPreferences(), probes);
        Assert.False(asked);
    }

    [Fact]
    public void Amsi_registration_lookup_never_throws()
    {
        Assert.False(PlatformProtectionStatusService.IsAmsiProviderRegistered(Path.Combine(Path.GetTempPath(), "absent.dll")));
    }
}
