using optiCombat.Localization;
using optiCombat.Services;

namespace optiCombat.Coordinators;

/// <summary>
/// Premier lancement : parcours court (présentation, cohabitation Defender si actif,
/// mise à jour des signatures, première analyse). Affiché une seule fois ; ignoré si des analyses existent déjà.
/// </summary>
public static class OnboardingCoordinator
{
    public sealed class Host
    {
        public required IUserConfirmService Confirm { get; init; }
        public required UserPreferences Preferences { get; init; }
        public required Action SavePreferences { get; init; }
        public Func<bool>? IsDefenderActive { get; init; }
        public Action<bool>? ApplyDefenderComplement { get; init; }
        public Action? StartSignatureUpdate { get; init; }
    }

    /// <summary>Vrai si le parcours a été proposé pendant cet appel.</summary>
    public static bool RunIfNeeded(Host host)
    {
        var prefs = host.Preferences;
        if (prefs.OnboardingCompleted)
            return false;

        if (prefs.TotalScansCount > 0)
        {
            MarkCompleted(host);
            return false;
        }

        var title = LocalizationService.GetString("Onboarding_Title");
        if (!host.Confirm.ConfirmYesNo(LocalizationService.GetString("Onboarding_Step1"), title, warning: false))
        {
            // Refus du guide : ne plus le reproposer.
            MarkCompleted(host);
            return true;
        }

        if (host.IsDefenderActive?.Invoke() == true && host.ApplyDefenderComplement != null)
        {
            var complement = host.Confirm.ConfirmYesNo(
                LocalizationService.GetString("Onboarding_DefenderStep"),
                LocalizationService.GetString("Onboarding_DefenderTitle"),
                warning: false);
            host.ApplyDefenderComplement(complement);
        }

        if (host.Confirm.ConfirmYesNo(LocalizationService.GetString("Onboarding_Step2"), title, warning: false))
            host.StartSignatureUpdate?.Invoke();

        host.Confirm.Inform(LocalizationService.GetString("Onboarding_Step3"), title);
        MarkCompleted(host);
        return true;
    }

    private static void MarkCompleted(Host host)
    {
        host.Preferences.OnboardingCompleted = true;
        host.SavePreferences();
    }
}
