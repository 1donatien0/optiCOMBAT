using optiCombat.Localization;
using System.Windows;
using MessageBox = System.Windows.MessageBox;

namespace optiCombat.Services
{
    /// <summary>Premier lancement : parcours court en 3 étapes.</summary>
    public static class OnboardingService
    {
        public static void ShowIfNeeded(Window owner, IViewServices ui) =>
            ShowIfNeeded(owner, ui, null);

        public static void ShowIfNeeded(Window owner, IViewServices ui, IUserPreferencesAccessor? preferences)
        {
            var prefs = (preferences ?? new DefaultUserPreferencesAccessor()).Current;
            if (prefs.OnboardingCompleted)
                return;

            if (prefs.TotalScansCount > 0)
            {
                prefs.OnboardingCompleted = true;
                prefs.Save();
                return;
            }

            var title = LocalizationService.GetString("Onboarding_Title");

            var step1 = MessageBox.Show(
                owner,
                LocalizationService.GetString("Onboarding_Step1"),
                title,
                MessageBoxButton.OKCancel,
                MessageBoxImage.Information);
            if (step1 != MessageBoxResult.OK)
                return;

            var step2 = MessageBox.Show(
                owner,
                LocalizationService.GetString("Onboarding_Step2"),
                title,
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);
            if (step2 == MessageBoxResult.Yes)
            {
                ui.Navigation?.NavigateTo(Strings.OpticombatStrings.PanelIds.Antivirus);
                ui.RequestFocusAntivirusSignaturesTab();
                ui.TriggerSignatureUpdate();
            }

            MessageBox.Show(
                owner,
                LocalizationService.GetString("Onboarding_Step3"),
                title,
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            prefs.OnboardingCompleted = true;
            prefs.Save();
        }
    }
}
