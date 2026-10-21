using optiCombat.Localization;

namespace optiCombat.Services
{
    /// <summary>Valeurs placeholder affichées quand une version/base est inconnue.</summary>
    public static class VersionDisplayHelper
    {
        public static string UnknownLabel => LocalizationService.GetString("Common_Unknown");

        public static bool IsPlaceholder(string? value)
        {
            if (string.IsNullOrWhiteSpace(value) || value == "—")
                return true;
            if (string.Equals(value, UnknownLabel, StringComparison.Ordinal))
                return true;
            // Legacy FR codé en dur (avant i18n)
            return string.Equals(value, "Inconnue", StringComparison.Ordinal);
        }

        public static string NormalizeForDisplay(string? value) =>
            IsPlaceholder(value) ? "—" : value!;
    }
}
