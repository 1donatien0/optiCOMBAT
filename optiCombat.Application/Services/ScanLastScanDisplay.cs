using optiCombat.Localization;
using optiCombat.Models;
using System.Globalization;

namespace optiCombat.Services
{
    /// <summary>Libellé « dernière analyse » pour l'Accueil et l'en-tête Antivirus.</summary>
    public static class ScanLastScanDisplay
    {
        /// <summary>Type, date/heure locale et résumé menaces (ex. Accueil).</summary>
        public static string FormatDetailed(ScanSession? session)
        {
            if (session == null)
                return LocalizationService.GetString("Common_Never");

            var type = string.IsNullOrWhiteSpace(session.TypeDisplay)
                ? LocalizationService.GetString("Common_Unknown")
                : session.TypeDisplay;
            var when = session.StartedAt.ToString("g", CultureInfo.CurrentCulture);
            var result = session.ThreatsFound == 0
                ? LocalizationService.GetString("Overview_LastScanClean")
                : LocalizationService.Format("Overview_LastScanThreats", session.ThreatsFound);

            return LocalizationService.Format("Overview_LastScanLine", type, when, result);
        }
    }
}
