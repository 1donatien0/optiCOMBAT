using optiCombat.Localization;

namespace optiCombat.Models
{
    /// <summary>Durées et libellés d'affichage communs pour l'historique et les résumés de scan.</summary>
    public static class ScanDisplayFormatter
    {
        /// <summary>
        /// Formate une durée avec les unités localisées selon la culture UI active.
        /// </summary>
        public static string FormatDuration(TimeSpan d)
        {
            if (d < TimeSpan.Zero)
                d = TimeSpan.Zero;

            var total = (long)d.TotalSeconds;
            if (total < 1)
                return LocalizationService.GetString("Duration_LessThanOne");

            var uh = LocalizationService.GetString("Duration_Hours");
            var um = LocalizationService.GetString("Duration_Minutes");
            var us = LocalizationService.GetString("Duration_Seconds");

            var h = total / 3600;
            var m = (total % 3600) / 60;
            var s = total % 60;

            if (h > 0)
            {
                if (m == 0 && s == 0) return $"{h} {uh}";
                if (s == 0) return $"{h} {uh} {m} {um}";
                return $"{h} {uh} {m} {um} {s} {us}";
            }

            if (m > 0)
            {
                if (s == 0) return $"{m} {um}";
                return $"{m} {um} {s} {us}";
            }

            return $"{s} {us}";
        }
    }
}
