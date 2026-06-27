using System.Globalization;

namespace optiCombat.Localization
{
    /// <summary>Formatage des tailles de fichiers selon la culture UI active.</summary>
    public static class ByteSizeFormat
    {
        public static string Format(long bytes)
        {
            var cult = CultureInfo.CurrentCulture;
            if (bytes < 1024)
                return LocalizationService.Format("Size_B", bytes.ToString("N0", cult));
            if (bytes < 1024 * 1024)
                return LocalizationService.Format("Size_KB", (bytes / 1024.0).ToString("F1", cult));
            if (bytes < 1024L * 1024 * 1024)
                return LocalizationService.Format("Size_MB", (bytes / (1024.0 * 1024)).ToString("F1", cult));
            return LocalizationService.Format("Size_GB", (bytes / (1024.0 * 1024 * 1024)).ToString("F2", cult));
        }
    }
}
