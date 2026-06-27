using System.Globalization;

namespace optiCombat.Services
{
    /// <summary>Parse les horodatages Windows Update (format WMI UTC 14 chiffres).</summary>
    internal static class WindowsUpdateTimeParser
    {
        public static bool TryParseWmiUtc14(string? wmiUtc, out DateTime utc)
        {
            utc = default;
            if (string.IsNullOrWhiteSpace(wmiUtc) || wmiUtc.Length < 14)
                return false;

            return DateTime.TryParseExact(
                wmiUtc.Substring(0, 14),
                "yyyyMMddHHmmss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out utc);
        }

        public static DateTime? MaxUtc(DateTime? a, DateTime? b)
        {
            if (!a.HasValue) return b;
            if (!b.HasValue) return a;
            return a.Value >= b.Value ? a : b;
        }
    }
}
