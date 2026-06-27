namespace optiCombat.Services
{
    /// <summary>Couleurs sévérité pour exports PDF/HTML — palette fixe indépendante du thème UI.</summary>
    internal static class PdfRiskPalette
    {
        public static string GetSeverityColor(RiskLevel level) => level switch
        {
            RiskLevel.Critical => "#C0392B",
            RiskLevel.Major => "#E67E22",
            RiskLevel.Minor => "#F1C40F",
            _ => "#27AE60"
        };
    }
}
