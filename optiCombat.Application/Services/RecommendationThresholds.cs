namespace optiCombat.Services
{
    /// <summary>Seuils des recommandations affichées sur l'accueil (vue d'ensemble).</summary>
    internal static class RecommendationThresholds
    {
        /// <summary>Au-delà de ce délai sans nettoyage, suggestion d'un scan de nettoyage.</summary>
        public const int CleanSuggestThresholdDays = 14;

        /// <summary>Signatures ClamAV considérées obsolètes si la dernière MAJ dépasse ce délai.</summary>
        public const int SignatureStaleThresholdDays = 7;
    }
}
