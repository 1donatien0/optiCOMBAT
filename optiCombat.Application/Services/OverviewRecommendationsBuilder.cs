using optiCombat.Localization;

namespace optiCombat.Services
{
    /// <summary>
    /// Calcule la recommandation hygiène affichée sur l'accueil (signatures, nettoyage, ClamAV).
    /// L'activité d'analyse / menaces est portée par <see cref="OverviewProtectionStatsFormatter"/>.
    /// </summary>
    public sealed class OverviewRecommendationsBuilder
    {
        /// <summary>Résultat d'un appel à <see cref="Build"/>.</summary>
        public sealed class Result
        {
            public string HygieneLine { get; init; } = string.Empty;
            public int HygieneSeverity { get; init; }
            public bool ShowSigUpdateLink { get; init; }
        }

        public sealed class Context
        {
            public bool ClamInstalled { get; init; }
            /// <summary>
            /// Dernière MAJ signatures ClamAV (freshclam réussi ou date des .cvd/.cld locaux).
            /// </summary>
            public DateTime? LastFreshclamUpdate { get; init; }
            public DateTime? LastCleanAt { get; init; }
        }

        public static Result Build(Context ctx, IUserPreferencesAccessor? preferences = null)
        {
            var prefs = (preferences ?? new DefaultUserPreferencesAccessor()).Current;

            bool suggestClean = !ctx.LastCleanAt.HasValue
                || (DateTime.Now - ctx.LastCleanAt.Value).TotalDays > prefs.CleanSuggestThresholdDays;

            string hypLine = suggestClean
                ? LocalizationService.GetString("Rec_CleanSuggest")
                : LocalizationService.Format("Rec_CleanRecent",
                    ctx.LastCleanAt!.Value.ToString("d", LocalizationService.CurrentCulture));
            int hypSev = suggestClean ? 1 : 0;
            bool showLink = false;

            if (!ctx.ClamInstalled)
            {
                hypLine = LocalizationService.GetString("Rec_ClamMissing");
                hypSev = 1;
            }
            else if (ctx.LastFreshclamUpdate is null)
            {
                hypLine = LocalizationService.GetString("Rec_SigNeverUpdated");
                hypSev = 1;
                showLink = true;
            }
            else if ((DateTime.Now - ctx.LastFreshclamUpdate.Value).TotalDays > prefs.SignatureStaleThresholdDays)
            {
                hypLine = LocalizationService.Format("Rec_SigStale", prefs.SignatureStaleThresholdDays);
                hypSev = 1;
                showLink = true;
            }
            else if (!prefs.SignatureAutoUpdateEnabled)
            {
                hypLine = LocalizationService.GetString("Rec_SigAutoOff");
                hypSev = 3;
            }

            return new Result
            {
                HygieneLine = hypLine,
                HygieneSeverity = hypSev,
                ShowSigUpdateLink = showLink,
            };
        }
    }
}
