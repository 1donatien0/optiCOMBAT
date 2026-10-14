using optiCombat.Localization;
using System.Linq;
using System.Text.Json.Serialization;

namespace optiCombat.Models
{
    /// <summary>
    /// Entrée d'historique d'un scan — version allégée de <see cref="ScanResult"/>,
    /// sérialisable en JSON pour la persistance locale.
    /// </summary>
    public class ScanSession
    {
        /// <summary>Identifiant unique de la session (correspondant au <see cref="ScanResult"/> d'origine).</summary>
        public Guid SessionId { get; set; }

        /// <summary>Date et heure de démarrage du scan.</summary>
        public DateTime StartedAt { get; set; }

        /// <summary>Date et heure de fin du scan (<c>null</c> si non encore terminé).</summary>
        public DateTime? FinishedAt { get; set; }

        /// <summary>
        /// Type de scan — source de vérité pour le libellé affiché.
        /// Stocké dans le JSON depuis les versions récentes ; les entrées anciennes ont <see cref="TypeDisplayLegacy"/> à la place.
        /// </summary>
        public ScanType ScanTypeValue { get; set; } = ScanType.QuickScan;

        /// <summary>
        /// Libellé brut stocké par une version antérieure (chaîne localisée au moment du scan).
        /// Conservé pour la rétrocompatibilité JSON uniquement — ne pas utiliser dans l'UI.
        /// </summary>
        [JsonPropertyName("typeDisplay")]
        public string TypeDisplayLegacy { get; set; } = string.Empty;

        /// <summary>
        /// Libellé localisé du type de scan, calculé selon la culture UI active.
        /// Si <see cref="ScanTypeValue"/> est défini, il est utilisé ; sinon repli sur <see cref="TypeDisplayLegacy"/>.
        /// </summary>
        [JsonIgnore]
        public string TypeDisplay =>
            ScanTypeValue != default
                ? LocalizationService.ScanTypeDisplay(ScanTypeValue)
                : TypeDisplayLegacy;

        /// <summary>Chemin ou identifiant de la cible analysée.</summary>
        public string TargetPath { get; set; } = string.Empty;

        /// <summary>Nombre de fichiers parcourus pendant le scan.</summary>
        public int FilesScanned { get; set; }

        /// <summary>Nombre de menaces détectées.</summary>
        public int ThreatsFound { get; set; }

        /// <summary>Statut final du scan (valeur enum <see cref="ScanStatus"/> sérialisée en string).</summary>
        public string StatusDisplay { get; set; } = string.Empty;

        /// <summary>Message d'erreur si le scan s'est terminé en échec.</summary>
        public string? ErrorMessage { get; set; }

        /// <summary>Fichiers ignorés (exclusions, dossiers protégés).</summary>
        public int FilesSkipped { get; set; }

        /// <summary>Menaces détectées (chemins et noms conservés pour l'historique et les exports).</summary>
        public List<ThreatInfo> Threats { get; set; } = new();

        /// <summary>Durée formatée selon la culture UI active ; « — » si la session n'est pas terminée.</summary>
        [JsonIgnore]
        public string DurationDisplay =>
            FinishedAt.HasValue
                ? ScanDisplayFormatter.FormatDuration(FinishedAt.Value - StartedAt)
                : "—";

        /// <summary>Badge d'état localisé selon la culture UI active.</summary>
        [JsonIgnore]
        public string ThreatsBadge =>
            ThreatsFound == 0
                ? LocalizationService.GetString("Badge_Clean")
                : LocalizationService.Format("Badge_Threats", ThreatsFound,
                    ThreatsFound > 1 ? "s" : "");

        /// <summary>Convertit un <see cref="ScanResult"/> complet en entrée d'historique légère.</summary>
        public static ScanSession FromResult(ScanResult result) => new ScanSession
        {
            SessionId        = result.SessionId,
            StartedAt        = result.StartedAt,
            FinishedAt       = result.FinishedAt,
            ScanTypeValue    = result.Type,
            TypeDisplayLegacy = result.TypeDisplay, // rétrocompat lectures par ancien code
            TargetPath       = result.TargetPath,
            FilesScanned     = result.FilesScanned,
            ThreatsFound     = result.ThreatsFound,
            StatusDisplay    = result.Status.ToString(),
            ErrorMessage     = result.ErrorMessage,
            FilesSkipped     = result.FilesSkipped,
            Threats          = result.Threats.Select(t => t.Clone()).ToList()
        };
    }
}
