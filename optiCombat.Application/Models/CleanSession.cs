using System.Globalization;
using System.Text.Json.Serialization;

namespace optiCombat.Models
{
    /// <summary>
    /// Entrée d'historique d'une session de nettoyage système (fichiers temporaires, caches, corbeille).
    /// Sérialisable en JSON pour la persistance locale.
    /// </summary>
    public sealed class CleanSession
    {
        /// <summary>Date et heure de démarrage de la session de nettoyage.</summary>
        public DateTime StartedAt { get; set; }

        /// <summary>Date et heure de fin de la session de nettoyage.</summary>
        public DateTime FinishedAt { get; set; }

        /// <summary>Résumé des cibles cochées (ex. « Temp Windows, Corbeille, Edge »).</summary>
        public string TargetsSummary { get; set; } = "";

        /// <summary>Espace libéré en octets lors de cette session.</summary>
        public long BytesFreed { get; set; }

        /// <summary>Journal d'opérations de la session (étapes, volumes par cible, erreurs éventuelles).</summary>
        public string OperationLog { get; set; } = "";

        /// <summary>Date formatée pour l'affichage dans les listes (ex. « 22/05/2026 14:30 »).</summary>
        [JsonIgnore]
        public string DateDisplay =>
            StartedAt.ToString("dd/MM/yyyy HH:mm", CultureInfo.CurrentCulture);

        /// <summary>Durée formatée en français (ex. « 1 min 12 s »).</summary>
        [JsonIgnore]
        public string DurationDisplay
        {
            get
            {
                var d = FinishedAt - StartedAt;
                if (d < TimeSpan.Zero) d = TimeSpan.Zero;
                return ScanDisplayFormatter.FormatDuration(d);
            }
        }

        /// <summary>Espace libéré en unité lisible (Ko, Mo, Go).</summary>
        [JsonIgnore]
        public string BytesDisplay
        {
            get
            {
                if (BytesFreed >= 1_073_741_824) return $"{BytesFreed / 1_073_741_824.0:F1} Go";
                if (BytesFreed >= 1_048_576) return $"{BytesFreed / 1_048_576.0:F1} Mo";
                if (BytesFreed >= 1_024) return $"{BytesFreed / 1_024.0:F0} Ko";
                return $"{BytesFreed} o";
            }
        }
    }
}
