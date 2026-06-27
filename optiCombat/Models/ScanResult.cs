using optiCombat.Localization;

namespace optiCombat.Models
{
    /// <summary>
    /// Résultat complet d'une session de scan (ClamAV + YARA).
    /// Contient les statistiques, la liste des menaces détectées et les propriétés
    /// calculées pour l'affichage dans l'UI.
    /// </summary>
    public class ScanResult
    {
        // ── Identité de la session ──────────────────────────────────────────────

        /// <summary>Identifiant unique de la session de scan.</summary>
        public Guid SessionId { get; set; } = Guid.NewGuid();

        /// <summary>Date et heure de démarrage du scan.</summary>
        public DateTime StartedAt { get; set; } = DateTime.Now;

        /// <summary>Date et heure de fin du scan (<c>null</c> si en cours).</summary>
        public DateTime? FinishedAt { get; set; }

        /// <summary>Type de scan exécuté (fichier, dossier, rapide, complet).</summary>
        public ScanType Type { get; set; }

        /// <summary>Chemin ou identifiant de la cible analysée.</summary>
        public string TargetPath { get; set; } = string.Empty;

        // ── Statistiques ────────────────────────────────────────────────────────

        /// <summary>Nombre de fichiers parcourus pendant le scan.</summary>
        public int FilesScanned { get; set; }

        /// <summary>Nombre de menaces trouvées — calculé depuis <see cref="Threats"/>.</summary>
        public int ThreatsFound => Threats.Count;

        /// <summary>Nombre de fichiers ignorés (exclusions ou dossier d'installation).</summary>
        public int FilesSkipped { get; set; }

        /// <summary>Volume total scanné en octets (remontés par clamscan).</summary>
        public long TotalBytesScanned { get; set; }

        // ── Résultats ───────────────────────────────────────────────────────────

        /// <summary>Liste des menaces détectées au cours de cette session.</summary>
        public List<ThreatInfo> Threats { get; set; } = new();

        /// <summary>État courant du scan.</summary>
        public ScanStatus Status { get; set; } = ScanStatus.Running;

        /// <summary>Message d'erreur en cas d'état <see cref="ScanStatus.Error"/>.</summary>
        public string? ErrorMessage { get; set; }

        // ── Propriétés calculées ────────────────────────────────────────────────

        /// <summary>Durée du scan — en cours si <see cref="FinishedAt"/> est <c>null</c>.</summary>
        public TimeSpan Duration =>
            FinishedAt.HasValue ? FinishedAt.Value - StartedAt : DateTime.Now - StartedAt;

        /// <summary><c>true</c> si le scan est terminé sans aucune menace.</summary>
        public bool IsClean => Status == ScanStatus.Completed && ThreatsFound == 0;

        /// <summary>Résumé d'une ligne adapté à l'état courant du scan.</summary>
        public string SummaryDisplay =>
            LocalizationService.ScanSummaryDisplay(
                Status, FilesScanned, ThreatsFound, Duration, ErrorMessage);

        /// <summary>Libellé lisible du type de scan — localisé selon la culture UI active.</summary>
        public string TypeDisplay => LocalizationService.ScanTypeDisplay(Type);

        /// <summary>Durée formatée selon la culture UI active.</summary>
        public string DurationDisplay => ScanDisplayFormatter.FormatDuration(Duration);

        /// <summary>Badge d'état pour l'affichage dans les listes — localisé selon la culture UI active.</summary>
        public string ThreatsBadge => Status switch
        {
            ScanStatus.Running   => LocalizationService.GetString("Badge_Running"),
            ScanStatus.Cancelled => LocalizationService.GetString("Badge_Cancelled"),
            ScanStatus.Error     => LocalizationService.GetString("Badge_Error"),
            _ => ThreatsFound == 0
                ? LocalizationService.GetString("Badge_Clean")
                : LocalizationService.Format("Badge_Threats", ThreatsFound,
                    ThreatsFound > 1 ? "s" : "")
        };
    }

    /// <summary>Type de scan lancé.</summary>
    public enum ScanType
    {
        /// <summary>Analyse d'un fichier unique.</summary>
        File,
        /// <summary>Analyse récursive d'un dossier.</summary>
        Folder,
        /// <summary>Analyse rapide (dossiers système prioritaires).</summary>
        QuickScan,
        /// <summary>Analyse complète de tous les lecteurs.</summary>
        FullScan,
        /// <summary>Analyse automatique d'un lecteur amovible (USB, carte SD…).</summary>
        RemovableDrive
    }

    /// <summary>État d'avancement du scan.</summary>
    public enum ScanStatus
    {
        /// <summary>Scan en cours d'exécution.</summary>
        Running,
        /// <summary>Scan terminé normalement.</summary>
        Completed,
        /// <summary>Scan interrompu par l'utilisateur.</summary>
        Cancelled,
        /// <summary>Scan terminé avec une erreur fatale.</summary>
        Error
    }
}
