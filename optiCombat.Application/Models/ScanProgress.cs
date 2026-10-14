using optiCombat.Localization;

namespace optiCombat.Models
{
    /// <summary>
    /// Phases possibles du scan.
    /// </summary>
    public enum ScanPhase
    {
        Starting,
        Scanning,
        ThreatFound,
        Completed,
        Cancelled,
        Error
    }

    /// <summary>
    /// Progression du scan (utilisé avec IProgress pour remonter l'état en temps réel).
    /// </summary>
    public class ScanProgress
    {
        /// <summary>Message de progression affiché à l'utilisateur.</summary>
        public string Message { get; set; } = string.Empty;

        /// <summary>Nombre total de fichiers scannés.</summary>
        public int FilesScanned { get; set; }

        /// <summary>
        /// Nombre total de fichiers à scanner (connu seulement après énumération).
        /// 0 = inconnu (la progressbar restera indéterminée).
        /// </summary>
        public int TotalFiles { get; set; }

        /// <summary>
        /// Pourcentage d'avancement [0, 100]. -1 si TotalFiles est inconnu.
        /// </summary>
        public double PercentComplete => TotalFiles > 0
            ? Math.Min(100.0, FilesScanned * 100.0 / TotalFiles)
            : -1.0;

        /// <summary>Nombre total de menaces trouvées.</summary>
        public int ThreatsFound { get; set; }

        /// <summary>Phase actuelle du scan.</summary>
        public ScanPhase Phase { get; set; }

        /// <summary>Information sur la dernière menace trouvée (si Phase == ThreatFound).</summary>
        public ThreatInfo? ThreatInfo { get; set; }

        /// <summary>Dernier fichier ou dossier en cours d’analyse (affichage type suite antivirus).</summary>
        public string? CurrentFilePath { get; set; }

        /// <summary>Nombre de fichiers scannés par YARA.</summary>
        public int YaraFilesScanned { get; set; }

        /// <summary>Nombre de correspondances YARA trouvées.</summary>
        public int YaraMatchesFound { get; set; }

        /// <summary>Nombre de fichiers scannés par ClamAV.</summary>
        public int ClamFilesScanned { get; set; }

        /// <summary>Nombre de menaces ClamAV trouvées.</summary>
        public int ClamThreatsFound { get; set; }

        /// <summary>
        /// Constructeur par défaut.
        /// </summary>
        public ScanProgress()
        {
        }

        /// <summary>
        /// Constructeur de copie.
        /// </summary>
        public ScanProgress(ScanProgress other)
        {
            if (other == null) return;

            Message = other.Message;
            FilesScanned = other.FilesScanned;
            ThreatsFound = other.ThreatsFound;
            Phase = other.Phase;
            ThreatInfo = other.ThreatInfo?.Clone();
            YaraFilesScanned = other.YaraFilesScanned;
            YaraMatchesFound = other.YaraMatchesFound;
            ClamFilesScanned = other.ClamFilesScanned;
            ClamThreatsFound = other.ClamThreatsFound;
            TotalFiles = other.TotalFiles;
            CurrentFilePath = other.CurrentFilePath;
        }

        /// <summary>
        /// Crée une copie profonde de l'objet ScanProgress.
        /// </summary>
        public ScanProgress Clone()
        {
            return new ScanProgress(this);
        }

        /// <summary>
        /// Met à jour les statistiques de progression depuis un autre ScanProgress.
        /// </summary>
        public void UpdateFrom(ScanProgress other)
        {
            if (other == null) return;

            Message = other.Message;
            FilesScanned = other.FilesScanned;
            ThreatsFound = other.ThreatsFound;
            Phase = other.Phase;
            ThreatInfo = other.ThreatInfo?.Clone();
            YaraFilesScanned = other.YaraFilesScanned;
            YaraMatchesFound = other.YaraMatchesFound;
            ClamFilesScanned = other.ClamFilesScanned;
            ClamThreatsFound = other.ClamThreatsFound;
            TotalFiles = other.TotalFiles;
            CurrentFilePath = other.CurrentFilePath;
        }

        /// <summary>
        /// Réinitialise la progression.
        /// </summary>
        public void Reset()
        {
            Message = string.Empty;
            FilesScanned = 0;
            ThreatsFound = 0;
            Phase = ScanPhase.Starting;
            ThreatInfo = null;
            YaraFilesScanned = 0;
            YaraMatchesFound = 0;
            ClamFilesScanned = 0;
            ClamThreatsFound = 0;
            TotalFiles = 0;
            CurrentFilePath = null;
        }

        /// <summary>
        /// Crée une progression initiale avec le message localisé <c>Scan_Starting</c>.
        /// </summary>
        public static ScanProgress Starting(string? message = null)
        {
            return new ScanProgress
            {
                Message = message ?? LocalizationService.GetString("Scan_Starting"),
                Phase = ScanPhase.Starting
            };
        }

        /// <summary>
        /// Crée une progression pour une menace trouvée.
        /// </summary>
        public static ScanProgress ThreatFound(ThreatInfo threat)
        {
            return new ScanProgress
            {
                Message = $"{threat.VirusName} — {threat.FilePath}",
                Phase = ScanPhase.ThreatFound,
                ThreatInfo = threat,
                ThreatsFound = 1,
                CurrentFilePath = threat.FilePath,
            };
        }

        /// <summary>
        /// Crée une progression de scan en cours.
        /// </summary>
        public static ScanProgress Scanning(string message, int filesScanned, int threatsFound = 0)
        {
            return new ScanProgress
            {
                Message = message,
                FilesScanned = filesScanned,
                ThreatsFound = threatsFound,
                Phase = ScanPhase.Scanning
            };
        }

        /// <summary>
        /// Crée une progression pour un scan terminé.
        /// </summary>
        public static ScanProgress Completed(string message, int filesScanned, int threatsFound)
        {
            return new ScanProgress
            {
                Message = message,
                FilesScanned = filesScanned,
                ThreatsFound = threatsFound,
                Phase = ScanPhase.Completed
            };
        }

        /// <summary>
        /// Crée une progression pour un scan annulé.
        /// </summary>
        public static ScanProgress Cancelled(string message = "Scan annulé.")
        {
            return new ScanProgress
            {
                Message = message,
                Phase = ScanPhase.Cancelled
            };
        }

        /// <summary>
        /// Crée une progression pour une erreur.
        /// </summary>
        public static ScanProgress Error(string message)
        {
            return new ScanProgress
            {
                Message = message,
                Phase = ScanPhase.Error
            };
        }

        /// <summary>
        /// Indique si le scan est terminé (réussi, annulé ou en erreur).
        /// </summary>
        public bool IsFinished => Phase == ScanPhase.Completed ||
                                   Phase == ScanPhase.Cancelled ||
                                   Phase == ScanPhase.Error;

        /// <summary>
        /// Indique si le scan est en cours actif.
        /// </summary>
        public bool IsActive => Phase == ScanPhase.Starting ||
                                 Phase == ScanPhase.Scanning;

        public override string ToString()
        {
            return $"[{Phase}] {Message} (Fichiers: {FilesScanned}, Menaces: {ThreatsFound})";
        }
    }
}