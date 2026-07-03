using System.Security.Cryptography;
using System.Text;

namespace optiCombat.Models
{
    /// <summary>
    /// Représente une menace détectée lors d'un scan (ClamAV ou YARA).
    /// </summary>
    public class ThreatInfo
    {
        /// <summary>Chemin complet du fichier infecté.</summary>
        public string FilePath { get; set; } = string.Empty;

        /// <summary>Nom du virus / malware détecté (ex: Win.Trojan.Agent-123456 ou nom de la règle YARA).</summary>
        public string VirusName { get; set; } = string.Empty;

        /// <summary>Date et heure de détection.</summary>
        public DateTime DetectedAt { get; set; } = DateTime.Now;

        /// <summary>Statut de la menace (Détectée, En quarantaine, Supprimée, Ignorée).</summary>
        public ThreatStatus Status { get; set; } = ThreatStatus.Detected;

        /// <summary>Taille du fichier en octets (-1 si non disponible).</summary>
        public long FileSize { get; set; } = -1;

        /// <summary>Chemin vers le fichier en quarantaine (si applicable).</summary>
        public string? QuarantinePath { get; set; }

        /// <summary>Moteur qui a détecté la menace : "ClamAV", "YARA" ou "ClamAV+YARA".</summary>
        public string DetectedBy { get; set; } = "ClamAV";

        /// <summary>ID stable entre sessions (hash SHA-256 déterministe, pas GetHashCode()).</summary>
        public string Id
        {
            get
            {
                var raw = $"{FilePath}|{VirusName}|{DetectedAt:yyyyMMddHHmmss}";
                var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
                return Convert.ToHexString(bytes)[..16];
            }
        }

        /// <summary>Affichage court du nom de fichier (sans le chemin complet).</summary>
        public string FileName => System.IO.Path.GetFileName(FilePath);

        /// <summary>Affichage de la taille en format lisible.</summary>
        public string FileSizeDisplay => FileSize >= 0
            ? FileSize < 1024 ? $"{FileSize} o"
            : FileSize < 1024 * 1024 ? $"{FileSize / 1024.0:F1} Ko"
            : $"{FileSize / (1024.0 * 1024):F1} Mo"
            : "Inconnu";

        /// <summary>Couleur associée au moteur de détection (pour affichage).</summary>
        public string DetectedByColor => DetectedBy switch
        {
            "ClamAV" => "#27AE60",      // Vert
            "YARA" => "#E67E22",        // Orange
            "ClamAV+YARA" => "#9C27B0", // Violet
            _ => "#546478"              // Gris
        };

        /// <summary>Icône associée au moteur de détection.</summary>
        public string DetectedByIcon => DetectedBy switch
        {
            "ClamAV" => "ShieldCheck",
            "YARA" => "FileSearch",
            "ClamAV+YARA" => "ShieldCross",
            _ => "Alert"
        };

        /// <summary>Retourne une copie complète de l'objet.</summary>
        public ThreatInfo Clone()
        {
            return new ThreatInfo
            {
                FilePath = this.FilePath,
                VirusName = this.VirusName,
                DetectedAt = this.DetectedAt,
                Status = this.Status,
                FileSize = this.FileSize,
                QuarantinePath = this.QuarantinePath,
                DetectedBy = this.DetectedBy
            };
        }

        /// <summary>Crée une menace détectée par ClamAV.</summary>
        public static ThreatInfo FromClamAv(string filePath, string virusName, long fileSize = -1)
        {
            return new ThreatInfo
            {
                FilePath = filePath,
                VirusName = virusName,
                FileSize = fileSize,
                DetectedBy = "ClamAV",
                DetectedAt = DateTime.Now
            };
        }

        /// <summary>Crée une menace détectée par YARA.</summary>
        public static ThreatInfo FromYara(string filePath, string ruleName, long fileSize = -1)
        {
            return new ThreatInfo
            {
                FilePath = filePath,
                VirusName = ruleName,
                FileSize = fileSize,
                DetectedBy = "YARA",
                DetectedAt = DateTime.Now
            };
        }

        /// <summary>Crée une menace détectée par les deux moteurs simultanément.</summary>
        public static ThreatInfo FromBoth(string filePath, string clamVirusName, string yaraRuleName, long fileSize = -1)
        {
            return new ThreatInfo
            {
                FilePath = filePath,
                VirusName = $"{clamVirusName} / {yaraRuleName}",
                FileSize = fileSize,
                DetectedBy = "ClamAV+YARA",
                DetectedAt = DateTime.Now
            };
        }

        public override string ToString() =>
            $"[{Status}] {FileName} — {VirusName} ({DetectedBy}) {DetectedAt:dd/MM/yyyy HH:mm:ss}";

        public override bool Equals(object? obj)
        {
            return obj is ThreatInfo other &&
                   FilePath == other.FilePath &&
                   VirusName == other.VirusName &&
                   DetectedBy == other.DetectedBy;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(FilePath, VirusName, DetectedBy);
        }
    }

    /// <summary>Statut d'une menace détectée.</summary>
    public enum ThreatStatus
    {
        /// <summary>Menace détectée, aucune action effectuée.</summary>
        Detected,

        /// <summary>Fichier déplacé en quarantaine.</summary>
        Quarantined,

        /// <summary>Fichier supprimé définitivement.</summary>
        Deleted,

        /// <summary>Menace ignorée par l'utilisateur.</summary>
        Ignored
    }
}