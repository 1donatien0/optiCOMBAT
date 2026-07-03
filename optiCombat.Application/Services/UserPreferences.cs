using optiCombat.Localization;
using optiCombat.Models;
using Microsoft.Win32;
using System.IO;
using System.Runtime.Versioning;
using System.Text.Json.Serialization;

namespace optiCombat.Services
{
    /// <summary>
    /// Sauvegarde les préférences utilisateur dans un fichier sécurisé
    /// (chiffrement DPAPI CurrentUser + HMAC-SHA256 d'intégrité).
    ///
    /// Persiste entre les sessions : cibles récentes, type de scan favori, etc.
    /// L'ancien format JSON en clair est migré automatiquement au premier
    /// chargement (renommé en .legacy puis ignoré ensuite).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class UserPreferences
    {
        // ── Singleton thread-safe ────────────────────────────────────────────────
        // Lazy<T> ExecutionAndPublication = une seule instance même sous accès
        // concurrent (UI + protection temps réel + scan planifié).
        private static readonly Lazy<UserPreferences> _instance =
            new(Load, LazyThreadSafetyMode.ExecutionAndPublication);
        public static UserPreferences Current => _instance.Value;

        // Sérialise les écritures concurrentes pour éviter la corruption JSON.
        private static readonly object _saveLock = new();

        // ── Chemins ───────────────────────────────────────────────────────────────
        // Nouveau format : chiffré DPAPI + HMAC dans preferences.dat
        // Legacy   : JSON en clair preferences.json (migré au 1er chargement)
        private static readonly string FilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "optiCombat", "preferences.dat");

        private static readonly string LegacyPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "optiCombat", "preferences.json");

        // ── Propriétés persistées ─────────────────────────────────────────────────

        /// <summary>5 dernières cibles scannées (chemin + type).</summary>
        public List<RecentScanTarget> RecentTargets { get; set; } = new();

        /// <summary>Type de scan favori de l'utilisateur.</summary>
        // Auparavant `string` ("QuickScan", "FullScan"...) ce qui rendait toute
        // typo silencieusement valide. L'enum ScanType garantit la cohérence
        // avec le reste du domaine. JsonStringEnumConverter sérialise en
        // string lisible pour conserver la rétrocompatibilité du fichier JSON.
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public ScanType FavoriteScanType { get; set; } = ScanType.QuickScan;

        /// <summary>Dernier chemin scanné (dossier ou fichier).</summary>
        public string? LastScanPath { get; set; }

        /// <summary>Nombre total de scans effectués (statistique affichée).</summary>
        public int TotalScansCount { get; set; } = 0;

        /// <summary>Date du dernier scan complet.</summary>
        public DateTime? LastFullScanDate { get; set; }

        /// <summary>Thème sombre activé (true) ou clair (false).</summary>
        /// <remarks>Par défaut clair, aligné sur Donaby.Light.xaml au premier lancement.</remarks>
        public bool DarkTheme { get; set; } = false;

        /// <summary>Suivre le thème Windows automatiquement.</summary>
        /// <summary>Vrai par défaut : optiCombat suit le thème applications de Windows.</summary>
        public bool SyncWindowsTheme { get; set; } = true;

        /// <summary>Afficher les notifications d'action (toast avec boutons).</summary>
        public bool ActionNotificationsEnabled { get; set; } = true;

        /// <summary>MAJ automatique des signatures ClamAV et des règles YARA (timers freshclam / YARA-Forge).</summary>
        public bool SignatureAutoUpdateEnabled { get; set; } = true;

        /// <summary>Culture UI (fr-FR ou en-US). Vide = langue de l'installateur au premier lancement.</summary>
        public string UiCulture { get; set; } = string.Empty;

        /// <summary>Assistant de bienvenue affiché une fois au premier lancement.</summary>
        public bool OnboardingCompleted { get; set; }

        /// <summary>Thème à contraste renforcé (lisibilité accrue).</summary>
        public bool HighContrastEnabled { get; set; }

        /// <summary>Préférer le daemon clamd (repli automatique sur clamscan.exe).</summary>
        public bool UseClamdEngine { get; set; } = true;

        /// <summary>Mode jeu : réduit notifications et reports scans headless si plein écran / jeu.</summary>
        public bool GameModeAutoEnabled { get; set; } = true;

        /// <summary>Analyser automatiquement les lecteurs amovibles à l'insertion.</summary>
        public bool RemovableDriveScanEnabled { get; set; } = true;

        /// <summary>Analyse USB complète (récursive) ; sinon fichiers à risque uniquement.</summary>
        public bool RemovableDriveScanDetailed { get; set; }

        /// <summary>Taille max. du lecteur (Go) ; 0 = pas de limite.</summary>
        public int RemovableDriveMaxSizeGb { get; set; } = 64;

        /// <summary>Inclure les lecteurs amovibles dans l'analyse complète manuelle.</summary>
        public bool IncludeRemovableInFullScan { get; set; }

        /// <summary>Clé API VirusTotal (optionnelle, stockée chiffrée via SecureStore).</summary>
        public string VirusTotalApiKey { get; set; } = string.Empty;

        /// <summary>Surveille les lancements de processus (WMI) en complément de la RTP fichier.</summary>
        public bool ProcessMonitorEnabled { get; set; } = true;

        /// <summary>Copie de sécurité locale avant quarantaine automatique.</summary>
        public bool BackupBeforeQuarantine { get; set; }

        /// <summary>Tâche planifiée de relance si la protection est coupée (watchdog).</summary>
        public bool TamperProtectionEnabled { get; set; } = true;

        /// <summary>MAJ signatures plus fréquentes (2 h ClamAV, 12 h YARA).</summary>
        public bool AggressiveSignatureUpdates { get; set; }

        /// <summary>
        /// Utiliser le service Windows / minifiltre noyau pour la protection système avancée.
        /// Défaut : <c>false</c> — la protection temps réel user-mode (FileSystemWatcher) fonctionne SANS
        /// pilote ni signature Microsoft. Le mode plateforme nécessite un pilote minifiltre SIGNÉ
        /// (Partner Center / EV) : à n'activer que lorsque ce pilote est disponible et signé.
        /// </summary>
        public bool UsePlatformProtectionService { get; set; }

        /// <summary>
        /// Seuil (jours) au-delà duquel une suggestion de nettoyage est affichée sur l'accueil.
        /// Valeur par défaut : <see cref="RecommendationThresholds.CleanSuggestThresholdDays"/>.
        /// </summary>
        public int CleanSuggestThresholdDays { get; set; } = RecommendationThresholds.CleanSuggestThresholdDays;

        /// <summary>
        /// Seuil (jours) au-delà duquel les signatures ClamAV sont considérées obsolètes.
        /// Valeur par défaut : <see cref="RecommendationThresholds.SignatureStaleThresholdDays"/>.
        /// </summary>
        public int SignatureStaleThresholdDays { get; set; } = RecommendationThresholds.SignatureStaleThresholdDays;

        // ── Méthodes ──────────────────────────────────────────────────────────────

        /// <summary>
        /// Ajoute une cible récente (max 5). Les doublons sont déplacés en tête.
        /// </summary>
        public void AddRecentTarget(string path, ScanType scanType)
        {
            // Supprimer si déjà présent
            RecentTargets.RemoveAll(t => t.Path.Equals(path, StringComparison.OrdinalIgnoreCase));

            // Insérer en tête
            RecentTargets.Insert(0, new RecentScanTarget
            {
                Path = path,
                ScanType = scanType,
                LastUsed = DateTime.Now
            });

            // Garder seulement 5
            if (RecentTargets.Count > 5)
                RecentTargets.RemoveRange(5, RecentTargets.Count - 5);

            LastScanPath = path;
            Save();
        }

        /// <summary>Incrémente le compteur de scans terminés et sauvegarde.</summary>
        /// <remarks>Ne modifie pas <see cref="FavoriteScanType"/> (préférence utilisateur distincte).</remarks>
        public void IncrementScanCount(ScanType scanType)
        {
            TotalScansCount++;
            if (scanType == ScanType.FullScan)
                LastFullScanDate = DateTime.Now;
            Save();
        }

        /// <summary>Sauvegarde les préférences (DPAPI + HMAC, atomique, thread-safe).</summary>
        public void Save()
        {
            lock (_saveLock)
            {
                try
                {
                    var dir = Path.GetDirectoryName(FilePath)!;
                    if (!Directory.Exists(dir))
                        Directory.CreateDirectory(dir);

                    SecureStore.Save(FilePath, this);
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("UserPreferences", "Save", ex);
                }
            }
        }

        /// <summary>
        /// Charge les préférences depuis le fichier sécurisé. Migre depuis le
        /// fichier JSON en clair si présent (anciennes versions optiCombat).
        /// </summary>
        private static UserPreferences Load() => LoadFromStorage(FilePath, LegacyPath);

        /// <summary>Charge ou migre depuis des chemins explicites (tests, outils).</summary>
        internal static UserPreferences LoadFromStorage(string securePath, string legacyPlaintextPath)
        {
            var loaded = SecureStore.Load<UserPreferences>(securePath);
            if (loaded != null)
            {
                PlatformProtectionFeatureGate.NormalizePreferences(loaded);
                return loaded;
            }

            var migrated = SecureStore.MigrateFromPlaintext<UserPreferences>(legacyPlaintextPath, securePath);
            if (migrated != null)
            {
                PlatformProtectionFeatureGate.NormalizePreferences(migrated);
                return migrated;
            }

            // Premier lancement : synchroniser avec les choix faits à l'installation (Inno Setup).
            // Inno écrit HKCU\Software\optiCombat\AutoUpdateSignatures (dword 1/0) quand la tâche est
            // cochée/décochée. Sans cette lecture, UserPreferences ignore le choix de l'installateur.
            var prefs = new UserPreferences();
            ApplyInnoSetupDefaults(prefs);
            return prefs;
        }

        /// <summary>
        /// Lit les clés registre écrites par Inno Setup et les applique aux préférences
        /// par défaut. Appelé uniquement au premier lancement (aucun fichier de prefs existant).
        /// </summary>
        private static void ApplyInnoSetupDefaults(UserPreferences prefs)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\optiCombat");
                if (key == null) return;

                // AutoUpdateSignatures : 1 = activé, 0 = désactivé
                if (key.GetValue("AutoUpdateSignatures") is int autoUpdate)
                    prefs.SignatureAutoUpdateEnabled = autoUpdate != 0;

                AppLogger.Info("UserPreferences", $"Valeurs Inno appliquées : AutoUpdateSignatures={prefs.SignatureAutoUpdateEnabled}");
            }
            catch (Exception ex)
            {
                AppLogger.Warn("UserPreferences", "ApplyInnoSetupDefaults", ex);
            }
        }

        /// <summary>Sauvegarde vers un chemin explicite (tests).</summary>
        internal static void SaveToStorage(string securePath, UserPreferences prefs)
        {
            lock (_saveLock)
            {
                try
                {
                    var dir = Path.GetDirectoryName(securePath)!;
                    if (!Directory.Exists(dir))
                        Directory.CreateDirectory(dir);
                    SecureStore.Save(securePath, prefs);
                }
                catch (Exception ex)
                {
                    AppLogger.Warn("UserPreferences", "SaveToStorage", ex);
                }
            }
        }
    }

    /// <summary>Représente une cible de scan récente.</summary>
    public sealed class RecentScanTarget
    {
        public string Path { get; set; } = string.Empty;

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public ScanType ScanType { get; set; } = Models.ScanType.QuickScan;

        public DateTime LastUsed { get; set; }

        /// <summary>Affichage court pour les menus.</summary>
        public string DisplayName => System.IO.Path.GetFileName(Path) is { Length: > 0 } n ? n : Path;

        /// <summary>Ligne pour la liste des cibles récentes (panneau Antivirus).</summary>
        [JsonIgnore]
        public string ListLabel =>
            LocalizationService.RecentTargetLabel(ScanType, DisplayName);
    }
}
