//! Chargement hors-ligne de la threat intel abuse.ch depuis un dossier local.
//!
//! La couche C# (`ThreatIntelFeedUpdater`) télécharge les exports abuse.ch et les
//! dépose dans `%LocalAppData%\optiCombat\threat_intel\`. Ce module lit ce dossier,
//! sans aucun accès réseau, et construit :
//!
//! - une [`MalwareBazaarDb`] (liste noire de SHA-256, couche 1 du pipeline) ;
//! - un [`IocEngine`] URLhaus + ThreatFox (couche 3 du pipeline).
//!
//! Fichiers reconnus (tous optionnels) :
//!
//! | Fichier                    | Format                                   |
//! |----------------------------|------------------------------------------|
//! | `malwarebazaar.csv`        | export CSV MalwareBazaar (`recent.csv`)  |
//! | `malwarebazaar_sha256.txt` | un SHA-256 par ligne                     |
//! | `urlhaus.csv`              | export CSV URLhaus (`online.csv`)        |
//! | `urlhaus.txt`              | une URL par ligne                        |
//! | `threatfox.csv`            | export CSV ThreatFox (15 colonnes)       |
//!
//! Un fichier absent, illisible ou plus gros que [`MAX_FEED_FILE_BYTES`] est
//! ignoré : un dossier partiel ne doit jamais empêcher le moteur de démarrer.

use std::path::{Path, PathBuf};

use ioc_engine::threatfox::ThreatFoxFeed;
use ioc_engine::urlhaus::UrlhausFeed;
use ioc_engine::{IocEngine, IocFeed};
use reputation::MalwareBazaarDb;

/// Nom des fichiers déposés par la couche C#.
pub const MALWAREBAZAAR_CSV: &str = "malwarebazaar.csv";
pub const MALWAREBAZAAR_SHA256_TXT: &str = "malwarebazaar_sha256.txt";
pub const URLHAUS_CSV: &str = "urlhaus.csv";
pub const URLHAUS_TXT: &str = "urlhaus.txt";
pub const THREATFOX_CSV: &str = "threatfox.csv";

/// Variable d'environnement lue par [`crate::Dispatcher::new`] pour charger un dossier.
pub const THREAT_INTEL_DIR_ENV: &str = "OPTICOMBAT_THREAT_INTEL_DIR";

/// Taille maximale d'un fichier de feed lu en mémoire (512 Mio).
pub const MAX_FEED_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Compteurs exposés à l'interface (FFI JSON, CLI).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThreatIntelStats {
    pub malwarebazaar_hashes: usize,
    pub urlhaus_urls: usize,
    pub threatfox_iocs: usize,
}

impl ThreatIntelStats {
    /// Total des entrées chargées toutes sources confondues.
    pub fn total(&self) -> usize {
        self.malwarebazaar_hashes + self.urlhaus_urls + self.threatfox_iocs
    }

    /// Sérialisation JSON stable (consommée par le C#).
    pub fn to_json(&self) -> String {
        format!(
            "{{\"malwarebazaar\":{},\"urlhaus\":{},\"threatfox\":{},\"total\":{}}}",
            self.malwarebazaar_hashes,
            self.urlhaus_urls,
            self.threatfox_iocs,
            self.total()
        )
    }
}

/// Résultat du chargement d'un dossier de threat intel.
pub struct ThreatIntelBundle {
    pub bazaar: MalwareBazaarDb,
    pub ioc: IocEngine,
    pub stats: ThreatIntelStats,
}

impl ThreatIntelBundle {
    /// Bundle vide (aucun feed).
    pub fn empty() -> Self {
        Self {
            bazaar: MalwareBazaarDb::new(),
            ioc: IocEngine::empty(),
            stats: ThreatIntelStats::default(),
        }
    }

    /// Charge tous les feeds présents dans `dir`. Ne renvoie jamais d'erreur :
    /// les fichiers manquants ou invalides sont simplement ignorés.
    pub fn load_dir(dir: &Path) -> Self {
        let mut bazaar = MalwareBazaarDb::new();
        if let Some(text) = read_feed(&dir.join(MALWAREBAZAAR_CSV)) {
            bazaar.load_csv(&text);
        }
        if let Some(text) = read_feed(&dir.join(MALWAREBAZAAR_SHA256_TXT)) {
            bazaar.load_hash_list(&text, "Malware");
        }

        let mut urlhaus = UrlhausFeed::new();
        if let Some(text) = read_feed(&dir.join(URLHAUS_CSV)) {
            urlhaus.load_csv(&text);
        }
        if let Some(text) = read_feed(&dir.join(URLHAUS_TXT)) {
            urlhaus.load_text(&text);
        }

        let mut threatfox = ThreatFoxFeed::new();
        if let Some(text) = read_feed(&dir.join(THREATFOX_CSV)) {
            threatfox.load_csv(&text);
        }

        let stats = ThreatIntelStats {
            malwarebazaar_hashes: bazaar.hash_count(),
            urlhaus_urls: urlhaus.url_count(),
            threatfox_iocs: threatfox.ioc_count(),
        };

        let mut feeds: Vec<Box<dyn IocFeed>> = Vec::new();
        if !urlhaus.is_empty() {
            feeds.push(Box::new(urlhaus));
        }
        if !threatfox.is_empty() {
            feeds.push(Box::new(threatfox));
        }

        Self {
            bazaar,
            ioc: IocEngine::new(feeds),
            stats,
        }
    }

    /// Dossier désigné par [`THREAT_INTEL_DIR_ENV`], s'il est renseigné et existe.
    pub fn dir_from_env() -> Option<PathBuf> {
        let raw = std::env::var_os(THREAT_INTEL_DIR_ENV)?;
        let dir = PathBuf::from(raw);
        if dir.as_os_str().is_empty() || !dir.is_dir() {
            return None;
        }
        Some(dir)
    }
}

/// Lit un fichier de feed en texte (UTF-8 avec remplacement des octets invalides).
fn read_feed(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FEED_FILE_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reputation::{Reputation, ReputationSource};

    fn unique_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "oc_ti_{tag}_{}_{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn write_all_feeds(dir: &Path) {
        // Exports réels : séparateur `", "` (MalwareBazaar), en-têtes commentés.
        std::fs::write(
            dir.join(MALWAREBAZAAR_CSV),
            format!(
                "################################################################\n\
                 # MalwareBazaar recent malware samples (CSV)\n\
                 # \"first_seen_utc\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\",\"reporter\",\"file_name\",\"file_type_guess\",\"mime_type\",\"signature\",\"clamav\",\"vtpercent\",\"imphash\",\"ssdeep\",\"tlsh\"\n\
                 \"2026-10-23 10:00:00\", \"{SHA_A}\", \"m\", \"s\", \"r\", \"a.exe\", \"exe\", \"application/x-dosexec\", \"AgentTesla\", \"n/a\", \"n/a\", \"x\", \"y\", \"z\"\n"
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join(MALWAREBAZAAR_SHA256_TXT),
            format!("# liste\n{SHA_B}\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join(URLHAUS_CSV),
            "################################################################\n\
             # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n\
             \"3300001\",\"2026-10-23 10:00:00\",\"http://drop.example.net/a.exe\",\"online\",\"2026-10-23 10:00:00\",\"malware_download\",\"exe\",\"https://urlhaus.abuse.ch/url/3300001/\",\"r\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join(URLHAUS_TXT),
            "# text\nhttp://second.example.org/b.ps1\n",
        )
        .unwrap();
        std::fs::write(
            dir.join(THREATFOX_CSV),
            "# \"first_seen_utc\",\"ioc_id\",\"ioc_value\",\"ioc_type\",\"threat_type\",\"fk_malware\",\"malware_alias\",\"malware_printable\",\"last_seen_utc\",\"confidence_level\",\"is_compromised\",\"reference\",\"tags\",\"anonymous\",\"reporter\"\n\
             \"2026-10-23 10:00:00\", \"1600001\", \"c2.example.com\", \"domain\", \"botnet_cc\", \"win.cobalt_strike\", \"None\", \"Cobalt Strike\", \"\", \"100\", \"0\", \"\", \"cs\", \"0\", \"r\"\n",
        )
        .unwrap();
    }

    #[test]
    fn dossier_absent_donne_bundle_vide() {
        let b = ThreatIntelBundle::load_dir(Path::new("/chemin/qui/n/existe/pas"));
        assert_eq!(b.stats, ThreatIntelStats::default());
        assert!(b.ioc.is_empty());
        assert_eq!(b.stats.total(), 0);
    }

    #[test]
    fn charge_tous_les_feeds_aux_formats_reels() {
        let dir = unique_dir("all");
        write_all_feeds(&dir);
        let b = ThreatIntelBundle::load_dir(&dir);
        assert_eq!(b.stats.malwarebazaar_hashes, 2);
        assert_eq!(b.stats.urlhaus_urls, 2);
        assert_eq!(b.stats.threatfox_iocs, 1);
        assert_eq!(b.stats.total(), 5);

        match b.bazaar.lookup(SHA_A) {
            Reputation::Blacklisted(n) => assert_eq!(n, "MalwareBazaar:AgentTesla"),
            other => panic!("attendu liste noire, obtenu {other:?}"),
        }
        assert!(matches!(b.bazaar.lookup(SHA_B), Reputation::Blacklisted(_)));
        assert!(b.ioc.check_url("http://drop.example.net/a.exe").is_some());
        assert!(b.ioc.check_url("http://second.example.org/b.ps1").is_some());
        let tf = b.ioc.check_domain("c2.example.com").unwrap();
        assert_eq!(tf.threat.as_deref(), Some("Cobalt Strike"));
        assert_eq!(tf.confidence, 100);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fichier_partiel_charge_ce_qui_existe() {
        let dir = unique_dir("partial");
        std::fs::write(dir.join(URLHAUS_TXT), "http://only.example/x\n").unwrap();
        let b = ThreatIntelBundle::load_dir(&dir);
        assert_eq!(b.stats.urlhaus_urls, 1);
        assert_eq!(b.stats.malwarebazaar_hashes, 0);
        assert_eq!(b.stats.threatfox_iocs, 0);
        assert!(!b.ioc.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn un_dossier_a_la_place_d_un_fichier_est_ignore() {
        let dir = unique_dir("isdir");
        std::fs::create_dir_all(dir.join(THREATFOX_CSV)).unwrap();
        let b = ThreatIntelBundle::load_dir(&dir);
        assert_eq!(b.stats.threatfox_iocs, 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn octets_invalides_ne_bloquent_pas_le_chargement() {
        let dir = unique_dir("utf8");
        let mut data = b"\xff\xfe# entete binaire\n".to_vec();
        data.extend_from_slice(b"http://bin.example/z\n");
        std::fs::write(dir.join(URLHAUS_TXT), data).unwrap();
        let b = ThreatIntelBundle::load_dir(&dir);
        assert_eq!(b.stats.urlhaus_urls, 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stats_json_stable() {
        let s = ThreatIntelStats {
            malwarebazaar_hashes: 3,
            urlhaus_urls: 2,
            threatfox_iocs: 1,
        };
        assert_eq!(
            s.to_json(),
            r#"{"malwarebazaar":3,"urlhaus":2,"threatfox":1,"total":6}"#
        );
    }

    #[test]
    fn bundle_vide_explicite() {
        let b = ThreatIntelBundle::empty();
        assert!(b.ioc.is_empty());
        assert_eq!(b.bazaar.hash_count(), 0);
    }

    #[test]
    fn dir_from_env_ignore_valeur_absente_ou_invalide() {
        // Une seule fonction de test manipule la variable : pas de course entre tests.
        std::env::remove_var(THREAT_INTEL_DIR_ENV);
        assert!(ThreatIntelBundle::dir_from_env().is_none());
        std::env::set_var(THREAT_INTEL_DIR_ENV, "");
        assert!(ThreatIntelBundle::dir_from_env().is_none());
        std::env::set_var(THREAT_INTEL_DIR_ENV, "/inexistant/oc_ti");
        assert!(ThreatIntelBundle::dir_from_env().is_none());
        let dir = unique_dir("env");
        std::env::set_var(THREAT_INTEL_DIR_ENV, &dir);
        assert_eq!(
            ThreatIntelBundle::dir_from_env().as_deref(),
            Some(dir.as_path())
        );
        std::env::remove_var(THREAT_INTEL_DIR_ENV);
        let _ = std::fs::remove_dir_all(dir);
    }
}
