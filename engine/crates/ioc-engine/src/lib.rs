//! ioc-engine — vérification d'IOC réseau hors-ligne (URLhaus, ThreatFox).
//!
//! Architecture conforme au document de recherche optiCOMBAT (couche 3 du pipeline) :
//!
//! ```text
//! Fichier -> calcul SHA-256 -> base de hachage       (reputation)
//!         -> extraction/archives -> ClamAV            (clamav)
//!         -> règles YARA locales                      (yara-engine)
//!         -> IOC URL/domaine/IP                  ← ce crate
//!         -> verdict + score de confiance             (correlator)
//! ```
//!
//! Toutes les listes sont chargées depuis des **fichiers locaux** téléchargés
//! par la couche C#. Ce crate est **purement hors-ligne** :
//! aucune requête réseau, aucune dépendance HTTP.
//!
//! Sources supportées :
//! - **URLhaus** (abuse.ch) : liste texte d'URLs de distribution de malware.
//! - **ThreatFox** (abuse.ch) : CSV d'IOC communautaires (IP, domaines, URLs, hachages).

/// Plafond d'entrées par feed : un export corrompu ou démesuré ne doit pas épuiser
/// la mémoire du processus qui héberge le moteur.
pub const MAX_FEED_ENTRIES: usize = 2_000_000;

pub mod extractor;
pub mod threatfox;
pub mod urlhaus;

// ──────────────────────────────────────────────────────────────
// Types publics
// ──────────────────────────────────────────────────────────────

/// Catégorie d'IOC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IocKind {
    Url,
    Domain,
    /// Adresse IP (IPv4 ou IPv6, avec ou sans port).
    Ip,
}

/// Source ayant produit la correspondance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IocSource {
    Urlhaus,
    Threatfox,
}

impl IocSource {
    pub fn name(&self) -> &'static str {
        match self {
            IocSource::Urlhaus => "URLhaus",
            IocSource::Threatfox => "ThreatFox",
        }
    }
}

/// Correspondance IOC trouvée par une source.
#[derive(Debug, Clone)]
pub struct IocMatch {
    /// Valeur de l'IOC (URL, domaine, IP).
    pub ioc: String,
    pub kind: IocKind,
    pub source: IocSource,
    /// Famille de malware associée (optionnel selon la source).
    pub threat: Option<String>,
    /// Niveau de confiance 0-100.
    pub confidence: u8,
}

// ──────────────────────────────────────────────────────────────
// Trait IocFeed
// ──────────────────────────────────────────────────────────────

/// Source d'IOC réseau pouvant vérifier des URL, domaines et IPs.
pub trait IocFeed: Send + Sync {
    fn check_url(&self, url: &str) -> Option<IocMatch>;
    fn check_domain(&self, domain: &str) -> Option<IocMatch>;
    fn check_ip(&self, ip: &str) -> Option<IocMatch>;
    /// Nombre total d'entrées dans cette source.
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ──────────────────────────────────────────────────────────────
// IocEngine
// ──────────────────────────────────────────────────────────────

/// Moteur IOC : combine plusieurs sources, blacklist prioritaire.
///
/// Utilisé par le `dispatcher` pour l'étape « IOC URL/domaine/IP »
/// du pipeline de détection.
pub struct IocEngine {
    feeds: Vec<Box<dyn IocFeed>>,
}

impl IocEngine {
    pub fn new(feeds: Vec<Box<dyn IocFeed>>) -> Self {
        Self { feeds }
    }

    /// Moteur vide (utilisé quand aucune liste n'est disponible).
    pub fn empty() -> Self {
        Self { feeds: Vec::new() }
    }

    pub fn check_url(&self, url: &str) -> Option<IocMatch> {
        self.feeds.iter().find_map(|f| f.check_url(url))
    }

    pub fn check_domain(&self, domain: &str) -> Option<IocMatch> {
        self.feeds.iter().find_map(|f| f.check_domain(domain))
    }

    pub fn check_ip(&self, ip: &str) -> Option<IocMatch> {
        self.feeds.iter().find_map(|f| f.check_ip(ip))
    }

    /// Vérifie toutes les valeurs extraites (URLs, domaines, IPs) en une passe.
    pub fn check_all(&self, indicators: &Indicators) -> Vec<IocMatch> {
        let mut hits = Vec::new();
        for url in &indicators.urls {
            if let Some(m) = self.check_url(url) {
                hits.push(m);
            }
        }
        for domain in &indicators.domains {
            if let Some(m) = self.check_domain(domain) {
                hits.push(m);
            }
        }
        for ip in &indicators.ips {
            if let Some(m) = self.check_ip(ip) {
                hits.push(m);
            }
        }
        hits
    }

    /// Nombre total d'IOC chargés toutes sources confondues.
    pub fn total_iocs(&self) -> usize {
        self.feeds.iter().map(|f| f.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.feeds.is_empty() || self.feeds.iter().all(|f| f.is_empty())
    }
}

// ──────────────────────────────────────────────────────────────
// Indicators — résultat de l'extraction d'IOC d'un fichier
// ──────────────────────────────────────────────────────────────

/// Indicateurs réseau extraits d'un fichier (URLs, domaines, IPs).
#[derive(Debug, Default, Clone)]
pub struct Indicators {
    pub urls: Vec<String>,
    pub domains: Vec<String>,
    pub ips: Vec<String>,
}

impl Indicators {
    pub fn is_empty(&self) -> bool {
        self.urls.is_empty() && self.domains.is_empty() && self.ips.is_empty()
    }
}

// ──────────────────────────────────────────────────────────────
// Utilitaire : extraction de domaine depuis une URL
// ──────────────────────────────────────────────────────────────

/// Extrait le nom d'hôte d'une URL (sans port, sans chemin).
///
/// ```
/// use ioc_engine::extract_host;
/// assert_eq!(extract_host("https://evil.example/payload.exe"), Some("evil.example".into()));
/// assert_eq!(extract_host("http://1.2.3.4:8080/gate"), Some("1.2.3.4".into()));
/// ```
pub fn extract_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("ftp://"))?;
    let host = rest
        .split('/')
        .next()?
        .split('?')
        .next()?
        .split('#')
        .next()?;
    // Supprime le port (ex. "evil.com:8080" → "evil.com").
    let host = if host.contains(':') {
        host.split(':').next()?
    } else {
        host
    };
    if host.is_empty() || host.contains(' ') {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

// ──────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use threatfox::ThreatFoxFeed;
    use urlhaus::UrlhausFeed;

    #[test]
    fn extract_host_cas_normaux() {
        assert_eq!(
            extract_host("https://evil.example/payload.exe"),
            Some("evil.example".into())
        );
        assert_eq!(
            extract_host("http://1.2.3.4:8080/gate.php"),
            Some("1.2.3.4".into())
        );
        assert_eq!(
            extract_host("http://cdn.malware.tld/a/b/c?x=1"),
            Some("cdn.malware.tld".into())
        );
    }

    #[test]
    fn moteur_vide_ne_detecte_rien() {
        let eng = IocEngine::empty();
        assert!(eng.check_url("https://evil.example").is_none());
        assert!(eng.check_domain("evil.example").is_none());
        assert!(eng.check_ip("1.2.3.4").is_none());
        assert_eq!(eng.total_iocs(), 0);
    }

    #[test]
    fn urlhaus_detecte_url_chargee() {
        let mut feed = UrlhausFeed::new();
        feed.load_text("# URLhaus\nhttps://evil.example/drop.exe\nhttp://bad.tld/rat.bin\n");
        let eng = IocEngine::new(vec![Box::new(feed)]);
        assert!(eng.check_url("https://evil.example/drop.exe").is_some());
        assert!(eng.check_domain("evil.example").is_some());
        assert!(eng.check_url("https://clean.example/app.exe").is_none());
    }

    #[test]
    fn threatfox_detecte_ip_avec_port() {
        let mut feed = ThreatFoxFeed::new();
        // Format simplifié : ioc,ioc_type,malware
        feed.load_csv("\"1.2.3.4:4444\",\"ip:port\",\"Cobalt Strike\"\n");
        let eng = IocEngine::new(vec![Box::new(feed)]);
        let hit = eng.check_ip("1.2.3.4:4444");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().threat.as_deref(), Some("Cobalt Strike"));
    }

    #[test]
    fn check_all_renvoie_correspondances() {
        let mut urlhaus = UrlhausFeed::new();
        urlhaus.load_text("https://drop.evil/pay.exe\n");
        let eng = IocEngine::new(vec![Box::new(urlhaus)]);
        let indicators = Indicators {
            urls: vec![
                "https://drop.evil/pay.exe".into(),
                "https://clean.site/ok".into(),
            ],
            domains: vec![],
            ips: vec![],
        };
        let hits = eng.check_all(&indicators);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, IocKind::Url);
    }
}
