//! URLhaus — source d'IOC de distribution de malware (abuse.ch).
//!
//! Deux formats supportés :
//! - **Texte** : `https://urlhaus.abuse.ch/downloads/text/` — une URL par ligne, `#` = commentaire.
//! - **CSV**   : `https://urlhaus.abuse.ch/downloads/csv/` — colonnes `id,dateadded,url,...`.
//!
//! Le fichier est téléchargé par la couche C# et stocké dans
//! `%LocalAppData%\optiCombat\threat_intel\urlhaus.txt`.

use crate::{extract_host, IocFeed, IocKind, IocMatch, IocSource};
use std::collections::HashSet;

/// Base URLhaus chargée hors-ligne depuis le fichier texte ou CSV.
pub struct UrlhausFeed {
    /// URLs exactes (en minuscules).
    urls: HashSet<String>,
    /// Domaines / IPs extraits des URLs (en minuscules).
    domains: HashSet<String>,
}

impl UrlhausFeed {
    pub fn new() -> Self {
        Self {
            urls: HashSet::new(),
            domains: HashSet::new(),
        }
    }

    /// Charge le format **texte** (une URL par ligne, `#` = commentaire).
    ///
    /// Renvoie le nombre d'URLs chargées.
    pub fn load_text(&mut self, text: &str) -> usize {
        let mut count = 0usize;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let url = line.to_ascii_lowercase();
            if !url.starts_with("http") && !url.starts_with("ftp") {
                continue;
            }
            if let Some(host) = extract_host(&url) {
                self.domains.insert(host);
            }
            self.urls.insert(url);
            count += 1;
        }
        count
    }

    /// Charge le format **CSV** URLhaus.
    ///
    /// Colonnes attendues : `id,dateadded,url,url_status,last_online,threat,tags,...`
    ///
    /// Renvoie le nombre d'URLs chargées.
    pub fn load_csv(&mut self, csv: &str) -> usize {
        let mut count = 0usize;
        for line in csv.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // L'URL est en 3ème colonne (index 2).
            let url = match csv_nth_field(line, 2) {
                Some(u) => u.to_ascii_lowercase(),
                None => continue,
            };
            if !url.starts_with("http") && !url.starts_with("ftp") {
                continue;
            }
            if let Some(host) = extract_host(&url) {
                self.domains.insert(host);
            }
            self.urls.insert(url);
            count += 1;
        }
        count
    }

    pub fn url_count(&self) -> usize {
        self.urls.len()
    }
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }
}

impl Default for UrlhausFeed {
    fn default() -> Self {
        Self::new()
    }
}

impl IocFeed for UrlhausFeed {
    fn check_url(&self, url: &str) -> Option<IocMatch> {
        let url_lc = url.to_ascii_lowercase();
        if self.urls.contains(&url_lc) {
            return Some(IocMatch {
                ioc: url.to_string(),
                kind: IocKind::Url,
                source: IocSource::Urlhaus,
                threat: None,
                confidence: 90,
            });
        }
        None
    }

    fn check_domain(&self, domain: &str) -> Option<IocMatch> {
        let d = domain.to_ascii_lowercase();
        if self.domains.contains(&d) {
            return Some(IocMatch {
                ioc: domain.to_string(),
                kind: IocKind::Domain,
                source: IocSource::Urlhaus,
                threat: None,
                confidence: 75,
            });
        }
        None
    }

    fn check_ip(&self, _ip: &str) -> Option<IocMatch> {
        // URLhaus n'indexe pas les IPs directement (check_domain gère les IPs
        // extraites des URLs si l'hôte est une IP).
        None
    }

    fn len(&self) -> usize {
        self.urls.len()
    }
}

/// Extrait le N-ème champ d'une ligne CSV simple (guillemets optionnels, virgule séparateur).
fn csv_nth_field(line: &str, n: usize) -> Option<String> {
    let mut idx = 0usize;
    let mut in_quotes = false;
    let mut current = String::new();
    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                if idx == n {
                    return Some(current);
                }
                idx += 1;
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if idx == n {
        Some(current)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URLHAUS_TEXT: &str = r#"
# URLhaus export (Tue, 01 Jan 2026)
# Fields: url
https://evil.example/malware.exe
http://cdn.bad.tld/rat.zip
# ligne ignorée
ftp://drop.malware.cc/agent.bin
"#;

    #[test]
    fn charge_depuis_texte() {
        let mut feed = UrlhausFeed::new();
        let n = feed.load_text(URLHAUS_TEXT);
        assert_eq!(n, 3);
        assert_eq!(feed.url_count(), 3);
        assert_eq!(feed.domain_count(), 3);
    }

    #[test]
    fn detection_url_exacte() {
        let mut feed = UrlhausFeed::new();
        feed.load_text(URLHAUS_TEXT);
        let m = feed.check_url("https://evil.example/malware.exe").unwrap();
        assert_eq!(m.source, IocSource::Urlhaus);
        assert_eq!(m.kind, IocKind::Url);
        assert!(m.confidence >= 80);
    }

    #[test]
    fn detection_domaine_extrait() {
        let mut feed = UrlhausFeed::new();
        feed.load_text(URLHAUS_TEXT);
        let m = feed.check_domain("evil.example").unwrap();
        assert_eq!(m.kind, IocKind::Domain);
    }

    #[test]
    fn pas_de_detection_url_propre() {
        let mut feed = UrlhausFeed::new();
        feed.load_text(URLHAUS_TEXT);
        assert!(feed.check_url("https://clean.example/update.exe").is_none());
    }

    #[test]
    fn insensible_a_la_casse() {
        let mut feed = UrlhausFeed::new();
        feed.load_text("https://EVIL.EXAMPLE/MALWARE.EXE\n");
        // L'URL est normalisée en minuscules à l'insertion.
        assert!(feed.check_url("https://evil.example/malware.exe").is_some());
    }

    #[test]
    fn charge_depuis_csv() {
        let csv =
            "1,2026-01-01 00:00:00 UTC,https://csv.evil/drop.exe,online,,malware_download,,\n";
        let mut feed = UrlhausFeed::new();
        let n = feed.load_csv(csv);
        assert_eq!(n, 1);
        assert!(feed.check_domain("csv.evil").is_some());
    }

    #[test]
    fn csv_nth_field_fonctionne() {
        assert_eq!(csv_nth_field("a,b,c,d", 2), Some("c".into()));
        assert_eq!(csv_nth_field("\"a\",\"b\",\"c\"", 1), Some("b".into()));
        assert!(csv_nth_field("a,b", 5).is_none());
    }
}
