//! ThreatFox — IOC communautaires (abuse.ch).
//!
//! Supporte le format CSV exporté depuis `https://threatfox.abuse.ch/export/csv/`
//! (ou le dump complet `full.csv.gz`).
//!
//! Colonnes du CSV ThreatFox (export complet, format en vigueur depuis 2026-10) :
//! ```text
//! first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, fk_malware,
//! malware_alias, malware_printable, last_seen_utc, confidence_level, …
//! ```
//! Index (0-based) utilisés : 2=ioc_value, 3=ioc_type, 7=malware_printable,
//! 9=confidence_level.
//!
//! Le format court (3 colonnes : ioc_value, ioc_type, malware) est conservé
//! pour les tests et les exports réduits.
//!
//! Le fichier est téléchargé par la couche C# et stocké dans
//! `%LocalAppData%\optiCombat\threat_intel\threatfox.csv`.

use crate::{IocFeed, IocKind, IocMatch, IocSource};
use std::collections::HashMap;

/// Entrée interne ThreatFox (ce qu'on garde en mémoire par IOC).
#[derive(Clone)]
struct TfEntry {
    malware: String,
    ioc_type: String,
    confidence: u8,
}

/// Base ThreatFox chargée hors-ligne depuis le CSV export.
pub struct ThreatFoxFeed {
    /// Toutes les entrées indexées par IOC normalisé en minuscules.
    entries: HashMap<String, TfEntry>,
}

impl ThreatFoxFeed {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Charge le CSV ThreatFox (avec ou sans ligne d'en-tête, `#` = commentaire).
    ///
    /// Renvoie le nombre d'IOC chargés.
    pub fn load_csv(&mut self, csv: &str) -> usize {
        let mut count = 0usize;
        for line in csv.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Ignore la ligne d'en-tête (nouveau format : first_seen_utc ; ancien : ioc_id).
            if line.starts_with("first_seen_utc")
                || line.starts_with("\"first_seen_utc\"")
                || line.starts_with("\"ioc_id\"")
                || line.starts_with("ioc_id")
            {
                continue;
            }
            if let Some((ioc, entry)) = parse_line(line) {
                self.entries.insert(ioc, entry);
                count += 1;
            }
        }
        count
    }

    pub fn ioc_count(&self) -> usize {
        self.entries.len()
    }

    fn lookup(&self, ioc: &str) -> Option<&TfEntry> {
        self.entries.get(&ioc.to_ascii_lowercase())
    }
}

impl Default for ThreatFoxFeed {
    fn default() -> Self {
        Self::new()
    }
}

impl IocFeed for ThreatFoxFeed {
    fn check_url(&self, url: &str) -> Option<IocMatch> {
        self.lookup(url)
            .filter(|e| e.ioc_type.contains("url"))
            .map(|e| IocMatch {
                ioc: url.to_string(),
                kind: IocKind::Url,
                source: IocSource::Threatfox,
                threat: Some(e.malware.clone()),
                confidence: e.confidence,
            })
    }

    fn check_domain(&self, domain: &str) -> Option<IocMatch> {
        self.lookup(domain)
            .filter(|e| e.ioc_type.contains("domain") || e.ioc_type.contains("host"))
            .map(|e| IocMatch {
                ioc: domain.to_string(),
                kind: IocKind::Domain,
                source: IocSource::Threatfox,
                threat: Some(e.malware.clone()),
                confidence: e.confidence,
            })
    }

    fn check_ip(&self, ip: &str) -> Option<IocMatch> {
        // ThreatFox indexe les IPs avec port ("1.2.3.4:4444") et sans port.
        // On essaie d'abord l'IOC tel quel, puis sans port.
        let entry = self.lookup(ip).or_else(|| {
            // Chercher "1.2.3.4" si on a reçu "1.2.3.4:4444".
            ip.rfind(':').and_then(|i| self.lookup(&ip[..i]))
        });
        entry
            .filter(|e| e.ioc_type.contains("ip") || e.ioc_type.contains("host"))
            .map(|e| IocMatch {
                ioc: ip.to_string(),
                kind: IocKind::Ip,
                source: IocSource::Threatfox,
                threat: Some(e.malware.clone()),
                confidence: e.confidence,
            })
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

// ──────────────────────────────────────────────────────────────
// Analyse CSV
// ──────────────────────────────────────────────────────────────

/// Analyse une ligne CSV ThreatFox et renvoie `(ioc_normalisé, TfEntry)`.
fn parse_line(line: &str) -> Option<(String, TfEntry)> {
    let fields = split_csv(line);
    // Format long (≥10 colonnes, export complet) :
    //   first_seen_utc[0], ioc_id[1], ioc_value[2], ioc_type[3], threat_type[4],
    //   fk_malware[5], malware_alias[6], malware_printable[7], last_seen_utc[8],
    //   confidence_level[9], …
    // Format court (3+ colonnes) : ioc_value, ioc_type, malware
    let (ioc_raw, ioc_type_raw, malware_raw, confidence_raw) = if fields.len() >= 10 {
        // Format complet ThreatFox (export réel)
        (
            fields[2].trim_matches('"'), // ioc_value
            fields[3].trim_matches('"'), // ioc_type
            fields[7].trim_matches('"'), // malware_printable
            fields[9].trim_matches('"'), // confidence_level
        )
    } else if fields.len() >= 3 {
        // Format simplifié (tests ou export réduit)
        (
            fields[0].trim_matches('"'),
            fields[1].trim_matches('"'),
            fields[2].trim_matches('"'),
            fields.get(3).map(|s| s.trim_matches('"')).unwrap_or("50"),
        )
    } else {
        return None;
    };

    let ioc = ioc_raw.trim().to_ascii_lowercase();
    if ioc.is_empty() {
        return None;
    }

    let confidence = confidence_raw.trim().parse::<u8>().unwrap_or(50).min(100);

    Some((
        ioc,
        TfEntry {
            malware: malware_raw.trim().to_string(),
            ioc_type: ioc_type_raw.trim().to_ascii_lowercase(),
            confidence,
        },
    ))
}

/// Divise une ligne CSV en tenant compte des guillemets doubles.
fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    fields.push(current);
    fields
}

// ──────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Fixture calquée sur l'export réel ThreatFox (format en vigueur depuis 2026-10).
    // Colonnes : first_seen_utc[0], ioc_id[1], ioc_value[2], ioc_type[3], threat_type[4],
    //            fk_malware[5], malware_alias[6], malware_printable[7], last_seen_utc[8],
    //            confidence_level[9], is_compromised[10], reference[11], reporter[12],
    //            reward[13], tags[14]
    const CSV_FULL: &str = r#"
# ThreatFox IOC Database
first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type,fk_malware,malware_alias,malware_printable,last_seen_utc,confidence_level,is_compromised,reference,reporter,reward,tags
"2026-01-01 00:00:00","1964001","1.2.3.4:4444","ip:port","botnet_cc","win.cobalt_strike","CobaltStrike","Cobalt Strike","2026-01-02 00:00:00","90","0","","user1","0",""
"2026-01-02 00:00:00","1964002","evil-c2.example.com","domain","botnet_cc","win.emotet","Emotet","Emotet","2026-01-03 00:00:00","85","0","","user2","0",""
"2026-01-03 00:00:00","1964003","https://drop.evil/agent.exe","url","payload_delivery","win.redlinestealer","RedLine","RedLine Stealer","2026-01-04 00:00:00","75","0","","user3","0",""
"#;

    #[test]
    fn charge_csv_complet() {
        let mut feed = ThreatFoxFeed::new();
        let n = feed.load_csv(CSV_FULL);
        assert_eq!(n, 3, "3 IOC attendus");
    }

    #[test]
    fn detection_ip_avec_port() {
        let mut feed = ThreatFoxFeed::new();
        feed.load_csv(CSV_FULL);
        let m = feed.check_ip("1.2.3.4:4444").unwrap();
        assert_eq!(m.kind, IocKind::Ip);
        assert_eq!(m.threat.as_deref(), Some("Cobalt Strike"));
        assert_eq!(m.confidence, 90);
    }

    #[test]
    fn detection_domaine() {
        let mut feed = ThreatFoxFeed::new();
        feed.load_csv(CSV_FULL);
        let m = feed.check_domain("evil-c2.example.com").unwrap();
        assert_eq!(m.kind, IocKind::Domain);
        assert_eq!(m.threat.as_deref(), Some("Emotet"));
    }

    #[test]
    fn detection_url() {
        let mut feed = ThreatFoxFeed::new();
        feed.load_csv(CSV_FULL);
        let m = feed.check_url("https://drop.evil/agent.exe").unwrap();
        assert_eq!(m.kind, IocKind::Url);
        assert_eq!(m.threat.as_deref(), Some("RedLine Stealer"));
    }

    #[test]
    fn inconnu_renvoie_none() {
        let mut feed = ThreatFoxFeed::new();
        feed.load_csv(CSV_FULL);
        assert!(feed.check_ip("9.9.9.9").is_none());
        assert!(feed.check_domain("clean.example.com").is_none());
    }

    #[test]
    fn format_court_3_colonnes() {
        let csv = "\"1.2.3.4:9090\",\"ip:port\",\"Cobalt Strike\"\n";
        let mut feed = ThreatFoxFeed::new();
        let n = feed.load_csv(csv);
        assert_eq!(n, 1);
        assert!(feed.check_ip("1.2.3.4:9090").is_some());
    }

    #[test]
    fn ligne_commentee_ignoree() {
        let mut feed = ThreatFoxFeed::new();
        let n = feed.load_csv("# ceci est un commentaire\n\n");
        assert_eq!(n, 0);
    }
}
