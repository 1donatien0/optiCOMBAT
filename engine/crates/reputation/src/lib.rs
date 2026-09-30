//! reputation — réputation cloud + listes blanche/noire (feuille de route §9, §12).
//!
//! Décision par **hash SHA-256** : une whitelist (binaires de confiance, ex.
//! signés OS) **supprime** les faux positifs, une blacklist (hash connus
//! malveillants) tranche directement. Une source de réputation **cloud** est
//! abstraite derrière un trait : implémentation locale hors-ligne, et soumission
//! de hash **anonyme avec consentement** (RGPD : aucun contenu, seulement le
//! condensé, et seulement si l'utilisateur a opté).

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Réputation d'un condensé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reputation {
    /// Connu de confiance → supprime les détections (faux positif évité).
    Whitelisted,
    /// Connu malveillant → verdict décisif.
    Blacklisted(String),
    /// Inconnu → laisser le pipeline décider.
    Unknown,
}

/// Source de réputation (locale, cloud…).
pub trait ReputationSource: Send + Sync {
    fn lookup(&self, sha256_hex: &str) -> Reputation;
}

/// Base locale : whitelist + blacklist en mémoire.
pub struct LocalReputationDb {
    whitelist: HashSet<String>,
    blacklist: HashMap<String, String>, // hash → nom de menace
}

impl LocalReputationDb {
    pub fn new() -> Self {
        Self {
            whitelist: HashSet::new(),
            blacklist: HashMap::new(),
        }
    }

    /// Base de démonstration : EICAR en blacklist (hash réel).
    pub fn with_demo_seed() -> Self {
        let mut db = Self::new();
        db.add_blacklist(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "EICAR-Test-Signature",
        );
        db
    }

    pub fn add_whitelist(&mut self, sha256_hex: &str) {
        self.whitelist.insert(sha256_hex.to_ascii_lowercase());
    }

    pub fn add_blacklist(&mut self, sha256_hex: &str, name: &str) {
        self.blacklist
            .insert(sha256_hex.to_ascii_lowercase(), name.to_string());
    }

    pub fn whitelist_len(&self) -> usize {
        self.whitelist.len()
    }
    pub fn blacklist_len(&self) -> usize {
        self.blacklist.len()
    }
}

impl Default for LocalReputationDb {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationSource for LocalReputationDb {
    fn lookup(&self, sha256_hex: &str) -> Reputation {
        let h = sha256_hex.to_ascii_lowercase();
        if let Some(name) = self.blacklist.get(&h) {
            return Reputation::Blacklisted(name.clone());
        }
        if self.whitelist.contains(&h) {
            return Reputation::Whitelisted;
        }
        Reputation::Unknown
    }
}

/// Source cloud (best-effort). Hors-ligne par défaut : renvoie Unknown.
/// La soumission de hash est conditionnée au **consentement** explicite.
pub struct CloudReputation {
    endpoint: Option<String>,
    consent_to_share: bool,
}

impl CloudReputation {
    pub fn offline() -> Self {
        Self {
            endpoint: None,
            consent_to_share: false,
        }
    }

    pub fn new(endpoint: impl Into<String>, consent_to_share: bool) -> Self {
        Self {
            endpoint: Some(endpoint.into()),
            consent_to_share,
        }
    }

    /// Soumet un hash anonyme pour la détection collective — seulement si
    /// l'utilisateur a consenti ET qu'un endpoint est configuré.
    /// Renvoie true si la soumission a (conceptuellement) eu lieu.
    pub fn submit_hash(&self, _sha256_hex: &str) -> bool {
        self.consent_to_share && self.endpoint.is_some()
    }
}

impl ReputationSource for CloudReputation {
    fn lookup(&self, sha256_hex: &str) -> Reputation {
        let Some(endpoint) = self.endpoint.as_ref() else {
            return Reputation::Unknown;
        };
        lookup_http(endpoint, sha256_hex)
    }
}

/// Requête HTTP GET vers un endpoint de réputation (JSON `{ "status": "malicious"|"clean", "name": "..." }`).
#[cfg(feature = "http")]
fn lookup_http(endpoint: &str, sha256_hex: &str) -> Reputation {
    let url = format!("{endpoint}/v1/hash/{sha256_hex}");
    match ureq::get(&url).timeout(std::time::Duration::from_secs(5)).call() {
        Ok(resp) => {
            if let Ok(body) = resp.into_string() {
                if body.contains("\"malicious\"") || body.contains("\"blacklisted\"") {
                    return Reputation::Blacklisted("Cloud-Reputation".into());
                }
                if body.contains("\"clean\"") || body.contains("\"whitelisted\"") {
                    return Reputation::Whitelisted;
                }
            }
            Reputation::Unknown
        }
        Err(_) => Reputation::Unknown,
    }
}

#[cfg(not(feature = "http"))]
fn lookup_http(_endpoint: &str, _sha256_hex: &str) -> Reputation {
    Reputation::Unknown
}

/// Moteur de réputation : combine plusieurs sources (blacklist prioritaire).
pub struct ReputationEngine {
    sources: Vec<Box<dyn ReputationSource>>,
}

impl ReputationEngine {
    pub fn new(sources: Vec<Box<dyn ReputationSource>>) -> Self {
        Self { sources }
    }

    /// Construit un moteur par défaut : base locale (graine démo) + cloud offline.
    pub fn default_offline() -> Self {
        Self::new(vec![
            Box::new(LocalReputationDb::with_demo_seed()),
            Box::new(CloudReputation::offline()),
        ])
    }

    /// Construit un moteur à partir de l'environnement :
    /// `OPTICOMBAT_REPUTATION_URL` + `OPTICOMBAT_REPUTATION_CONSENT=1|true`.
    pub fn from_env() -> Self {
        let mut sources: Vec<Box<dyn ReputationSource>> =
            vec![Box::new(LocalReputationDb::with_demo_seed())];
        if let Ok(endpoint) = std::env::var("OPTICOMBAT_REPUTATION_URL") {
            if !endpoint.trim().is_empty() {
                let consent = std::env::var("OPTICOMBAT_REPUTATION_CONSENT")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                sources.push(Box::new(CloudReputation::new(endpoint, consent)));
                return Self::new(sources);
            }
        }
        sources.push(Box::new(CloudReputation::offline()));
        Self::new(sources)
    }

    /// Calcule le SHA-256 hex d'un buffer.
    pub fn sha256_hex(data: &[u8]) -> String {
        let digest = Sha256::digest(data);
        let mut s = String::with_capacity(64);
        for b in digest {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Réputation d'un buffer : blacklist > whitelist > unknown.
    pub fn evaluate(&self, data: &[u8]) -> Reputation {
        let h = Self::sha256_hex(data);
        let mut whitelisted = false;
        for src in &self.sources {
            match src.lookup(&h) {
                Reputation::Blacklisted(name) => return Reputation::Blacklisted(name),
                Reputation::Whitelisted => whitelisted = true,
                Reputation::Unknown => {}
            }
        }
        if whitelisted {
            Reputation::Whitelisted
        } else {
            Reputation::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EICAR: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    #[test]
    fn eicar_blackliste() {
        let eng = ReputationEngine::default_offline();
        match eng.evaluate(EICAR) {
            Reputation::Blacklisted(name) => assert_eq!(name, "EICAR-Test-Signature"),
            other => panic!("attendu blacklisté, obtenu {other:?}"),
        }
    }

    #[test]
    fn whitelist_supprime() {
        let mut db = LocalReputationDb::new();
        let data = b"binaire signe de confiance";
        db.add_whitelist(&ReputationEngine::sha256_hex(data));
        let eng = ReputationEngine::new(vec![Box::new(db)]);
        assert_eq!(eng.evaluate(data), Reputation::Whitelisted);
    }

    #[test]
    fn inconnu_par_defaut() {
        let eng = ReputationEngine::default_offline();
        assert_eq!(
            eng.evaluate(b"contenu quelconque jamais vu"),
            Reputation::Unknown
        );
    }

    #[test]
    fn consentement_requis_pour_soumission() {
        assert!(!CloudReputation::offline().submit_hash("abcd"));
        assert!(!CloudReputation::new("https://intel.example", false).submit_hash("abcd"));
        assert!(CloudReputation::new("https://intel.example", true).submit_hash("abcd"));
    }
}
