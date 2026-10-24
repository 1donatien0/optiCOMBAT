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
///
/// Seuls les endpoints `https://` sont acceptés : une réponse « clean » supprime
/// les détections, elle ne doit donc jamais transiter en clair (MITM).
#[cfg(feature = "http")]
fn lookup_http(endpoint: &str, sha256_hex: &str) -> Reputation {
    if !endpoint.starts_with("https://") {
        return Reputation::Unknown;
    }
    let url = format!("{}/v1/hash/{sha256_hex}", endpoint.trim_end_matches('/'));
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(5)))
        .build()
        .into();
    match agent.get(&url).call() {
        Ok(mut resp) => match resp
            .body_mut()
            .with_config()
            .limit(64 * 1024)
            .read_to_string()
        {
            Ok(body) => classify_cloud_body(&body),
            Err(_) => Reputation::Unknown,
        },
        Err(_) => Reputation::Unknown,
    }
}

/// Interprète la réponse du service cloud. Une réponse ambiguë (à la fois
/// malveillante et propre) est traitée comme malveillante.
#[cfg_attr(not(feature = "http"), allow(dead_code))]
fn classify_cloud_body(body: &str) -> Reputation {
    if body.contains("\"malicious\"") || body.contains("\"blacklisted\"") {
        return Reputation::Blacklisted("Cloud-Reputation".into());
    }
    if body.contains("\"clean\"") || body.contains("\"whitelisted\"") {
        return Reputation::Whitelisted;
    }
    Reputation::Unknown
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
    fn reponse_cloud_ambigue_reste_malveillante() {
        assert!(matches!(
            classify_cloud_body(r#"{"status":"malicious","alt":"clean"}"#),
            Reputation::Blacklisted(_)
        ));
        assert_eq!(classify_cloud_body("{}"), Reputation::Unknown);
    }

    #[test]
    fn endpoint_non_https_ignore() {
        let c = CloudReputation::new("http://intel.example", true);
        assert_eq!(c.lookup("abcd"), Reputation::Unknown);
    }

    #[test]
    fn consentement_requis_pour_soumission() {
        assert!(!CloudReputation::offline().submit_hash("abcd"));
        assert!(!CloudReputation::new("https://intel.example", false).submit_hash("abcd"));
        assert!(CloudReputation::new("https://intel.example", true).submit_hash("abcd"));
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// MalwareBazaarDb — base de hachages depuis les exports MalwareBazaar (abuse.ch)
// ══════════════════════════════════════════════════════════════════════════════

/// Base de hachages SHA-256 chargée depuis un export MalwareBazaar.
///
/// MalwareBazaar (abuse.ch) fournit un export CSV complet téléchargeable.
/// Ce type charge ce CSV et expose une [`ReputationSource`] pour le pipeline
/// de détection.
///
/// **Format CSV attendu** (en-tête ou sans en-tête) :
/// ```text
/// first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,
/// file_type_mime,file_type,signature,clamav,tags,...
/// ```
///
/// Seules les colonnes `sha256_hash` (index 1) et `signature` (index 8,
/// famille abuse.ch : Emotet, Mirai, …) sont utilisées.
///
/// Le fichier est téléchargé par la couche C# et stocké dans
/// `%LocalAppData%\optiCombat\threat_intel\malwarebazaar.csv`.
pub struct MalwareBazaarDb {
    /// SHA-256 (minuscules) → famille de malware.
    hashes: std::collections::HashMap<String, String>,
}

impl MalwareBazaarDb {
    pub fn new() -> Self {
        Self {
            hashes: std::collections::HashMap::new(),
        }
    }

    /// Charge depuis le texte du CSV MalwareBazaar.
    ///
    /// Renvoie le nombre de hachages ajoutés.
    pub fn load_csv(&mut self, csv: &str) -> usize {
        let mut count = 0usize;
        for line in csv.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Ignore la ligne d'en-tête.
            if line.starts_with("first_seen") || line.starts_with("\"first_seen") {
                continue;
            }
            if let Some((sha256, name)) = parse_bazaar_line(line) {
                self.hashes.insert(sha256, name);
                count += 1;
            }
        }
        count
    }

    /// Charge depuis un fichier texte simple : un SHA-256 par ligne
    /// (format alternatif léger, sans métadonnées).
    pub fn load_hash_list(&mut self, text: &str, default_name: &str) -> usize {
        let mut count = 0usize;
        for line in text.lines() {
            let hash = line.trim().to_ascii_lowercase();
            if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                self.hashes
                    .entry(hash)
                    .or_insert_with(|| default_name.to_string());
                count += 1;
            }
        }
        count
    }

    pub fn hash_count(&self) -> usize {
        self.hashes.len()
    }
}

impl Default for MalwareBazaarDb {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationSource for MalwareBazaarDb {
    fn lookup(&self, sha256_hex: &str) -> Reputation {
        let h = sha256_hex.to_ascii_lowercase();
        match self.hashes.get(&h) {
            Some(name) => Reputation::Blacklisted(format!("MalwareBazaar:{name}")),
            None => Reputation::Unknown,
        }
    }
}

/// Analyse une ligne CSV MalwareBazaar.
///
/// Format : `first_seen,sha256,md5,sha1,reporter,file_name,mime,type,country,signature,tags,...`
fn parse_bazaar_line(line: &str) -> Option<(String, String)> {
    // Divise en colonnes (guillemets optionnels).
    let fields = split_csv_line(line);
    let sha256 = fields.get(1)?.trim().trim_matches('"').to_ascii_lowercase();
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    // Col 8 = signature (famille abuse.ch : Emotet, Mirai, …)
    // Col 9 = clamav   (souvent "n/a" ou vide — non utilisé)
    let name = fields
        .get(8)
        .map(|s| s.trim().trim_matches('"'))
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("n/a"))
        .unwrap_or("Malware")
        .to_string();
    Some((sha256, name))
}

/// Divise une ligne CSV simple (guillemets doubles, séparateur virgule).
fn split_csv_line(line: &str) -> Vec<String> {
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

#[cfg(test)]
mod bazaar_tests {
    use super::*;

    // Fixture calquée sur le format réel MalwareBazaar (sans origin_country) :
    // first_seen_utc[0], sha256_hash[1], md5_hash[2], sha1_hash[3], reporter[4],
    // file_name[5], file_type_mime[6], file_type[7], signature[8], clamav[9], tags[10]
    const CSV: &str = r#"first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_mime,file_type,signature,clamav,tags
2026-01-01 00:00:00,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,md5a,sha1a,user1,malware.exe,application/x-dosexec,exe,Emotet,Win.Trojan.Emotet,trojan
2026-01-02 00:00:00,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,md5b,sha1b,user2,rat.dll,application/x-dosexec,dll,,n/a,banker
"#;

    #[test]
    fn charge_csv() {
        let mut db = MalwareBazaarDb::new();
        let n = db.load_csv(CSV);
        assert_eq!(n, 2);
        assert_eq!(db.hash_count(), 2);
    }

    #[test]
    fn detection_hash_connu() {
        let mut db = MalwareBazaarDb::new();
        db.load_csv(CSV);
        match db.lookup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
            Reputation::Blacklisted(name) => assert!(name.contains("Emotet")),
            other => panic!("attendu blacklisté, obtenu {other:?}"),
        }
    }

    #[test]
    fn hash_inconnu_renvoie_unknown() {
        let mut db = MalwareBazaarDb::new();
        db.load_csv(CSV);
        assert_eq!(
            db.lookup("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            Reputation::Unknown
        );
    }

    #[test]
    fn signature_vide_utilise_malware_par_defaut() {
        let mut db = MalwareBazaarDb::new();
        db.load_csv(CSV);
        // La ligne "bbbb..." n'a pas de signature → doit avoir "Malware".
        match db.lookup("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
            Reputation::Blacklisted(name) => assert!(name.contains("Malware")),
            other => panic!("attendu blacklisté, obtenu {other:?}"),
        }
    }

    #[test]
    fn charge_hash_list_simple() {
        let mut db = MalwareBazaarDb::new();
        let list = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
                    # commentaire ignoré\n\
                    bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
        let n = db.load_hash_list(list, "TestFamily");
        assert_eq!(n, 2);
        assert!(matches!(
            db.lookup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Reputation::Blacklisted(_)
        ));
    }

    #[test]
    fn hash_malformed_ignore() {
        let mut db = MalwareBazaarDb::new();
        let n = db.load_hash_list("not-a-hash\n   \n", "X");
        assert_eq!(n, 0);
    }

    #[test]
    fn insensible_a_la_casse() {
        let mut db = MalwareBazaarDb::new();
        db.load_hash_list(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "X",
        );
        // Lookup en minuscules doit fonctionner.
        assert!(matches!(
            db.lookup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Reputation::Blacklisted(_)
        ));
    }
}
