//! updater — vérification des mises à jour signées (feuille de route §12).
//!
//! Toute mise à jour (signatures ClamAV, règles YARA, heuristiques, whitelist,
//! blacklist, modèle ML) est décrite par un **manifeste** signé en **ed25519**.
//! Avant installation, on vérifie : (1) la signature du manifeste avec la clé
//! publique embarquée, puis (2) le **SHA-256 de chaque charge utile** contre la
//! valeur du manifeste. Aucun octet n'est installé sans cette double garantie.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Catégorie de mise à jour (alignée sur la feuille de route §12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Category {
    ClamavSignatures,
    YaraRules,
    Heuristics,
    Whitelist,
    Blacklist,
    MlModel,
    Other(String),
}

impl Category {
    fn parse(s: &str) -> Self {
        match s {
            "clamav" => Category::ClamavSignatures,
            "yara" => Category::YaraRules,
            "heuristics" => Category::Heuristics,
            "whitelist" => Category::Whitelist,
            "blacklist" => Category::Blacklist,
            "ml" => Category::MlModel,
            other => Category::Other(other.to_string()),
        }
    }
}

/// Entrée du manifeste : une charge utile à installer.
#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub category: Category,
    pub name: String,
    pub sha256: String,
}

/// Manifeste de mise à jour analysé.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub version: String,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UpdateError {
    BadSignature,
    BadKey,
    Malformed(String),
    HashMismatch { name: String },
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateError::BadSignature => write!(f, "signature de manifeste invalide"),
            UpdateError::BadKey => write!(f, "clé publique invalide"),
            UpdateError::Malformed(m) => write!(f, "manifeste malformé: {m}"),
            UpdateError::HashMismatch { name } => write!(f, "hash incorrect: {name}"),
        }
    }
}
impl std::error::Error for UpdateError {}

/// Calcule le SHA-256 d'un buffer en hexadécimal minuscule.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Analyse le texte d'un manifeste.
///
/// Format (une entrée par ligne) :
/// ```text
/// version: 2026.06.26
/// clamav daily.cvd <sha256hex>
/// yara ransomware.yar <sha256hex>
/// ```
pub fn parse_manifest(text: &str) -> Result<Manifest, UpdateError> {
    let mut version = String::new();
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(v) = line.strip_prefix("version:") {
            version = v.trim().to_string();
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(UpdateError::Malformed(format!("ligne invalide: {line}")));
        }
        entries.push(ManifestEntry {
            category: Category::parse(parts[0]),
            name: parts[1].to_string(),
            sha256: parts[2].to_ascii_lowercase(),
        });
    }
    if version.is_empty() {
        return Err(UpdateError::Malformed("version absente".into()));
    }
    Ok(Manifest { version, entries })
}

/// Vérificateur de mises à jour basé sur une clé publique ed25519.
pub struct UpdateVerifier {
    key: VerifyingKey,
}

impl UpdateVerifier {
    /// Construit le vérificateur depuis une clé publique ed25519 (32 octets).
    pub fn from_public_key(pubkey: &[u8; 32]) -> Result<Self, UpdateError> {
        let key = VerifyingKey::from_bytes(pubkey).map_err(|_| UpdateError::BadKey)?;
        Ok(Self { key })
    }

    /// Vérifie la signature du manifeste, puis l'analyse.
    pub fn verify_manifest(
        &self,
        manifest_text: &str,
        signature: &[u8; 64],
    ) -> Result<Manifest, UpdateError> {
        let sig = Signature::from_bytes(signature);
        self.key
            .verify(manifest_text.as_bytes(), &sig)
            .map_err(|_| UpdateError::BadSignature)?;
        parse_manifest(manifest_text)
    }

    /// Vérifie qu'une charge utile correspond à son entrée de manifeste.
    pub fn verify_payload(entry: &ManifestEntry, data: &[u8]) -> Result<(), UpdateError> {
        if sha256_hex(data) == entry.sha256 {
            Ok(())
        } else {
            Err(UpdateError::HashMismatch {
                name: entry.name.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn sample_manifest() -> String {
        let payload_clam = b"signatures clamav du jour";
        let payload_yara = b"regles yara du jour";
        format!(
            "version: 2026.06.26\nclamav daily.cvd {}\nyara ransomware.yar {}\n",
            sha256_hex(payload_clam),
            sha256_hex(payload_yara),
        )
    }

    #[test]
    fn manifeste_signe_valide() {
        let (sk, pk) = keypair();
        let text = sample_manifest();
        let sig = sk.sign(text.as_bytes()).to_bytes();
        let v = UpdateVerifier::from_public_key(&pk).unwrap();
        let m = v.verify_manifest(&text, &sig).unwrap();
        assert_eq!(m.version, "2026.06.26");
        assert_eq!(m.entries.len(), 2);
        assert_eq!(m.entries[0].category, Category::ClamavSignatures);
    }

    #[test]
    fn manifeste_altere_rejete() {
        let (sk, pk) = keypair();
        let text = sample_manifest();
        let sig = sk.sign(text.as_bytes()).to_bytes();
        let tampered = text.replace("2026.06.26", "2099.01.01");
        let v = UpdateVerifier::from_public_key(&pk).unwrap();
        assert!(matches!(
            v.verify_manifest(&tampered, &sig),
            Err(UpdateError::BadSignature)
        ));
    }

    #[test]
    fn mauvaise_cle_rejete() {
        let (sk, _) = keypair();
        let other_pk = SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        let text = sample_manifest();
        let sig = sk.sign(text.as_bytes()).to_bytes();
        let v = UpdateVerifier::from_public_key(&other_pk).unwrap();
        assert!(v.verify_manifest(&text, &sig).is_err());
    }

    #[test]
    fn charge_utile_hash_verifie() {
        let payload = b"signatures clamav du jour";
        let entry = ManifestEntry {
            category: Category::ClamavSignatures,
            name: "daily.cvd".into(),
            sha256: sha256_hex(payload),
        };
        assert!(UpdateVerifier::verify_payload(&entry, payload).is_ok());
        assert!(UpdateVerifier::verify_payload(&entry, b"charge falsifiee").is_err());
    }
}
