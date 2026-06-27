//! quarantine — mise en quarantaine sûre (feuille de route §8).
//!
//! Pipeline : hash SHA-256 → chiffrement AES-256-GCM (nonce aléatoire par
//! fichier, tag d'authentification) → stockage. Ne jamais supprimer
//! immédiatement : restauration possible sur faux positif, vérifiée par le
//! tag GCM ET par recomputation du SHA-256.
//!
//! Parité avec le `QuarantineManager` C# (AES-GCM 256). La clé maîtresse est
//! ici fournie par l'appelant ; côté Windows elle est enveloppée par DPAPI
//! (portée utilisateur) — étape plateforme hors du cœur portable.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub sha256_hex: String,
    pub size: u64,
    pub stored_at: PathBuf,
}

#[derive(Debug)]
pub enum QuarantineError {
    Io(std::io::Error),
}
impl std::fmt::Display for QuarantineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuarantineError::Io(e) => write!(f, "io: {e}"),
        }
    }
}
impl std::error::Error for QuarantineError {}
impl From<std::io::Error> for QuarantineError {
    fn from(e: std::io::Error) -> Self {
        QuarantineError::Io(e)
    }
}

pub struct Quarantine {
    store_dir: PathBuf,
    key: [u8; 32],
}

impl Quarantine {
    pub fn new(store_dir: impl Into<PathBuf>, key: [u8; 32]) -> Self {
        Self {
            store_dir: store_dir.into(),
            key,
        }
    }

    /// Met un fichier en quarantaine et renvoie l'entrée (métadonnées).
    pub fn quarantine_file(&self, path: &Path) -> Result<QuarantineEntry, QuarantineError> {
        let data = std::fs::read(path)?;
        let digest = sha256_hex(&data); // hash AVANT scellement
        let sealed = seal(&data, &self.key); // AES-256-GCM, nonce aléatoire
        std::fs::create_dir_all(&self.store_dir)?;
        let id = format!("{}-{}", &digest[..16], data.len());
        let stored_at = self.store_dir.join(format!("{id}.qbin"));
        std::fs::write(&stored_at, &sealed)?;
        Ok(QuarantineEntry {
            id,
            original_path: path.to_path_buf(),
            sha256_hex: digest,
            size: data.len() as u64,
            stored_at,
        })
    }

    /// Restaure une entrée vers une destination (faux positif).
    pub fn restore(&self, entry: &QuarantineEntry, dest: &Path) -> Result<(), QuarantineError> {
        let sealed = std::fs::read(&entry.stored_at)?;
        let data = unseal(&sealed, &self.key).ok_or_else(|| {
            QuarantineError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "déchiffrement AES-GCM échoué (tag invalide / altération)",
            ))
        })?;
        // Défense en profondeur : le hash doit aussi correspondre.
        if sha256_hex(&data) != entry.sha256_hex {
            return Err(QuarantineError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "intégrité quarantaine compromise",
            )));
        }
        std::fs::write(dest, data)?;
        Ok(())
    }
}

/// Chiffre `data` en AES-256-GCM. Format : `nonce(12) || ciphertext+tag`.
fn seal(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 12 octets aléatoires
    let ct = cipher.encrypt(&nonce, data).expect("chiffrement AES-GCM");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    out
}

/// Déchiffre `nonce(12) || ciphertext+tag`. None si tag invalide (altération)
/// ou format trop court.
fn unseal(blob: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    if blob.len() < 12 {
        return None;
    }
    let (nonce_bytes, ct) = blob.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ct).ok()
}

/// SHA-256 — implémentation autonome (sera remplacée par la crate `sha2`).
pub fn sha256_hex(data: &[u8]) -> String {
    let h = sha256(data);
    let mut s = String::with_capacity(64);
    for b in h {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn sha256(message: &[u8]) -> [u8; 32] {
    // FIPS 180-4 — implémentation compacte et correcte.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = message.to_vec();
    let bitlen = (message.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_vecteur_connu() {
        // SHA-256("abc")
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn alteration_detectee() {
        let dir = std::env::temp_dir().join(format!("oc_qalt_{}", std::process::id()));
        let src = dir.join("s.bin");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&src, b"charge utile").unwrap();
        let q = Quarantine::new(dir.join("store"), [3u8; 32]);
        let entry = q.quarantine_file(&src).unwrap();
        // Altère un octet du blob chiffré.
        let mut blob = std::fs::read(&entry.stored_at).unwrap();
        let n = blob.len();
        blob[n - 1] ^= 0xFF;
        std::fs::write(&entry.stored_at, &blob).unwrap();
        // La restauration doit échouer (tag GCM invalide).
        assert!(q.restore(&entry, &dir.join("out.bin")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cycle_quarantaine_restauration() {
        let dir = std::env::temp_dir().join(format!("oc_q_{}", std::process::id()));
        let src = dir.join("sample.bin");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&src, b"contenu malveillant simule").unwrap();
        let q = Quarantine::new(dir.join("store"), [7u8; 32]);
        let entry = q.quarantine_file(&src).unwrap();
        let restored = dir.join("restored.bin");
        q.restore(&entry, &restored).unwrap();
        assert_eq!(
            std::fs::read(&restored).unwrap(),
            b"contenu malveillant simule"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
