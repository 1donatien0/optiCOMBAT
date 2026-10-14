//! platform — couche d'abstraction plateforme (clé maîtresse, mémoire process).
//!
//! Le cœur portable ne connaît pas Windows. Cette crate expose des **traits**
//! que la plateforme implémente : protection de la clé de quarantaine et
//! énumération des régions mémoire d'un processus. Une implémentation
//! **portable et testée** est fournie pour le développement et les tests ; les
//! implémentations Windows (DPAPI, `ReadProcessMemory`) se branchent derrière
//! les mêmes traits sans toucher au cœur.

use sha2::{Digest, Sha256};

/// Fournit la clé maîtresse 256 bits utilisée par la quarantaine.
///
/// Sous Windows, l'implémentation enveloppe/désenveloppe la clé via **DPAPI**
/// (`CryptProtectData`, portée utilisateur) — déjà disponible côté C#
/// (`ProtectedData`) dans optiCombat. Ici, `LocalKeyProvider` dérive une clé
/// déterministe d'un secret, suffisant pour le dev et les tests.
pub trait KeyProvider: Send + Sync {
    /// Renvoie la clé maîtresse 32 octets.
    fn master_key(&self) -> [u8; 32];
}

/// Dérive une clé d'un secret par SHA-256 (dev / non-Windows).
pub struct LocalKeyProvider {
    secret: Vec<u8>,
}

impl LocalKeyProvider {
    pub fn from_secret(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
        }
    }

    /// Lit le secret depuis la variable d'environnement `OPTICOMBAT_KEY`,
    /// avec un repli déterministe si absente (dev uniquement).
    pub fn from_env() -> Self {
        let secret =
            std::env::var("OPTICOMBAT_KEY").unwrap_or_else(|_| "opticombat-dev-key".to_string());
        Self::from_secret(secret.into_bytes())
    }
}

impl KeyProvider for LocalKeyProvider {
    fn master_key(&self) -> [u8; 32] {
        let digest = Sha256::digest(&self.secret);
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        key
    }
}

/// Renvoie le fournisseur de clé par défaut de la plateforme.
pub fn default_key_provider() -> Box<dyn KeyProvider> {
    #[cfg(all(windows, feature = "windows-platform"))]
    {
        if let Some(provider) = try_dpapi_key_provider() {
            return provider;
        }
    }
    Box::new(LocalKeyProvider::from_env())
}

#[cfg(all(windows, feature = "windows-platform"))]
fn try_dpapi_key_provider() -> Option<Box<dyn KeyProvider>> {
    use std::path::PathBuf;
    let path = std::env::var("LOCALAPPDATA")
        .ok()
        .map(|p| PathBuf::from(p).join("optiCombat").join("master_key.dpapi"))?;
    if path.exists() {
        let wrapped = std::fs::read(&path).ok()?;
        return Some(Box::new(windows_impl::DpapiKeyProvider::from_wrapped(wrapped)));
    }
    // Première utilisation : générer une clé aléatoire et l'envelopper.
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).ok()?;
    let wrapped = windows_impl::DpapiKeyProvider::wrap(&key).ok()?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, &wrapped);
    Some(Box::new(windows_impl::DpapiKeyProvider::from_wrapped(
        wrapped,
    )))
}

/// Région mémoire possédée (copie d'octets + étiquette).
#[derive(Debug, Clone)]
pub struct OwnedRegion {
    pub label: String,
    pub bytes: Vec<u8>,
}

/// Énumère les régions mémoire à analyser pour un processus.
///
/// L'implémentation Windows lit la mémoire via `VirtualQueryEx` +
/// `ReadProcessMemory` ; le cœur ne consomme que ce trait.
pub trait MemoryRegionProvider {
    fn regions(&self) -> Vec<OwnedRegion>;
}

/// Fournisseur portable : régions fournies en dur (tests, dumps importés).
pub struct StaticRegions {
    regions: Vec<OwnedRegion>,
}

impl StaticRegions {
    pub fn new(regions: Vec<OwnedRegion>) -> Self {
        Self { regions }
    }
    pub fn single(label: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            regions: vec![OwnedRegion {
                label: label.into(),
                bytes,
            }],
        }
    }
}

impl MemoryRegionProvider for StaticRegions {
    fn regions(&self) -> Vec<OwnedRegion> {
        self.regions.clone()
    }
}

/// Implémentations natives Windows (DPAPI, ReadProcessMemory), activées par la
/// feature `windows-platform` sous Windows uniquement.
#[cfg(all(windows, feature = "windows-platform"))]
pub mod windows_impl;
#[cfg(all(windows, feature = "windows-platform"))]
pub use windows_impl::{DpapiKeyProvider, WindowsMemoryRegionProvider};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cle_deterministe_et_distincte() {
        let a = LocalKeyProvider::from_secret(*b"secret-A").master_key();
        let a2 = LocalKeyProvider::from_secret(*b"secret-A").master_key();
        let b = LocalKeyProvider::from_secret(*b"secret-B").master_key();
        assert_eq!(a, a2, "même secret → même clé");
        assert_ne!(a, b, "secrets différents → clés différentes");
    }

    #[test]
    fn regions_statiques() {
        let p = StaticRegions::single("pid:1:0x1000", vec![1, 2, 3]);
        let r = p.regions();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].bytes, vec![1, 2, 3]);
    }
}
