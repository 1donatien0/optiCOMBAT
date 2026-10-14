//! clamav — wrapper de moteur de signatures (feuille de route §2).
//!
//! Cible : FFI vers `libclamav` (cl_scanfile) OU client TCP `clamd`, exactement
//! comme le `CompositeClamAvBackend` C# actuel. Ici : implémentation de
//! référence (stub) qui compile sans dépendance native, à brancher sur la FFI.
//!
//! TODO(FFI): lier libclamav via un build.rs + bindgen, ou réutiliser le
//! `ClamdClient` existant en parlant le protocole clamd (INSTREAM/SCAN).

pub mod clamd;
pub use clamd::ClamdClient;

use engine_core::{Detection, EngineError, EngineResult, Severity, SignatureEngine, Verdict};
use std::path::Path;

/// Backend ClamAV. `available` reflète la présence de la base de signatures.
pub struct ClamAvEngine {
    available: bool,
}

impl ClamAvEngine {
    pub fn new() -> Self {
        Self { available: true }
    }
    pub fn with_availability(available: bool) -> Self {
        Self { available }
    }
}

impl Default for ClamAvEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureEngine for ClamAvEngine {
    fn name(&self) -> &str {
        "clamav"
    }

    fn scan_path(&self, path: &Path) -> Result<EngineResult, EngineError> {
        if !self.available {
            return Err(EngineError::Unavailable(
                "base de signatures absente".into(),
            ));
        }
        let bytes = std::fs::read(path)?;
        // Détection EICAR : permet un test d'intégration réel de bout en bout
        // sans échantillon malveillant (parité avec les tests YARA existants).
        const EICAR: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR";
        if bytes.windows(EICAR.len()).any(|w| w == EICAR) {
            return Ok(EngineResult {
                engine: "clamav".into(),
                verdict: Verdict::Malicious,
                detections: vec![Detection {
                    engine: "clamav".into(),
                    name: "Eicar-Test-Signature".into(),
                    score: 100,
                    severity: Severity::Major,
                    explanation: "Signature de test EICAR détectée".into(),
                }],
                elapsed_ms: 0,
            });
        }
        Ok(EngineResult::clean("clamav"))
    }
}

/// Backend composite : privilégie le démon clamd (signatures à jour) et
/// bascule sur le moteur de secours hors-ligne (EICAR) s'il est injoignable.
/// Reproduit l'intention de `CompositeClamAvBackend` (C#).
pub struct CompositeClamAvBackend {
    clamd: ClamdClient,
    fallback: ClamAvEngine,
    prefer_clamd: bool,
}

impl CompositeClamAvBackend {
    /// Construit le backend ; sonde clamd une fois pour décider de la voie.
    pub fn new() -> Self {
        let clamd = ClamdClient::local();
        let prefer_clamd = clamd.ping();
        Self {
            clamd,
            fallback: ClamAvEngine::new(),
            prefer_clamd,
        }
    }

    pub fn with_clamd(addr: impl Into<String>) -> Self {
        let clamd = ClamdClient::new(addr);
        let prefer_clamd = clamd.ping();
        Self {
            clamd,
            fallback: ClamAvEngine::new(),
            prefer_clamd,
        }
    }

    /// Vrai si un démon clamd a répondu et sera utilisé en priorité.
    pub fn clamd_available(&self) -> bool {
        self.prefer_clamd
    }
}

impl Default for CompositeClamAvBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureEngine for CompositeClamAvBackend {
    fn name(&self) -> &str {
        "clamav"
    }

    fn scan_path(&self, path: &std::path::Path) -> Result<EngineResult, EngineError> {
        if self.prefer_clamd {
            let data = std::fs::read(path)?;
            match self.clamd.scan_bytes(&data) {
                Ok(r) => return Ok(r),
                Err(_) => { /* démon tombé en cours de route → repli */ }
            }
        }
        self.fallback.scan_path(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detecte_eicar() {
        let mut f = tempfile_with(br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD");
        let r = ClamAvEngine::new().scan_path(f.path()).unwrap();
        assert_eq!(r.verdict, Verdict::Malicious);
        f.cleanup();
    }

    #[test]
    fn fichier_propre() {
        let mut f = tempfile_with(b"contenu benin");
        let r = ClamAvEngine::new().scan_path(f.path()).unwrap();
        assert_eq!(r.verdict, Verdict::Clean);
        f.cleanup();
    }

    // Mini-helper de fichier temporaire (évite une dépendance externe).
    struct Tmp {
        p: std::path::PathBuf,
    }
    impl Tmp {
        fn path(&self) -> &Path {
            &self.p
        }
        fn cleanup(&mut self) {
            let _ = std::fs::remove_file(&self.p);
        }
    }
    fn tempfile_with(data: &[u8]) -> Tmp {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let uid = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("oc_clamav_{}_{}.bin", std::process::id(), uid));
        let mut fh = std::fs::File::create(&p).unwrap();
        fh.write_all(data).unwrap();
        Tmp { p }
    }
}
