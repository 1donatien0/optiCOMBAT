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
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
        let bytes = std::fs::read(path)?;
        self.scan_bytes(path, &bytes)
    }

    fn scan_bytes(&self, _path: &Path, bytes: &[u8]) -> Result<EngineResult, EngineError> {
        if !self.available {
            return Err(EngineError::Unavailable(
                "base de signatures absente".into(),
            ));
        }
        // Détection EICAR : permet un test d'intégration réel de bout en bout
        // sans échantillon malveillant (parité avec les tests YARA existants).
        let eicar = eicar_prefix();
        if bytes.windows(eicar.len()).any(|w| w == eicar.as_slice()) {
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

/// Préfixe EICAR stocké masqué (XOR) : en clair, la chaîne présente dans
/// `opticombat_engine.dll` faisait détecter la DLL elle-même comme « EICAR ».
fn eicar_prefix() -> Vec<u8> {
    const MASK: u8 = 0x5A;
    const MASKED: [u8; 33] = {
        let plain = *br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR";
        let mut out = [0u8; 33];
        let mut i = 0;
        while i < plain.len() {
            out[i] = plain[i] ^ MASK;
            i += 1;
        }
        out
    };
    MASKED
        .iter()
        .map(|b| std::hint::black_box(*b) ^ MASK)
        .collect()
}

/// Backend composite : privilégie le démon clamd (signatures à jour) et
/// bascule sur le moteur de secours hors-ligne (EICAR) s'il est injoignable.
/// Reproduit l'intention de `CompositeClamAvBackend` (C#).
///
/// La disponibilité de clamd est re-sondée périodiquement : le backend vit
/// désormais aussi longtemps que la DLL (dispatcher mis en cache côté FFI), et
/// clamd met souvent plusieurs dizaines de secondes à charger ses bases.
pub struct CompositeClamAvBackend {
    clamd: ClamdClient,
    fallback: ClamAvEngine,
    probe: Mutex<ProbeState>,
}

struct ProbeState {
    available: bool,
    checked_at: Instant,
}

/// Intervalle minimal entre deux sondes clamd quand il est injoignable.
const CLAMD_REPROBE: Duration = Duration::from_secs(30);

impl CompositeClamAvBackend {
    /// Construit le backend ; sonde clamd une première fois.
    pub fn new() -> Self {
        Self::from_client(ClamdClient::local())
    }

    pub fn with_clamd(addr: impl Into<String>) -> Self {
        Self::from_client(ClamdClient::new(addr))
    }

    fn from_client(clamd: ClamdClient) -> Self {
        let available = clamd.ping();
        Self {
            clamd,
            fallback: ClamAvEngine::new(),
            probe: Mutex::new(ProbeState {
                available,
                checked_at: Instant::now(),
            }),
        }
    }

    /// Vrai si un démon clamd a répondu et sera utilisé en priorité.
    pub fn clamd_available(&self) -> bool {
        let mut st = match self.probe.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if !st.available && st.checked_at.elapsed() >= CLAMD_REPROBE {
            st.available = self.clamd.ping();
            st.checked_at = Instant::now();
        }
        st.available
    }

    fn mark_clamd_down(&self) {
        let mut st = match self.probe.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        st.available = false;
        st.checked_at = Instant::now();
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
        let data = std::fs::read(path)?;
        self.scan_bytes(path, &data)
    }

    fn scan_bytes(&self, path: &Path, data: &[u8]) -> Result<EngineResult, EngineError> {
        if self.clamd_available() {
            match self.clamd.scan_bytes(data) {
                Ok(r) => return Ok(r),
                Err(_) => self.mark_clamd_down(), // démon tombé en cours de route → repli
            }
        }
        self.fallback.scan_bytes(path, data)
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

    #[test]
    fn composite_utilise_clamd_puis_bascule_sur_le_repli() {
        // 1 PING (construction) + 1 INSTREAM, puis le démon s'arrête.
        let (addr, h) = crate::clamd::fake::spawn(2, "stream: Win.Fake FOUND\0");
        let b = CompositeClamAvBackend::with_clamd(addr);
        assert!(b.clamd_available());
        let r = b.scan_bytes(Path::new("x"), b"contenu").unwrap();
        assert_eq!(r.detections[0].name, "Win.Fake");
        h.join().unwrap();
        // Démon tombé : échec → marqué indisponible → moteur de secours (propre).
        let r = b.scan_bytes(Path::new("x"), b"contenu").unwrap();
        assert_eq!(r.verdict, Verdict::Clean);
        assert!(!b.clamd_available(), "pas de nouvelle sonde avant 30 s");
        assert_eq!(b.name(), "clamav");
    }

    #[test]
    fn composite_sans_demon_et_moteur_indisponible() {
        let b = CompositeClamAvBackend::with_clamd("127.0.0.1:1");
        assert!(!b.clamd_available());
        let mut f = tempfile_with(b"rien");
        assert_eq!(b.scan_path(f.path()).unwrap().verdict, Verdict::Clean);
        f.cleanup();
        assert!(b.scan_path(Path::new("/oc/absent")).is_err());

        let off = ClamAvEngine::with_availability(false);
        assert!(matches!(
            off.scan_bytes(Path::new("x"), b"y"),
            Err(EngineError::Unavailable(_))
        ));
        assert_eq!(ClamAvEngine::default().name(), "clamav");
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
