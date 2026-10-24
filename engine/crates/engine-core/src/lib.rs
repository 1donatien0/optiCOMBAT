//! engine-core — types et traits partagés par tous les moteurs optiCombat.
//!
//! Principe directeur de la feuille de route : chaque moteur (ClamAV, YARA,
//! heuristique, réputation, IA) est un module indépendant qui renvoie un
//! [`EngineResult`] *normalisé*. Le corrélateur applique ensuite la politique
//! de décision. Aucun moteur ne connaît les autres.

use std::borrow::Cow;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Sévérité normalisée alignée sur le `RiskScoringService` C# existant
/// (Informationnel / Mineur / Majeur / Critique) afin de garder la parité
/// fonctionnelle pendant la migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Clean,
    Informational,
    Minor,
    Major,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Clean => "Clean",
            Severity::Informational => "Informational",
            Severity::Minor => "Minor",
            Severity::Major => "Major",
            Severity::Critical => "Critical",
        };
        f.write_str(s)
    }
}

/// Verdict d'un moteur sur une cible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
    /// Le moteur n'a pas pu se prononcer (non applicable, erreur récupérable).
    Inconclusive,
}

/// Détection unitaire émise par un moteur.
#[derive(Debug, Clone)]
pub struct Detection {
    /// Moteur émetteur ("clamav", "yara", "heuristics"...).
    pub engine: String,
    /// Nom de la signature/règle ou identifiant de l'heuristique.
    pub name: String,
    /// Score brut contribué (échelle heuristique de la feuille de route).
    pub score: i32,
    pub severity: Severity,
    /// Explication lisible (exigée pour l'auditabilité, cf. corrélateur).
    pub explanation: String,
}

/// Résultat normalisé renvoyé par tout moteur implémentant [`Engine`].
#[derive(Debug, Clone)]
pub struct EngineResult {
    pub engine: String,
    pub verdict: Verdict,
    pub detections: Vec<Detection>,
    /// Durée d'analyse en millisecondes (télémétrie).
    pub elapsed_ms: u128,
}

impl EngineResult {
    pub fn clean(engine: impl Into<String>) -> Self {
        Self {
            engine: engine.into(),
            verdict: Verdict::Clean,
            detections: Vec::new(),
            elapsed_ms: 0,
        }
    }
    pub fn inconclusive(engine: impl Into<String>) -> Self {
        Self {
            engine: engine.into(),
            verdict: Verdict::Inconclusive,
            detections: Vec::new(),
            elapsed_ms: 0,
        }
    }
    /// Score cumulé de toutes les détections (entrée du corrélateur).
    pub fn total_score(&self) -> i32 {
        self.detections.iter().map(|d| d.score).sum()
    }
}

/// Type de contenu détecté par le dispatcher pour router vers les bons moteurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    PortableExecutable,
    OfficeDocument,
    Pdf,
    Script,
    Archive,
    Unknown,
}

/// Contexte transmis à chaque moteur pour une cible donnée.
#[derive(Debug, Clone)]
pub struct ScanContext {
    pub path: PathBuf,
    pub kind: FileKind,
    pub size: u64,
    /// Contenu déjà lu par le dispatcher : les moteurs ne relisent pas le
    /// fichier (auparavant une lecture disque par moteur et par cible).
    pub data: Option<Arc<[u8]>>,
}

impl ScanContext {
    pub fn new(path: impl Into<PathBuf>, kind: FileKind, size: u64) -> Self {
        Self {
            path: path.into(),
            kind,
            size,
            data: None,
        }
    }

    /// Attache le contenu déjà en mémoire.
    pub fn with_data(mut self, data: Arc<[u8]>) -> Self {
        self.data = Some(data);
        self
    }

    /// Contenu de la cible : celui fourni par le dispatcher, sinon lu sur disque.
    pub fn bytes(&self) -> std::io::Result<Cow<'_, [u8]>> {
        match &self.data {
            Some(d) => Ok(Cow::Borrowed(d)),
            None => std::fs::read(&self.path).map(Cow::Owned),
        }
    }
}

/// Erreur moteur. Récupérable => le pipeline continue avec les autres moteurs.
#[derive(Debug)]
pub enum EngineError {
    Io(std::io::Error),
    Unavailable(String),
    Parse(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::Io(e) => write!(f, "io: {e}"),
            EngineError::Unavailable(m) => write!(f, "indisponible: {m}"),
            EngineError::Parse(m) => write!(f, "parse: {m}"),
        }
    }
}

impl std::error::Error for EngineError {}
impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        EngineError::Io(e)
    }
}

/// Clé de masquage des motifs de détection embarqués.
pub const NEEDLE_MASK: u8 = 0x5A;

/// Masque un motif à la compilation (utilisé via [`masked!`]).
pub const fn mask_bytes<const N: usize>(plain: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = plain[i] ^ NEEDLE_MASK;
        i += 1;
    }
    out
}

/// Démasque un motif embarqué.
pub fn unmask_bytes(masked: &[u8]) -> Vec<u8> {
    masked
        .iter()
        .map(|b| std::hint::black_box(*b) ^ NEEDLE_MASK)
        .collect()
}

/// Motif de détection stocké masqué dans le binaire : en clair, les tables de
/// motifs (noms d'API d'injection, clés Run, « powershell »…) faisaient
/// détecter `opticombat_engine.dll` par ses propres moteurs (audit 360).
#[macro_export]
macro_rules! masked {
    ($s:literal) => {{
        const M: &[u8] = &$crate::mask_bytes($s);
        M
    }};
}

/// Contrat commun à tous les moteurs d'analyse.
pub trait Engine: Send + Sync {
    /// Identifiant stable du moteur.
    fn name(&self) -> &str;
    /// Le moteur est-il pertinent pour cette cible ? (utilisé par le dispatcher)
    fn applicable(&self, ctx: &ScanContext) -> bool {
        let _ = ctx;
        true
    }
    /// Analyse la cible et renvoie un résultat normalisé.
    fn scan(&self, ctx: &ScanContext) -> Result<EngineResult, EngineError>;
}

/// Contrat spécifique aux moteurs de signatures (ClamAV, Defender OEM...),
/// repris tel quel de la feuille de route : `trait SignatureEngine { fn scan(path); }`.
/// Permet de remplacer le backend sans toucher au reste du système.
pub trait SignatureEngine: Send + Sync {
    fn name(&self) -> &str;
    fn scan_path(&self, path: &Path) -> Result<EngineResult, EngineError>;
    /// Analyse un contenu déjà en mémoire (par défaut : relit le chemin).
    fn scan_bytes(&self, path: &Path, data: &[u8]) -> Result<EngineResult, EngineError> {
        let _ = data;
        self.scan_path(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dummy;
    impl Engine for Dummy {
        fn name(&self) -> &str {
            "dummy"
        }
        fn scan(&self, ctx: &ScanContext) -> Result<EngineResult, EngineError> {
            let bytes = ctx.bytes()?;
            Ok(if bytes.is_empty() {
                EngineResult::inconclusive(self.name())
            } else {
                EngineResult::clean(self.name())
            })
        }
    }

    struct Sig;
    impl SignatureEngine for Sig {
        fn name(&self) -> &str {
            "sig"
        }
        fn scan_path(&self, path: &Path) -> Result<EngineResult, EngineError> {
            if path.exists() {
                Ok(EngineResult::clean("sig"))
            } else {
                Err(EngineError::Unavailable(path.display().to_string()))
            }
        }
    }

    #[test]
    fn severites_affichees() {
        let all = [
            (Severity::Clean, "Clean"),
            (Severity::Informational, "Informational"),
            (Severity::Minor, "Minor"),
            (Severity::Major, "Major"),
            (Severity::Critical, "Critical"),
        ];
        for (s, txt) in all {
            assert_eq!(s.to_string(), txt);
        }
        assert!(Severity::Critical > Severity::Major);
    }

    #[test]
    fn resultat_et_score_cumule() {
        let mut r = EngineResult::clean("x");
        assert_eq!(r.total_score(), 0);
        for score in [10, 25] {
            r.detections.push(Detection {
                engine: "x".into(),
                name: "n".into(),
                score,
                severity: Severity::Minor,
                explanation: String::new(),
            });
        }
        assert_eq!(r.total_score(), 35);
        let i = EngineResult::inconclusive("y");
        assert_eq!(i.verdict, Verdict::Inconclusive);
        assert_eq!(i.engine, "y");
    }

    #[test]
    fn contexte_lit_le_disque_sans_donnees_partagees() {
        let p = std::env::temp_dir().join(format!("oc_core_{}.bin", std::process::id()));
        std::fs::write(&p, b"abc").unwrap();
        let ctx = ScanContext::new(p.clone(), FileKind::Unknown, 3);
        assert_eq!(&*ctx.bytes().unwrap(), b"abc");
        assert_eq!(Dummy.scan(&ctx).unwrap().verdict, Verdict::Clean);
        assert!(Dummy.applicable(&ctx));

        let shared = ScanContext::new(p.clone(), FileKind::Script, 0)
            .with_data(std::sync::Arc::from(&b""[..]));
        assert_eq!(Dummy.scan(&shared).unwrap().verdict, Verdict::Inconclusive);
        let _ = std::fs::remove_file(&p);

        let missing = ScanContext::new(p.clone(), FileKind::Unknown, 0);
        let err = Dummy.scan(&missing).unwrap_err();
        assert!(err.to_string().starts_with("io: "));
    }

    #[test]
    fn erreurs_affichees() {
        assert_eq!(
            EngineError::Unavailable("x".into()).to_string(),
            "indisponible: x"
        );
        assert_eq!(EngineError::Parse("y".into()).to_string(), "parse: y");
        let io: EngineError = std::io::Error::other("z").into();
        assert!(matches!(io, EngineError::Io(_)));
        let as_dyn: &dyn std::error::Error = &io;
        assert!(as_dyn.to_string().contains('z'));
    }

    #[test]
    fn signature_engine_scan_bytes_par_defaut_relit_le_chemin() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(
            Sig.scan_bytes(here, b"ignored").unwrap().verdict,
            Verdict::Clean
        );
        assert!(Sig.scan_bytes(Path::new("/oc/absent"), b"").is_err());
        assert_eq!(Sig.name(), "sig");
    }

    #[test]
    fn masquage_reversible() {
        let m = masked!(b"powershell");
        assert_ne!(m, b"powershell");
        assert_eq!(unmask_bytes(m), b"powershell");
        assert_eq!(mask_bytes(&[NEEDLE_MASK]), [0u8]);
    }
}
