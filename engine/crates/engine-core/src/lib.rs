//! engine-core — types et traits partagés par tous les moteurs optiCombat.
//!
//! Principe directeur de la feuille de route : chaque moteur (ClamAV, YARA,
//! heuristique, réputation, IA) est un module indépendant qui renvoie un
//! [`EngineResult`] *normalisé*. Le corrélateur applique ensuite la politique
//! de décision. Aucun moteur ne connaît les autres.

use std::fmt;
use std::path::{Path, PathBuf};

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
}

impl ScanContext {
    pub fn new(path: impl Into<PathBuf>, kind: FileKind, size: u64) -> Self {
        Self {
            path: path.into(),
            kind,
            size,
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
}
