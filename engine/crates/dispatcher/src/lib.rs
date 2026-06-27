//! dispatcher — routage des cibles vers les moteurs pertinents (feuille de route §1).
//!
//! Chaque fichier ne passe que par les moteurs applicables :
//!   PDF/Office → YARA → ClamAV → Heuristique → Corrélation
//!   PE         → ClamAV → Heuristique(PE) → YARA → Corrélation
//! Le dispatcher ne contient AUCUNE logique de détection : il orchestre.

use std::io::{Cursor, Read};
use std::path::Path;

use clamav::CompositeClamAvBackend;
use correlator::{correlate, FinalDecision};
use engine_core::{
    Detection, Engine, EngineResult, FileKind, ScanContext, Severity, SignatureEngine, Verdict,
};
use heuristics::HeuristicEngine;
use ml_classifier::Classifier;
use reputation::{Reputation, ReputationEngine};
use sandbox::Sandbox;
use yara_engine::YaraEngine;

/// Détecte le type de contenu par les magic bytes (proxy du vrai détecteur).
pub fn detect_kind(data: &[u8], path: &Path) -> FileKind {
    if data.len() >= 2 && &data[0..2] == b"MZ" {
        return FileKind::PortableExecutable;
    }
    if data.len() >= 4 && &data[0..4] == b"%PDF" {
        return FileKind::Pdf;
    }
    if data.len() >= 4 && &data[0..4] == b"PK\x03\x04" {
        // ZIP : Office (docx/xlsx) ou archive simple — départage par extension.
        return match path.extension().and_then(|e| e.to_str()) {
            Some("docx") | Some("xlsm") | Some("xlsx") | Some("pptx") => FileKind::OfficeDocument,
            _ => FileKind::Archive,
        };
    }
    match path.extension().and_then(|e| e.to_str()) {
        Some("ps1") | Some("js") | Some("vbs") | Some("bat") | Some("cmd") => FileKind::Script,
        _ => FileKind::Unknown,
    }
}

pub struct Dispatcher {
    clam: CompositeClamAvBackend,
    yara: YaraEngine,
    heur: HeuristicEngine,
    sandbox: Sandbox,
    ml: Classifier,
    reputation: ReputationEngine,
}

impl Dispatcher {
    pub fn new() -> Self {
        Self::with_reputation(ReputationEngine::from_env())
    }

    pub fn with_reputation(reputation: ReputationEngine) -> Self {
        Self {
            clam: CompositeClamAvBackend::new(),
            yara: YaraEngine::new(),
            heur: HeuristicEngine::new(),
            sandbox: Sandbox::new(),
            ml: Classifier::new(),
            reputation,
        }
    }

    /// Pipeline complet sur une cible : détection de type → moteurs → corrélation.
    /// Les archives sont déballées et leurs membres scannés récursivement.
    pub fn scan_path(&self, path: &Path) -> std::io::Result<FinalDecision> {
        let data = std::fs::read(path)?;

        // Réputation par hash AVANT analyse : blacklist tranche, whitelist
        // supprime (faux positif évité), inconnu → pipeline complet.
        match self.reputation.evaluate(&data) {
            Reputation::Blacklisted(name) => {
                return Ok(correlate(&[reputation_result(
                    Verdict::Malicious,
                    Severity::Critical,
                    100,
                    name.clone(),
                    format!("Hash en liste noire : {name}"),
                )]));
            }
            Reputation::Whitelisted => {
                return Ok(correlate(&[reputation_result(
                    Verdict::Clean,
                    Severity::Clean,
                    0,
                    "Whitelisted".into(),
                    "Hash de confiance (whitelist) — analyse supprimée".into(),
                )]));
            }
            Reputation::Unknown => {}
        }

        let results = self.scan_all(path, &data, 0);
        Ok(correlate(&results))
    }

    /// Exécute les moteurs sur la cible, puis déballe si c'est une archive.
    fn scan_all(&self, path: &Path, data: &[u8], depth: u8) -> Vec<EngineResult> {
        let mut results = self.run_engines(path, data);
        let kind = detect_kind(data, path);
        if matches!(kind, FileKind::Archive) && depth < MAX_ARCHIVE_DEPTH {
            results.extend(self.scan_archive(data, depth));
        }
        results
    }

    /// Applique les moteurs pertinents à un fichier (sans déballage).
    fn run_engines(&self, path: &Path, data: &[u8]) -> Vec<EngineResult> {
        let kind = detect_kind(data, path);
        let ctx = ScanContext::new(path.to_path_buf(), kind, data.len() as u64);
        let mut results: Vec<EngineResult> = Vec::new();

        // 1) Moteur de signatures (toujours).
        match self.clam.scan_path(path) {
            Ok(r) => results.push(r),
            Err(_) => results.push(EngineResult::inconclusive("clamav")),
        }
        // 2) YARA si applicable.
        if self.yara.applicable(&ctx) {
            if let Ok(r) = self.yara.scan(&ctx) {
                results.push(r);
            }
        }
        // 3) Heuristique PE si applicable.
        if self.heur.applicable(&ctx) {
            if let Ok(r) = self.heur.scan(&ctx) {
                results.push(r);
            }
        }
        // 4) Sandbox comportementale (PE/scripts/Office).
        if self.sandbox.applicable(&ctx) {
            if let Ok(r) = self.sandbox.scan(&ctx) {
                results.push(r);
            }
        }
        // 5) Classifieur ML (PE).
        if self.ml.applicable(&ctx) {
            if let Ok(r) = self.ml.scan(&ctx) {
                results.push(r);
            }
        }
        results
    }

    /// Déballe une archive ZIP et scanne chaque membre (avec garde-fous
    /// anti zip-bomb : profondeur, nombre d'entrées, taille décompressée).
    fn scan_archive(&self, data: &[u8], depth: u8) -> Vec<EngineResult> {
        let mut out = Vec::new();
        let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(data)) else {
            return out;
        };
        let count = archive.len().min(MAX_ARCHIVE_ENTRIES);
        for i in 0..count {
            let Ok(entry) = archive.by_index(i) else {
                continue;
            };
            if !entry.is_file() {
                continue;
            }
            let name = entry.name().to_string();
            let mut buf = Vec::new();
            if entry.take(MAX_MEMBER_SIZE).read_to_end(&mut buf).is_err() {
                continue;
            }
            // Écrit dans un fichier temporaire pour réutiliser tout le pipeline.
            let tmp = std::env::temp_dir().join(format!(
                "oc_zip_{}_{}_{}",
                std::process::id(),
                depth,
                sanitize(&name)
            ));
            if std::fs::write(&tmp, &buf).is_err() {
                continue;
            }
            let mut member = self.scan_all(&tmp, &buf, depth + 1);
            let _ = std::fs::remove_file(&tmp);
            // Trace le membre dans chaque explication pour l'auditabilité.
            for r in &mut member {
                for d in &mut r.detections {
                    d.explanation = format!("[zip:{name}] {}", d.explanation);
                }
            }
            out.extend(member);
        }
        out
    }
}

/// Garde-fous de déballage d'archives.
const MAX_ARCHIVE_DEPTH: u8 = 2;
const MAX_ARCHIVE_ENTRIES: usize = 256;
const MAX_MEMBER_SIZE: u64 = 64 * 1024 * 1024;

/// Réduit un nom de membre à un suffixe de fichier temporaire sûr.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .chars()
        .rev()
        .take(40)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

/// Construit un EngineResult de réputation pour le corrélateur.
fn reputation_result(
    verdict: Verdict,
    severity: Severity,
    score: i32,
    name: String,
    explanation: String,
) -> EngineResult {
    let detections = if score > 0 {
        vec![Detection {
            engine: "reputation".into(),
            name,
            score,
            severity,
            explanation,
        }]
    } else {
        Vec::new()
    };
    EngineResult {
        engine: "reputation".into(),
        verdict,
        detections,
        elapsed_ms: 0,
    }
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::Verdict;
    use std::io::Write;

    fn tmp(data: &[u8], ext: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let uid = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("oc_disp_{}_{}.{ext}", std::process::id(), uid));
        std::fs::File::create(&p).unwrap().write_all(data).unwrap();
        p
    }

    #[test]
    fn route_script_powershell_malicieux() {
        let p = tmp(b"powershell -enc ZQ== ; Invoke-Expression $x", "ps1");
        let d = Dispatcher::new().scan_path(&p).unwrap();
        assert_eq!(d.verdict, Verdict::Malicious);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn fichier_texte_propre() {
        let p = tmp(b"juste du texte normal", "txt");
        let d = Dispatcher::new().scan_path(&p).unwrap();
        assert_eq!(d.verdict, Verdict::Clean);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn detection_type_pe() {
        assert_eq!(
            detect_kind(b"MZ\x90\x00", Path::new("a.exe")),
            FileKind::PortableExecutable
        );
        assert_eq!(detect_kind(b"%PDF-1.7", Path::new("a.pdf")), FileKind::Pdf);
    }
}
