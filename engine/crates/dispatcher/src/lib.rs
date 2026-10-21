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
    // Extension normalisée en minuscules : « RAPPORT.DOCM » ou « RUN.PS1 »
    // échappaient auparavant au routage (comparaison sensible à la casse).
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    if data.len() >= 4 && &data[0..4] == b"PK\x03\x04" {
        // ZIP : Office OOXML (y compris les formats à macros *m) ou archive simple.
        return match ext.as_deref() {
            Some(
                "docx" | "docm" | "dotx" | "dotm" | "xlsx" | "xlsm" | "xltx" | "xltm" | "xlam"
                | "pptx" | "pptm" | "potx" | "potm" | "ppsx" | "ppsm",
            ) => FileKind::OfficeDocument,
            _ => FileKind::Archive,
        };
    }
    match ext.as_deref() {
        Some(
            "ps1" | "psm1" | "psd1" | "js" | "jse" | "vbs" | "vbe" | "wsf" | "wsh" | "hta" | "bat"
            | "cmd",
        ) => FileKind::Script,
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

    /// Vrai si un démon clamd (signatures ClamAV complètes) répond. Sinon le
    /// moteur « clamav » ne reconnaît que la signature de test EICAR.
    pub fn clamd_available(&self) -> bool {
        self.clam.clamd_available()
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
        let data = match std::fs::read(path) {
            Ok(data) => data,
            Err(e) if is_os_virus_block(&e) => return Ok(os_blocked_decision(&e)),
            Err(e) => return Err(e),
        };

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
        // Le contenu est partagé avec tous les moteurs : une seule lecture disque.
        let ctx = ScanContext::new(path.to_path_buf(), kind, data.len() as u64)
            .with_data(std::sync::Arc::from(data));
        let mut results: Vec<EngineResult> = Vec::new();

        // 1) Moteur de signatures (toujours).
        match self.clam.scan_bytes(path, data) {
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
        // Budget global de décompression par archive (anti zip-bomb) : sans lui,
        // 256 membres × 64 Mio pouvaient être écrits sur disque à chaque niveau.
        let mut budget = MAX_ARCHIVE_TOTAL_BYTES;
        for i in 0..count {
            if budget == 0 {
                break;
            }
            let Ok(entry) = archive.by_index(i) else {
                continue;
            };
            if !entry.is_file() {
                continue;
            }
            let Ok(name) = entry.name().map(|n| n.into_owned()) else {
                continue;
            };
            let mut buf = Vec::new();
            if entry
                .take(MAX_MEMBER_SIZE.min(budget))
                .read_to_end(&mut buf)
                .is_err()
            {
                continue;
            }
            budget = budget.saturating_sub(buf.len() as u64);
            // Écrit dans un fichier temporaire pour réutiliser tout le pipeline.
            // Nom unique (pid + compteur) et création exclusive : deux membres de
            // même nom, ou deux scans concurrents, ne s'écrasent plus, et un
            // fichier/lien préexistant n'est jamais réutilisé.
            let Some(tmp) = write_unique_temp(depth, &name, &buf) else {
                continue;
            };
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
const MAX_ARCHIVE_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// Crée un fichier temporaire exclusif (`create_new`) pour un membre d'archive.
fn write_unique_temp(depth: u8, name: &str, data: &[u8]) -> Option<std::path::PathBuf> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    for _ in 0..8 {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = std::env::temp_dir().join(format!(
            "oc_zip_{}_{}_{}_{}",
            std::process::id(),
            seq,
            depth,
            sanitize(name)
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
        {
            Ok(mut f) => {
                if f.write_all(data).is_err() {
                    drop(f);
                    let _ = std::fs::remove_file(&tmp);
                    return None;
                }
                return Some(tmp);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return None,
        }
    }
    None
}

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

/// Windows : lecture refusée parce que le fichier est déjà jugé malveillant.
/// ERROR_VIRUS_INFECTED (225) et ERROR_VIRUS_DELETED (226).
fn is_os_virus_block(err: &std::io::Error) -> bool {
    matches!(err.raw_os_error(), Some(225 | 226))
}

/// Décision lorsque l'OS bloque la lecture : ce n'est pas un échec d'analyse.
fn os_blocked_decision(err: &std::io::Error) -> FinalDecision {
    correlate(&[EngineResult {
        engine: "windows".into(),
        verdict: Verdict::Malicious,
        detections: vec![Detection {
            engine: "windows".into(),
            name: "Win32.OsBlocked".into(),
            score: 100,
            severity: Severity::Critical,
            explanation: format!("Windows a refusé la lecture : {err}"),
        }],
        elapsed_ms: 0,
    }])
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
    fn route_script_powershell_suspect() {
        // Règle YARA « medium » + indicateurs comportementaux faibles : indice,
        // pas preuve → Suspicious (n'est plus auto-mis en quarantaine).
        let p = tmp(b"powershell -enc ZQ== ; Invoke-Expression $x", "ps1");
        let d = Dispatcher::new().scan_path(&p).unwrap();
        assert_eq!(d.verdict, Verdict::Suspicious);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn extension_insensible_a_la_casse() {
        assert_eq!(detect_kind(b"x", Path::new("RUN.PS1")), FileKind::Script);
        assert_eq!(
            detect_kind(b"PK\x03\x04", Path::new("Rapport.DOCM")),
            FileKind::OfficeDocument
        );
        assert_eq!(detect_kind(b"x", Path::new("a.hta")), FileKind::Script);
    }

    #[test]
    fn temp_unique_ne_reutilise_pas_un_fichier_existant() {
        let a = write_unique_temp(0, "same.txt", b"a").unwrap();
        let b = write_unique_temp(0, "same.txt", b"b").unwrap();
        assert_ne!(a, b);
        assert_eq!(std::fs::read(&a).unwrap(), b"a");
        let _ = std::fs::remove_file(a);
        let _ = std::fs::remove_file(b);
    }

    #[test]
    fn eicar_complet_est_malveillant_meme_si_windows_bloque_la_lecture() {
        let p = tmp(
            br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            "com",
        );
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
