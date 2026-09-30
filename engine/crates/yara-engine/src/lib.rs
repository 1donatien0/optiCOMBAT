//! yara-engine — moteur de règles YARA réel (feuille de route §3).
//!
//! Charge et évalue les règles `.yar` du sous-ensemble utilisé par optiCombat.
//! Les règles du dépôt (`optiCombat/rules/*.yar`) sont embarquées via `include_str!`
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

/// Règles du dépôt, embarquées à la compilation (chargement réel).
const TEST_RULES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../optiCombat/rules/test_rules.yar"
));
const MALWARE_RULES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../optiCombat/rules/malware_signatures.yar"
));
const SUSPICIOUS_RULES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../optiCombat/rules/suspicious_strings.yar"
));

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
        for src in [TEST_RULES, MALWARE_RULES, SUSPICIOUS_RULES] {
            if let Ok(mut r) = parse_rules(src) {
                rules.append(&mut r);
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
        let data = std::fs::read(&ctx.path)?;
        let detections = self.match_bytes(&data);
        let verdict = if detections.is_empty() {
            Verdict::Clean
        } else {
            Verdict::Malicious
        };
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
        // 2 extensions ransomware → Possible_Ransomware (Cas 3 : 2 of ($ext*)).
        let e = YaraEngine::new();
        let data = b"fichiers renommes: rapport.encrypted budget.locked";
        let dets = e.match_bytes(data);
        assert!(dets.iter().any(|d| d.name == "Possible_Ransomware"));
    }
}
