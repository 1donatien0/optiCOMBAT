//! correlator — corrélateur de décision (feuille de route §7).
//!
//! Fusionne tous les EngineResult en un verdict final selon la politique :
//! un moteur **décisif** (signatures ClamAV/YARA, réputation, blocage OS) qui
//! crie "malware" l'emporte ; sinon le score heuristique/sandbox/ML cumulé
//! décide, avec deux garde-fous anti faux positifs (audit 360) :
//!   - la contribution du classifieur ML est plafonnée ([`ML_SCORE_CAP`]) : il
//!     ne peut pas, à lui seul, faire basculer une cible ;
//!   - sans moteur décisif, le verdict Malicious exige un cumul au moins égal
//!     au seuil critique (les DLL Microsoft légitimes — vcruntime140, mscordbi —
//!     atteignaient le seuil Malicious par simple présence d'imports courants).
//!
//! Chaque décision est explicable (liste des détections contributrices).

use engine_core::{Detection, EngineResult, Severity, Verdict};

#[derive(Debug, Clone)]
pub struct FinalDecision {
    pub verdict: Verdict,
    pub severity: Severity,
    pub total_score: i32,
    pub reasons: Vec<Detection>,
    pub summary: String,
}

/// Politique de décision configurable : seuils de score appliqués au cumul.
/// Permet d'ajuster la sensibilité sans recompiler la logique.
#[derive(Debug, Clone, Copy)]
pub struct DecisionPolicy {
    /// Score à partir duquel la cible est Suspicious.
    pub suspicious_threshold: i32,
    /// Score à partir duquel la cible est Malicious.
    pub malicious_threshold: i32,
    /// Score (ou sévérité Critical) qui élève la gravité à Critical.
    pub critical_threshold: i32,
    /// Score à partir duquel la cible est Malicious **sans** moteur décisif
    /// (heuristique/sandbox/ML seuls). Plus élevé que `malicious_threshold`
    /// pour limiter les faux positifs sur les binaires légitimes.
    pub behavioral_malicious_threshold: i32,
}

impl Default for DecisionPolicy {
    fn default() -> Self {
        // Bandes de la feuille de route : 40 Suspicious, 80 Danger, 150 Malware.
        Self {
            suspicious_threshold: 40,
            malicious_threshold: 80,
            critical_threshold: 150,
            behavioral_malicious_threshold: 150,
        }
    }
}

/// Plafond de contribution du classifieur ML au score cumulé.
pub const ML_SCORE_CAP: i32 = 40;

/// Moteurs dont un verdict Malicious tranche directement.
fn is_decisive_engine(engine: &str) -> bool {
    matches!(engine, "clamav" | "yara" | "reputation" | "windows")
}

/// Corrèle avec la politique par défaut.
pub fn correlate(results: &[EngineResult]) -> FinalDecision {
    correlate_with_policy(results, &DecisionPolicy::default())
}

/// Corrèle l'ensemble des résultats selon une politique de décision donnée.
pub fn correlate_with_policy(results: &[EngineResult], policy: &DecisionPolicy) -> FinalDecision {
    let mut reasons: Vec<Detection> = Vec::new();
    let mut total_score = 0;
    let mut signature_malicious = false;
    let mut any_suspicious = false;
    let mut max_sev = Severity::Clean;

    let mut ml_score = 0;
    for r in results {
        for d in &r.detections {
            if r.engine == "ml" {
                ml_score += d.score;
            } else {
                total_score += d.score;
            }
            if d.severity > max_sev {
                max_sev = d.severity;
            }
            reasons.push(d.clone());
        }
        match r.verdict {
            Verdict::Malicious => {
                // Un moteur décisif (signatures, réputation, OS) tranche directement.
                if is_decisive_engine(&r.engine) {
                    signature_malicious = true;
                } else {
                    any_suspicious = true;
                }
            }
            Verdict::Suspicious => any_suspicious = true,
            _ => {}
        }
    }
    total_score += ml_score.min(ML_SCORE_CAP);

    // Sans moteur décisif, il faut un cumul plus élevé pour conclure Malicious.
    let behavioral_malicious_threshold = policy
        .behavioral_malicious_threshold
        .max(policy.malicious_threshold);

    let verdict = if signature_malicious || total_score >= behavioral_malicious_threshold {
        Verdict::Malicious
    } else if total_score >= policy.suspicious_threshold || any_suspicious {
        Verdict::Suspicious
    } else {
        Verdict::Clean
    };

    let severity = match verdict {
        Verdict::Malicious
            if total_score >= policy.critical_threshold || max_sev == Severity::Critical =>
        {
            Severity::Critical
        }
        Verdict::Malicious => Severity::Major,
        Verdict::Suspicious => Severity::Minor,
        _ => Severity::Clean,
    };

    let summary = format!(
        "verdict={verdict:?} score={total_score} severite={severity} ({} détection(s))",
        reasons.len()
    );

    FinalDecision {
        verdict,
        severity,
        total_score,
        reasons,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::Verdict;

    fn det(engine: &str, score: i32, sev: Severity) -> Detection {
        Detection {
            engine: engine.into(),
            name: "x".into(),
            score,
            severity: sev,
            explanation: String::new(),
        }
    }

    #[test]
    fn signature_l_emporte() {
        let yara = EngineResult {
            engine: "yara".into(),
            verdict: Verdict::Malicious,
            detections: vec![det("yara", 90, Severity::Critical)],
            elapsed_ms: 0,
        };
        let d = correlate(&[yara]);
        assert_eq!(d.verdict, Verdict::Malicious);
        assert_eq!(d.severity, Severity::Critical);
    }

    #[test]
    fn cumul_heuristique() {
        let heur = EngineResult {
            engine: "heuristics".into(),
            verdict: Verdict::Suspicious,
            detections: vec![det("heuristics", 45, Severity::Minor)],
            elapsed_ms: 0,
        };
        let d = correlate(&[heur]);
        assert_eq!(d.verdict, Verdict::Suspicious);
    }

    #[test]
    fn propre() {
        let clean = EngineResult::clean("clamav");
        assert_eq!(correlate(&[clean]).verdict, Verdict::Clean);
    }

    #[test]
    fn ml_seul_ne_tranche_pas() {
        // Cas réel : vcruntime140.dll (Microsoft) — PACKER_SECTIONS 20 + ML 63.
        let heur = EngineResult {
            engine: "heuristics".into(),
            verdict: Verdict::Clean,
            detections: vec![det("heuristics", 20, Severity::Informational)],
            elapsed_ms: 0,
        };
        let ml = EngineResult {
            engine: "ml".into(),
            verdict: Verdict::Malicious,
            detections: vec![det("ml", 63, Severity::Major)],
            elapsed_ms: 0,
        };
        let d = correlate(&[heur, ml]);
        assert_eq!(d.verdict, Verdict::Suspicious);
        assert_eq!(d.total_score, 20 + ML_SCORE_CAP);
    }

    #[test]
    fn cumul_comportemental_critique_reste_malveillant() {
        let sandbox = EngineResult {
            engine: "sandbox".into(),
            verdict: Verdict::Malicious,
            detections: vec![det("sandbox", 160, Severity::Major)],
            elapsed_ms: 0,
        };
        assert_eq!(correlate(&[sandbox]).verdict, Verdict::Malicious);
    }

    #[test]
    fn reputation_blacklist_tranche() {
        let rep = EngineResult {
            engine: "reputation".into(),
            verdict: Verdict::Malicious,
            detections: vec![det("reputation", 100, Severity::Critical)],
            elapsed_ms: 0,
        };
        assert_eq!(correlate(&[rep]).verdict, Verdict::Malicious);
    }

    #[test]
    fn politique_personnalisee() {
        let heur = EngineResult {
            engine: "heuristics".into(),
            verdict: Verdict::Suspicious,
            detections: vec![det("heuristics", 50, Severity::Minor)],
            elapsed_ms: 0,
        };
        // Politique stricte : seuil malveillant abaissé à 50 → score 50 = Malicious.
        let strict = DecisionPolicy {
            suspicious_threshold: 20,
            malicious_threshold: 50,
            critical_threshold: 100,
            behavioral_malicious_threshold: 50,
        };
        assert_eq!(
            correlate_with_policy(std::slice::from_ref(&heur), &strict).verdict,
            Verdict::Malicious
        );
        // Politique par défaut : score 50 reste Suspicious.
        assert_eq!(
            correlate(std::slice::from_ref(&heur)).verdict,
            Verdict::Suspicious
        );
    }
}
