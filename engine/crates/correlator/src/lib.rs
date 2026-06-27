//! correlator — corrélateur de décision (feuille de route §7).
//!
//! Fusionne tous les EngineResult en un verdict final selon la politique :
//! un moteur de signatures (ClamAV/YARA) qui crie "malware" l'emporte ;
//! sinon le score heuristique/sandbox cumulé décide. Chaque décision est
//! explicable (liste des détections contributrices).

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
}

impl Default for DecisionPolicy {
    fn default() -> Self {
        // Bandes de la feuille de route : 40 Suspicious, 80 Danger, 150 Malware.
        Self {
            suspicious_threshold: 40,
            malicious_threshold: 80,
            critical_threshold: 150,
        }
    }
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

    for r in results {
        for d in &r.detections {
            total_score += d.score;
            if d.severity > max_sev {
                max_sev = d.severity;
            }
            reasons.push(d.clone());
        }
        match r.verdict {
            Verdict::Malicious => {
                // Un moteur de signatures (clamav/yara) tranche directement.
                if r.engine == "clamav" || r.engine == "yara" {
                    signature_malicious = true;
                }
            }
            Verdict::Suspicious => any_suspicious = true,
            _ => {}
        }
    }

    let verdict = if signature_malicious || total_score >= policy.malicious_threshold {
        // Signature qui tranche, ou cumul au-delà du seuil malveillant.
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
