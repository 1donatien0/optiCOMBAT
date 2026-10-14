//! heuristics — moteur heuristique maison à score (feuille de route §4).
//!
//! Chaque règle possède un score ; la somme classe la cible :
//!   0–40 OK · 40–80 Suspicious · 80–150 Danger · 150+ Malware.
//! Les indicateurs proviennent de l'analyse PE (imports, sections, entropy).

use engine_core::{
    Detection, Engine, EngineError, EngineResult, FileKind, ScanContext, Severity, Verdict,
};
use pe_analysis::PeFeatures;

/// Règle heuristique pondérée (table directement issue de la feuille de route).
struct HeuRule {
    id: &'static str,
    weight: i32,
    /// Prédicat sur les caractéristiques PE extraites.
    test: fn(&PeFeatures) -> bool,
    why: &'static str,
}

const RULES: &[HeuRule] = &[
    HeuRule {
        id: "EXEC_TEXT_SECTION",
        weight: 30,
        test: |f| f.has_executable_writable_section,
        why: "section exécutable+inscriptible (.text W^X violé)",
    },
    HeuRule {
        id: "UPX_MODIFIED",
        weight: 15,
        test: |f| f.modified_upx,
        why: "en-tête UPX altéré (packer modifié)",
    },
    HeuRule {
        id: "VIRTUALALLOC",
        weight: 25,
        test: |f| f.imports("VirtualAlloc"),
        why: "import VirtualAlloc (alloc mémoire exécutable)",
    },
    HeuRule {
        id: "WRITEPROCESSMEMORY",
        weight: 40,
        test: |f| f.imports("WriteProcessMemory"),
        why: "import WriteProcessMemory (injection)",
    },
    HeuRule {
        id: "CREATEREMOTETHREAD",
        weight: 60,
        test: |f| f.imports("CreateRemoteThread"),
        why: "import CreateRemoteThread (injection distante)",
    },
    HeuRule {
        id: "RUNPE",
        weight: 80,
        test: |f| f.runpe_combo(),
        why: "combinaison RunPE (hollowing de process)",
    },
    HeuRule {
        id: "HIGH_ENTROPY",
        weight: 25,
        test: |f| f.max_section_entropy > 7.2,
        why: "entropie de section élevée (chiffré/packé)",
    },
    HeuRule {
        id: "PACKER_SECTIONS",
        weight: 20,
        test: |f| f.nonstandard_section_count >= 2,
        why: "plusieurs sections au nom non standard (indice de packer)",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Band {
    Ok,
    Suspicious,
    Danger,
    Malware,
}

/// Classe un score selon les bandes de la feuille de route.
pub fn classify(score: i32) -> Band {
    match score {
        i32::MIN..=39 => Band::Ok,
        40..=79 => Band::Suspicious,
        80..=149 => Band::Danger,
        _ => Band::Malware,
    }
}

fn band_severity(b: Band) -> Severity {
    match b {
        Band::Ok => Severity::Clean,
        Band::Suspicious => Severity::Minor,
        Band::Danger => Severity::Major,
        Band::Malware => Severity::Critical,
    }
}

pub struct HeuristicEngine;

impl HeuristicEngine {
    pub fn new() -> Self {
        Self
    }
    /// Évalue un jeu de caractéristiques PE déjà extrait (testable unitairement).
    pub fn evaluate(&self, f: &PeFeatures) -> (i32, Vec<Detection>) {
        let mut score = 0;
        let mut dets = Vec::new();
        for r in RULES {
            if (r.test)(f) {
                score += r.weight;
                dets.push(Detection {
                    engine: "heuristics".into(),
                    name: r.id.into(),
                    score: r.weight,
                    severity: Severity::Informational,
                    explanation: r.why.into(),
                });
            }
        }
        (score, dets)
    }
}
impl Default for HeuristicEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine for HeuristicEngine {
    fn name(&self) -> &str {
        "heuristics"
    }

    fn applicable(&self, ctx: &ScanContext) -> bool {
        matches!(ctx.kind, FileKind::PortableExecutable)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<EngineResult, EngineError> {
        let features =
            pe_analysis::analyze(&ctx.path).map_err(|e| EngineError::Parse(e.to_string()))?;
        let (score, dets) = self.evaluate(&features);
        let band = classify(score);
        let verdict = match band {
            Band::Ok => Verdict::Clean,
            Band::Suspicious => Verdict::Suspicious,
            Band::Danger | Band::Malware => Verdict::Malicious,
        };
        // On résume aussi le score global dans une détection chapeau.
        let mut detections = dets;
        if score > 0 {
            detections.insert(
                0,
                Detection {
                    engine: "heuristics".into(),
                    name: format!("HEUR_SCORE_{score}"),
                    score: 0, // chapeau : la somme est portée par les règles individuelles
                    severity: band_severity(band),
                    explanation: format!("Score heuristique {score} → {band:?}"),
                },
            );
        }
        Ok(EngineResult {
            engine: "heuristics".into(),
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
    fn bandes() {
        assert_eq!(classify(0), Band::Ok);
        assert_eq!(classify(40), Band::Suspicious);
        assert_eq!(classify(80), Band::Danger);
        assert_eq!(classify(160), Band::Malware);
    }

    #[test]
    fn injection_score_eleve() {
        let mut f = PeFeatures::empty();
        f.import_names = vec![
            "WriteProcessMemory".into(),
            "CreateRemoteThread".into(),
            "VirtualAlloc".into(),
        ];
        let (score, dets) = HeuristicEngine::new().evaluate(&f);
        assert!(score >= 125, "score={score}");
        assert!(dets.iter().any(|d| d.name == "CREATEREMOTETHREAD"));
        assert_eq!(classify(score), Band::Danger);
    }

    #[test]
    fn packer_sections() {
        let mut f = PeFeatures::empty();
        f.nonstandard_section_count = 3;
        let (score, dets) = HeuristicEngine::new().evaluate(&f);
        assert_eq!(score, 20);
        assert!(dets.iter().any(|d| d.name == "PACKER_SECTIONS"));
    }
}
