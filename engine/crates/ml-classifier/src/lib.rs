//! ml-classifier — classification légère par famille (feuille de route §10).
//!
//! Pas de LLM : un modèle de classification **explicable** sur des features PE
//! (entropy, imports, sections, API, packer). Entrées normalisées → logits
//! linéaires par classe → softmax → probabilités (ex. « 95 % ransomware »).
//!
//! Les poids sont **appris** par régression logistique softmax (voir le crate
//! `ml-train` : jeu de données étiqueté, descente de gradient, ~89 % d'exactitude
//! sur jeu de test). Ils sont régénérables par `cargo run -p ml-train` et peuvent
//! être remplacés par un modèle LightGBM/XGBoost sans changer l'interface.

use engine_core::{
    Detection, Engine, EngineError, EngineResult, FileKind, ScanContext, Severity, Verdict,
};
use pe_analysis::PeFeatures;

/// Classes de sortie du modèle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Benign,
    Ransomware,
    Rat,
    Dropper,
}

impl Class {
    pub fn label(self) -> &'static str {
        match self {
            Class::Benign => "benign",
            Class::Ransomware => "ransomware",
            Class::Rat => "RAT",
            Class::Dropper => "dropper",
        }
    }
}

/// Vecteur de features normalisées (0..1) extrait d'un binaire PE.
#[derive(Debug, Clone, Copy)]
pub struct FeatureVector {
    pub entropy: f64,    // max_section_entropy / 8
    pub imports: f64,    // densité d'imports
    pub wx_section: f64, // section W^X
    pub packer: f64,     // sections non standard
    pub injection: f64,  // API d'injection
    pub network: f64,    // API réseau / téléchargement
}

impl FeatureVector {
    pub fn from_pe(f: &PeFeatures) -> Self {
        let net = f.imports("URLDownloadToFileA")
            || f.imports("WinInet")
            || f.imports("InternetOpenA")
            || f.imports("WinHttp");
        let inj = f.imports("WriteProcessMemory")
            || f.imports("CreateRemoteThread")
            || f.imports("VirtualAllocEx");
        FeatureVector {
            entropy: (f.max_section_entropy / 8.0).clamp(0.0, 1.0),
            imports: ((f.import_names.len() as f64) / 20.0).clamp(0.0, 1.0),
            wx_section: if f.has_executable_writable_section {
                1.0
            } else {
                0.0
            },
            packer: ((f.nonstandard_section_count as f64) / 4.0).clamp(0.0, 1.0),
            injection: if inj { 1.0 } else { 0.0 },
            network: if net { 1.0 } else { 0.0 },
        }
    }

    fn as_array(&self) -> [f64; 6] {
        [
            self.entropy,
            self.imports,
            self.wx_section,
            self.packer,
            self.injection,
            self.network,
        ]
    }
}

/// Probabilité d'appartenance à une classe.
#[derive(Debug, Clone, Copy)]
pub struct ClassProb {
    pub class: Class,
    pub prob: f64,
}

/// Poids linéaires par classe : [biais, w_entropy, w_imports, w_wx, w_packer, w_inject, w_net].
struct ClassModel {
    class: Class,
    bias: f64,
    weights: [f64; 6],
}

/// Poids **appris** par `ml-train` (régression softmax, graine 0xC0FFEE123,
/// exactitude 89,2 % sur jeu de test disjoint). Régénérables via `cargo run -p ml-train`.
const MODELS: &[ClassModel] = &[
    ClassModel {
        class: Class::Benign,
        bias: 3.2784,
        weights: [-0.8181, -0.9528, -1.2559, -2.2413, -1.2679, -1.9296],
    },
    ClassModel {
        class: Class::Ransomware,
        bias: -1.6300,
        weights: [2.9386, 0.0397, -0.3855, 1.4113, -1.6261, 0.3120],
    },
    ClassModel {
        class: Class::Rat,
        bias: -1.0399,
        weights: [-0.4544, 1.0128, 1.2986, -2.4939, 2.5925, 0.6199],
    },
    ClassModel {
        class: Class::Dropper,
        bias: -0.6085,
        weights: [-1.6662, -0.0997, 0.3428, 3.3238, 0.3016, 0.9978],
    },
];

pub struct Classifier;

impl Classifier {
    pub fn new() -> Self {
        Self
    }

    /// Renvoie les probabilités par classe, triées par ordre décroissant.
    pub fn classify(&self, fv: &FeatureVector) -> Vec<ClassProb> {
        let x = fv.as_array();
        let logits: Vec<(Class, f64)> = MODELS
            .iter()
            .map(|m| {
                let z = m.bias
                    + m.weights
                        .iter()
                        .zip(x.iter())
                        .map(|(w, xi)| w * xi)
                        .sum::<f64>();
                (m.class, z)
            })
            .collect();
        // Softmax numériquement stable.
        let max = logits.iter().map(|(_, z)| *z).fold(f64::MIN, f64::max);
        let exps: Vec<(Class, f64)> = logits.iter().map(|(c, z)| (*c, (z - max).exp())).collect();
        let sum: f64 = exps.iter().map(|(_, e)| *e).sum();
        let mut probs: Vec<ClassProb> = exps
            .iter()
            .map(|(c, e)| ClassProb {
                class: *c,
                prob: e / sum,
            })
            .collect();
        probs.sort_by(|a, b| b.prob.partial_cmp(&a.prob).unwrap());
        probs
    }
}

impl Default for Classifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine for Classifier {
    fn name(&self) -> &str {
        "ml"
    }

    fn applicable(&self, ctx: &ScanContext) -> bool {
        matches!(ctx.kind, FileKind::PortableExecutable)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<EngineResult, EngineError> {
        let pe = pe_analysis::analyze(&ctx.path).map_err(|e| EngineError::Parse(e.to_string()))?;
        let fv = FeatureVector::from_pe(&pe);
        let probs = self.classify(&fv);
        let top = probs[0];
        // On ne signale que si une famille malveillante domine nettement.
        if top.class == Class::Benign || top.prob < 0.5 {
            return Ok(EngineResult::clean("ml"));
        }
        let summary = probs
            .iter()
            .take(3)
            .map(|p| format!("{} {:.0}%", p.class.label(), p.prob * 100.0))
            .collect::<Vec<_>>()
            .join(", ");
        let score = (top.prob * 100.0) as i32;
        let verdict = if top.prob >= 0.8 {
            Verdict::Malicious
        } else {
            Verdict::Suspicious
        };
        Ok(EngineResult {
            engine: "ml".into(),
            verdict,
            detections: vec![Detection {
                engine: "ml".into(),
                name: format!("ML_{}", top.class.label().to_uppercase()),
                score,
                severity: if top.prob >= 0.8 {
                    Severity::Major
                } else {
                    Severity::Minor
                },
                explanation: format!("Classification ML : {summary}"),
            }],
            elapsed_ms: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_benign() -> PeFeatures {
        let mut f = PeFeatures::empty();
        f.is_pe = true;
        f.max_section_entropy = 4.5;
        f.import_names = vec!["GetProcAddress".into(), "LoadLibraryA".into()];
        f
    }

    fn pe_rat() -> PeFeatures {
        let mut f = PeFeatures::empty();
        f.is_pe = true;
        f.max_section_entropy = 7.0;
        f.has_executable_writable_section = true;
        f.import_names = vec![
            "WriteProcessMemory".into(),
            "CreateRemoteThread".into(),
            "VirtualAllocEx".into(),
            "WinInet".into(),
        ];
        f
    }

    #[test]
    fn benin_classe_benign() {
        let probs = Classifier::new().classify(&FeatureVector::from_pe(&pe_benign()));
        assert_eq!(probs[0].class, Class::Benign, "{probs:?}");
    }

    #[test]
    fn injection_reseau_classe_malveillante() {
        let probs = Classifier::new().classify(&FeatureVector::from_pe(&pe_rat()));
        assert_ne!(probs[0].class, Class::Benign, "{probs:?}");
        // Injection forte → RAT ou Dropper en tête.
        assert!(matches!(probs[0].class, Class::Rat | Class::Dropper));
    }

    #[test]
    fn probabilites_somment_a_un() {
        let probs = Classifier::new().classify(&FeatureVector::from_pe(&pe_rat()));
        let sum: f64 = probs.iter().map(|p| p.prob).sum();
        assert!((sum - 1.0).abs() < 1e-9, "sum={sum}");
    }
}
