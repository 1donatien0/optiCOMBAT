//! ml-train — entraînement du classifieur de familles (feuille de route §10).
//!
//! Modes :
//! - Par défaut : charge `corpus/labeled.jsonl` (features dérivées de profils PE réels)
//!   et entraîne une régression logistique softmax.
//! - `--synthetic` : jeu de données synthétique (legacy).
//! - `--extract <fichier.pe> <classe>` : extrait un vecteur de features depuis un PE réel.
//! - `--validate` : évalue sur `corpus/holdout.jsonl` après entraînement.

use pe_analysis::PeFeatures;
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const NCLASS: usize = 4;
const NFEAT: usize = 6;
const CLASS_NAMES: [&str; NCLASS] = ["Benign", "Ransomware", "Rat", "Dropper"];

#[derive(Debug, Deserialize)]
struct LabeledSample {
    class: String,
    entropy: f64,
    imports: f64,
    wx_section: f64,
    packer: f64,
    injection: f64,
    network: f64,
}

impl LabeledSample {
    fn features(&self) -> [f64; NFEAT] {
        [
            self.entropy,
            self.imports,
            self.wx_section,
            self.packer,
            self.injection,
            self.network,
        ]
    }

    fn class_index(&self) -> Option<usize> {
        CLASS_NAMES
            .iter()
            .position(|c| c.eq_ignore_ascii_case(&self.class))
    }
}

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus")
}

fn load_jsonl(path: &Path) -> std::io::Result<Vec<( [f64; NFEAT], usize)>> {
    let text = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let s: LabeledSample = serde_json::from_str(line)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let Some(class) = s.class_index() else {
            continue;
        };
        out.push((s.features(), class));
    }
    Ok(out)
}

fn features_from_pe(f: &PeFeatures) -> [f64; NFEAT] {
    let net = f.imports("URLDownloadToFileA")
        || f.imports("WinInet")
        || f.imports("InternetOpenA")
        || f.imports("WinHttp");
    let inj = f.imports("WriteProcessMemory")
        || f.imports("CreateRemoteThread")
        || f.imports("VirtualAllocEx");
    [
        (f.max_section_entropy / 8.0).clamp(0.0, 1.0),
        ((f.import_names.len() as f64) / 20.0).clamp(0.0, 1.0),
        if f.has_executable_writable_section {
            1.0
        } else {
            0.0
        },
        ((f.nonstandard_section_count as f64) / 4.0).clamp(0.0, 1.0),
        if inj { 1.0 } else { 0.0 },
        if net { 1.0 } else { 0.0 },
    ]
}

fn extract_pe(path: &Path, class: &str) -> std::io::Result<()> {
    let pe = pe_analysis::analyze(path).map_err(|e| std::io::Error::other(e.to_string()))?;
    let feat = features_from_pe(&pe);
    let sample = LabeledSample {
        class: class.to_string(),
        entropy: feat[0],
        imports: feat[1],
        wx_section: feat[2],
        packer: feat[3],
        injection: feat[4],
        network: feat[5],
    };
    println!("{}", serde_json::to_string(&sample).unwrap());
    Ok(())
}

fn extract_dir(dir: &Path, class: &str) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            extract_pe(&path, class)?;
        }
    }
    Ok(())
}

/// RNG déterministe (LCG) → float [0,1).
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 11) as f64) / ((1u64 << 53) as f64)
    }
    fn uniform(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.next()
    }
    fn bernoulli(&mut self, p: f64) -> f64 {
        if self.next() < p {
            1.0
        } else {
            0.0
        }
    }
}

fn sample_synthetic(class: usize, rng: &mut Rng) -> [f64; NFEAT] {
    match class {
        0 => [
            rng.uniform(0.2, 0.6),
            rng.uniform(0.0, 0.3),
            rng.bernoulli(0.02),
            rng.uniform(0.0, 0.2),
            rng.bernoulli(0.02),
            rng.bernoulli(0.05),
        ],
        1 => [
            rng.uniform(0.85, 1.0),
            rng.uniform(0.2, 0.6),
            rng.bernoulli(0.3),
            rng.uniform(0.4, 0.9),
            rng.bernoulli(0.1),
            rng.bernoulli(0.8),
        ],
        2 => [
            rng.uniform(0.55, 0.85),
            rng.uniform(0.3, 0.7),
            rng.bernoulli(0.8),
            rng.uniform(0.2, 0.5),
            rng.bernoulli(0.95),
            rng.bernoulli(0.85),
        ],
        _ => [
            rng.uniform(0.5, 0.85),
            rng.uniform(0.2, 0.6),
            rng.bernoulli(0.5),
            rng.uniform(0.5, 0.9),
            rng.bernoulli(0.5),
            rng.bernoulli(0.9),
        ],
    }
}

fn softmax(logits: &[f64; NCLASS]) -> [f64; NCLASS] {
    let max = logits.iter().cloned().fold(f64::MIN, f64::max);
    let mut exp = [0.0; NCLASS];
    let mut sum = 0.0;
    for k in 0..NCLASS {
        exp[k] = (logits[k] - max).exp();
        sum += exp[k];
    }
    for e in &mut exp {
        *e /= sum;
    }
    exp
}

fn predict(w: &[[f64; NFEAT + 1]; NCLASS], x: &[f64; NFEAT]) -> [f64; NCLASS] {
    let mut logits = [0.0; NCLASS];
    for (k, lk) in logits.iter_mut().enumerate() {
        let mut z = w[k][0];
        for j in 0..NFEAT {
            z += w[k][j + 1] * x[j];
        }
        *lk = z;
    }
    softmax(&logits)
}

fn accuracy(w: &[[f64; NFEAT + 1]; NCLASS], data: &[( [f64; NFEAT], usize)]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut correct = 0;
    for (x, y) in data {
        let p = predict(w, x);
        let pred = (0..NCLASS)
            .max_by(|a, b| p[*a].partial_cmp(&p[*b]).unwrap())
            .unwrap();
        if pred == *y {
            correct += 1;
        }
    }
    correct as f64 / data.len() as f64
}

fn train(data: &[( [f64; NFEAT], usize)]) -> [[f64; NFEAT + 1]; NCLASS] {
    let mut w = [[0.0f64; NFEAT + 1]; NCLASS];
    let lr = 0.3;
    let l2 = 1e-4;
    let epochs = 400;
    for _ in 0..epochs {
        let mut grad = [[0.0f64; NFEAT + 1]; NCLASS];
        for (x, y) in data {
            let p = predict(&w, x);
            for k in 0..NCLASS {
                let err = p[k] - if k == *y { 1.0 } else { 0.0 };
                grad[k][0] += err;
                for j in 0..NFEAT {
                    grad[k][j + 1] += err * x[j];
                }
            }
        }
        let n = data.len() as f64;
        for k in 0..NCLASS {
            for j in 0..(NFEAT + 1) {
                let mut g = grad[k][j] / n;
                if j > 0 {
                    g += l2 * w[k][j];
                }
                w[k][j] -= lr * g;
            }
        }
    }
    w
}

fn print_weights(w: &[[f64; NFEAT + 1]; NCLASS], acc: f64) {
    println!(
        "// Poids appris par ml-train (corpus réel, exactitude holdout {:.1}%).",
        acc * 100.0
    );
    println!("const MODELS: &[ClassModel] = &[");
    for k in 0..NCLASS {
        println!("    ClassModel {{");
        println!("        class: Class::{},", CLASS_NAMES[k]);
        println!("        bias: {:.4},", w[k][0]);
        print!("        weights: [");
        for j in 0..NFEAT {
            print!("{:.4}", w[k][j + 1]);
            if j + 1 < NFEAT {
                print!(", ");
            }
        }
        println!("],");
        println!("    }},");
    }
    println!("];");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 4 && args[1] == "--extract" {
        extract_pe(Path::new(&args[2]), &args[3]).expect("extract PE");
        return;
    }
    if args.len() >= 4 && args[1] == "--extract-dir" {
        extract_dir(Path::new(&args[2]), &args[3]).expect("extract dir");
        return;
    }

    let use_synthetic = args.iter().any(|a| a == "--synthetic");
    let do_validate = args.iter().any(|a| a == "--validate");

    let train_data = if use_synthetic {
        eprintln!("Mode synthétique (legacy) — graine 0xC0FFEE123");
        let mut rng = Rng::new(0xC0FFEE123);
        let mut train = Vec::new();
        for c in 0..NCLASS {
            for _ in 0..1500 {
                train.push((sample_synthetic(c, &mut rng), c));
            }
        }
        train
    } else {
        let path = corpus_dir().join("labeled.jsonl");
        eprintln!("Chargement du corpus réel : {}", path.display());
        load_jsonl(&path).expect("corpus labeled.jsonl")
    };

    assert!(
        !train_data.is_empty(),
        "jeu d'entraînement vide — fournir corpus/labeled.jsonl"
    );

    let w = train(&train_data);
    let holdout_path = corpus_dir().join("holdout.jsonl");
    let holdout = load_jsonl(&holdout_path).unwrap_or_default();
    let acc = accuracy(&w, &holdout);
    eprintln!(
        "Exactitude holdout = {:.2}% ({}/{})",
        acc * 100.0,
        (acc * holdout.len() as f64).round() as usize,
        holdout.len()
    );

    if do_validate && acc < 0.70 {
        eprintln!("Échec validation : exactitude holdout < 70 %");
        std::process::exit(1);
    }

    print_weights(&w, acc);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_labeled_charge() {
        let data = load_jsonl(&corpus_dir().join("labeled.jsonl")).expect("labeled");
        assert!(data.len() >= 40, "corpus trop petit : {}", data.len());
    }

    #[test]
    fn holdout_validation_min_70pct() {
        let train = load_jsonl(&corpus_dir().join("labeled.jsonl")).unwrap();
        let holdout = load_jsonl(&corpus_dir().join("holdout.jsonl")).unwrap();
        let w = train(&train);
        let acc = accuracy(&w, &holdout);
        assert!(
            acc >= 0.70,
            "exactitude holdout insuffisante : {:.1}%",
            acc * 100.0
        );
    }
}
