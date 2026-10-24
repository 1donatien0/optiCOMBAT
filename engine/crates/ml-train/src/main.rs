//! ml-train — entraînement du classifieur de familles (feuille de route §10).
//!
//! Modes :
//! - Par défaut : charge `corpus/labeled.jsonl` (features dérivées de profils PE réels)
//!   et entraîne une régression logistique softmax.
//! - `--synthetic` : jeu de données synthétique (legacy).
//! - `--extract <fichier.pe> <classe>` : extrait un vecteur de features depuis un PE réel.
//! - `--validate` : évalue sur `corpus/holdout.jsonl` après entraînement.

use pe_analysis::PeFeatures;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const NCLASS: usize = 4;
const NFEAT: usize = 6;
const CLASS_NAMES: [&str; NCLASS] = ["Benign", "Ransomware", "Rat", "Dropper"];

#[derive(Debug, Deserialize, Serialize)]
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

fn load_jsonl(path: &Path) -> std::io::Result<Vec<([f64; NFEAT], usize)>> {
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

fn extract_pe(path: &Path, class: &str, out: &mut dyn Write) -> std::io::Result<()> {
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
    let json = serde_json::to_string(&sample).map_err(std::io::Error::other)?;
    writeln!(out, "{json}")
}

fn extract_dir(dir: &Path, class: &str, out: &mut dyn Write) -> std::io::Result<()> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    paths.sort(); // sortie reproductible
    for path in paths {
        extract_pe(&path, class, out)?;
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

fn accuracy(w: &[[f64; NFEAT + 1]; NCLASS], data: &[([f64; NFEAT], usize)]) -> f64 {
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

fn train(data: &[([f64; NFEAT], usize)]) -> [[f64; NFEAT + 1]; NCLASS] {
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

fn print_weights(
    w: &[[f64; NFEAT + 1]; NCLASS],
    acc: f64,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    writeln!(
        out,
        "// Poids appris par ml-train (corpus réel, exactitude holdout {:.1}%).",
        acc * 100.0
    )?;
    writeln!(out, "const MODELS: &[ClassModel] = &[")?;
    for k in 0..NCLASS {
        writeln!(out, "    ClassModel {{")?;
        writeln!(out, "        class: Class::{},", CLASS_NAMES[k])?;
        writeln!(out, "        bias: {:.4},", w[k][0])?;
        write!(out, "        weights: [")?;
        for j in 0..NFEAT {
            write!(out, "{:.4}", w[k][j + 1])?;
            if j + 1 < NFEAT {
                write!(out, ", ")?;
            }
        }
        writeln!(out, "],")?;
        writeln!(out, "    }},")?;
    }
    writeln!(out, "];")
}

fn synthetic_dataset(per_class: usize) -> Vec<([f64; NFEAT], usize)> {
    let mut rng = Rng::new(0xC0FFEE123);
    let mut train = Vec::with_capacity(per_class * NCLASS);
    for c in 0..NCLASS {
        for _ in 0..per_class {
            train.push((sample_synthetic(c, &mut rng), c));
        }
    }
    train
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let code = run(
        &args,
        &corpus_dir(),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    std::process::exit(code);
}

/// Point d'entrée testable (`args[0]` = nom du programme). Codes : 0 succès,
/// 1 validation échouée, 2 erreur (corpus, extraction).
fn run(args: &[String], corpus: &Path, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if args.len() >= 4 && (args[1] == "--extract" || args[1] == "--extract-dir") {
        let (target, class) = (Path::new(&args[2]), args[3].as_str());
        let r = if args[1] == "--extract" {
            extract_pe(target, class, out)
        } else {
            extract_dir(target, class, out)
        };
        return match r {
            Ok(()) => 0,
            Err(e) => {
                let _ = writeln!(err, "extraction : {e}");
                2
            }
        };
    }

    let use_synthetic = args.iter().any(|a| a == "--synthetic");
    let do_validate = args.iter().any(|a| a == "--validate");

    let train_data = if use_synthetic {
        let _ = writeln!(err, "Mode synthétique (legacy) — graine 0xC0FFEE123");
        synthetic_dataset(1500)
    } else {
        let path = corpus.join("labeled.jsonl");
        let _ = writeln!(err, "Chargement du corpus réel : {}", path.display());
        match load_jsonl(&path) {
            Ok(d) => d,
            Err(e) => {
                let _ = writeln!(err, "corpus labeled.jsonl : {e}");
                return 2;
            }
        }
    };

    if train_data.is_empty() {
        let _ = writeln!(
            err,
            "jeu d'entraînement vide — fournir corpus/labeled.jsonl"
        );
        return 2;
    }

    let w = train(&train_data);
    let holdout = load_jsonl(&corpus.join("holdout.jsonl")).unwrap_or_default();
    let acc = accuracy(&w, &holdout);
    let _ = writeln!(
        err,
        "Exactitude holdout = {:.2}% ({}/{})",
        acc * 100.0,
        (acc * holdout.len() as f64).round() as usize,
        holdout.len()
    );

    if do_validate && acc < 0.70 {
        let _ = writeln!(err, "Échec validation : exactitude holdout < 70 %");
        return 1;
    }

    match print_weights(&w, acc, out) {
        Ok(()) => 0,
        Err(_) => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_labeled_charge() {
        let data = load_jsonl(&corpus_dir().join("labeled.jsonl")).expect("labeled");
        assert!(data.len() >= 40, "corpus trop petit : {}", data.len());
    }

    fn s(v: &[&str]) -> Vec<String> {
        std::iter::once("ml-train")
            .chain(v.iter().copied())
            .map(String::from)
            .collect()
    }

    fn run_capture(args: &[String], corpus: &Path) -> (i32, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(args, corpus, &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oc_mlt_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn entrainement_corpus_reel_valide_et_imprime_les_poids() {
        let (code, out, err) = run_capture(&s(&["--validate"]), &corpus_dir());
        assert_eq!(code, 0, "{err}");
        assert!(out.contains("const MODELS: &[ClassModel]"));
        assert_eq!(out.matches("ClassModel {").count(), NCLASS);
        assert!(err.contains("Exactitude holdout"));
    }

    #[test]
    fn corpus_absent_vide_ou_invalide() {
        let missing = tmp_dir("missing");
        let (code, _, err) = run_capture(&s(&[]), &missing);
        assert_eq!(code, 2);
        assert!(err.contains("labeled.jsonl"));

        let empty = tmp_dir("empty");
        fs::write(empty.join("labeled.jsonl"), "\n{\"class\":\"Inconnue\",\"entropy\":0,\"imports\":0,\"wx_section\":0,\"packer\":0,\"injection\":0,\"network\":0}\n").unwrap();
        let (code, _, err) = run_capture(&s(&[]), &empty);
        assert_eq!(code, 2);
        assert!(err.contains("vide"));

        let bad = tmp_dir("bad");
        fs::write(bad.join("labeled.jsonl"), "{pas du json}\n").unwrap();
        assert_eq!(run_capture(&s(&[]), &bad).0, 2);
        for d in [missing, empty, bad] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[test]
    fn validation_echoue_sous_70_pourcent() {
        // Entraîné sur une seule classe, évalué sur une autre : exactitude nulle.
        let d = tmp_dir("lowacc");
        let line = |c: &str| {
            format!("{{\"class\":\"{c}\",\"entropy\":0.5,\"imports\":0.5,\"wx_section\":0,\"packer\":0,\"injection\":0,\"network\":0}}\n")
        };
        fs::write(d.join("labeled.jsonl"), line("Benign").repeat(5)).unwrap();
        fs::write(d.join("holdout.jsonl"), line("Rat").repeat(3)).unwrap();
        let (code, _, err) = run_capture(&s(&["--validate"]), &d);
        assert_eq!(code, 1, "{err}");
        let (code, out, _) = run_capture(&s(&[]), &d);
        assert_eq!(code, 0);
        assert!(out.contains("exactitude holdout 0.0%"), "{out}");
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn jeu_synthetique_separable() {
        let data = synthetic_dataset(60);
        assert_eq!(data.len(), 60 * NCLASS);
        let w = train(&data);
        assert!(accuracy(&w, &data) > 0.8);
        assert_eq!(accuracy(&w, &[]), 0.0);
        let p = predict(&w, &data[0].0);
        assert!((p.iter().sum::<f64>() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn extraction_d_un_pe_et_d_un_dossier() {
        use pe_analysis::fixtures::{build_pe, FixtureSection, CODE, RWX};
        let d = tmp_dir("extract");
        let pe = build_pe(
            &[
                FixtureSection {
                    name: ".text",
                    characteristics: CODE,
                    data: b"..WriteProcessMemory..CreateRemoteThread..URLDownloadToFileA..",
                },
                FixtureSection {
                    name: ".evil",
                    characteristics: RWX,
                    data: b"x",
                },
            ],
            false,
            b"",
        );
        fs::write(d.join("a.exe"), &pe).unwrap();
        fs::write(d.join("b.exe"), &pe).unwrap();
        fs::create_dir_all(d.join("sous-dossier")).unwrap();

        let one = d.join("a.exe").display().to_string();
        let (code, out, _) = run_capture(&s(&["--extract", &one, "Rat"]), &corpus_dir());
        assert_eq!(code, 0);
        let sample: LabeledSample = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(sample.class, "Rat");
        assert_eq!(sample.injection, 1.0);
        assert_eq!(sample.network, 1.0);
        assert_eq!(sample.wx_section, 1.0);
        assert!(sample.packer > 0.0);

        let dir = d.display().to_string();
        let (code, out, _) = run_capture(&s(&["--extract-dir", &dir, "Dropper"]), &corpus_dir());
        assert_eq!(code, 0);
        assert_eq!(out.lines().count(), 2);

        let (code, _, err) =
            run_capture(&s(&["--extract", "/oc/absent.exe", "Rat"]), &corpus_dir());
        assert_eq!(code, 2);
        assert!(err.contains("extraction"));
        let (code, _, _) = run_capture(&s(&["--extract-dir", "/oc/absent", "Rat"]), &corpus_dir());
        assert_eq!(code, 2);
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn rng_bornes() {
        let mut r = Rng::new(7);
        for _ in 0..100 {
            let u = r.uniform(0.2, 0.4);
            assert!((0.2..0.4).contains(&u));
            let b = r.bernoulli(0.5);
            assert!(b == 0.0 || b == 1.0);
        }
        let mut sink = Vec::new();
        print_weights(&[[0.0; NFEAT + 1]; NCLASS], 1.0, &mut sink).unwrap();
        assert!(String::from_utf8(sink).unwrap().contains("100.0%"));
    }

    #[test]
    fn holdout_validation_min_70pct() {
        let train_data = load_jsonl(&corpus_dir().join("labeled.jsonl")).unwrap();
        let holdout = load_jsonl(&corpus_dir().join("holdout.jsonl")).unwrap();
        let w = train(&train_data);
        let acc = accuracy(&w, &holdout);
        assert!(
            acc >= 0.70,
            "exactitude holdout insuffisante : {:.1}%",
            acc * 100.0
        );
    }
}
