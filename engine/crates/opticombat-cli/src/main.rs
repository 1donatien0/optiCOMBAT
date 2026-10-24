//! opticombat — CLI de démonstration du cœur moteur (feuille de route : GUI/CLI).
//!
//! Usage : opticombat [--intel <dossier>] <chemin> [<chemin>...]
//! Scanne chaque cible via le dispatcher et imprime le verdict corrélé.
//! `--intel` charge les feeds abuse.ch déposés dans un dossier local
//! (MalwareBazaar, URLhaus, ThreatFox — voir `dispatcher::threat_intel`).
//! Code de sortie : 0 = propre, 1 = suspect, 2 = malveillant, 3 = erreur d'usage.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use dispatcher::Dispatcher;
use engine_core::Verdict;

const USAGE: &str = "usage: opticombat [--intel <dossier>] <chemin> [<chemin>...]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(
        &args,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    ExitCode::from(code)
}

/// Arguments analysés.
#[derive(Debug, PartialEq, Eq)]
struct CliArgs {
    intel: Option<PathBuf>,
    targets: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<CliArgs, String> {
    let mut intel = None;
    let mut targets = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--intel" => {
                let dir = it.next().ok_or("--intel attend un dossier")?;
                intel = Some(PathBuf::from(dir));
            }
            "-h" | "--help" => return Err(String::new()),
            _ => targets.push(a.clone()),
        }
    }
    if targets.is_empty() {
        return Err(String::new());
    }
    Ok(CliArgs { intel, targets })
}

/// Point d'entrée testable : renvoie le code de sortie.
fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(msg) => {
            if !msg.is_empty() {
                let _ = writeln!(err, "{msg}");
            }
            let _ = writeln!(err, "{USAGE}");
            return 3;
        }
    };

    let dispatcher = match &parsed.intel {
        Some(dir) if !dir.is_dir() => {
            let _ = writeln!(
                err,
                "dossier de threat intel introuvable : {}",
                dir.display()
            );
            return 3;
        }
        Some(dir) => {
            let d = Dispatcher::with_threat_intel_dir(dir);
            let s = d.threat_intel_stats();
            let _ = writeln!(
                out,
                "threat intel : {} hash MalwareBazaar, {} URL URLhaus, {} IOC ThreatFox",
                s.malwarebazaar_hashes, s.urlhaus_urls, s.threatfox_iocs
            );
            d
        }
        None => Dispatcher::new(),
    };

    let mut worst = Verdict::Clean;
    for arg in &parsed.targets {
        match dispatcher.scan_path(Path::new(arg)) {
            Ok(decision) => {
                let _ = writeln!(out, "[{}] {}", arg, decision.summary);
                for r in &decision.reasons {
                    let _ = writeln!(
                        out,
                        "    - {} :: {} (+{}) {}",
                        r.engine, r.name, r.score, r.explanation
                    );
                }
                worst = worst_of(worst, decision.verdict);
            }
            Err(e) => {
                let _ = writeln!(err, "[{arg}] erreur: {e}");
                worst = worst_of(worst, Verdict::Suspicious);
            }
        }
    }
    exit_code(worst)
}

fn exit_code(v: Verdict) -> u8 {
    rank(v)
}

fn rank(v: Verdict) -> u8 {
    match v {
        Verdict::Clean => 0,
        Verdict::Inconclusive => 0,
        Verdict::Suspicious => 1,
        Verdict::Malicious => 2,
    }
}

fn worst_of(a: Verdict, b: Verdict) -> Verdict {
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn tmp_file(data: &[u8], ext: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "oc_cli_{}_{}.{ext}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, data).unwrap();
        p
    }

    fn run_capture(args: &[String]) -> (u8, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(args, &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn sans_argument_affiche_l_usage() {
        let (code, _, err) = run_capture(&[]);
        assert_eq!(code, 3);
        assert!(err.contains("usage:"));
        let (code, _, _) = run_capture(&s(&["--help"]));
        assert_eq!(code, 3);
    }

    #[test]
    fn intel_sans_dossier_est_une_erreur_d_usage() {
        let (code, _, err) = run_capture(&s(&["--intel"]));
        assert_eq!(code, 3);
        assert!(err.contains("--intel attend un dossier"));
    }

    #[test]
    fn intel_dossier_introuvable() {
        let (code, _, err) = run_capture(&s(&["--intel", "/oc/inexistant", "x"]));
        assert_eq!(code, 3);
        assert!(err.contains("introuvable"));
    }

    #[test]
    fn analyse_propre_puis_fichier_absent() {
        let p = tmp_file(b"texte banal", "txt");
        let (code, out, _) = run_capture(&s(&[p.to_str().unwrap()]));
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("Clean") || out.contains("propre"), "{out}");
        let (code, _, err) = run_capture(&s(&["/oc/absent.bin"]));
        assert_eq!(code, 1);
        assert!(err.contains("erreur"));
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn intel_charge_et_detecte_un_hash() {
        let payload = b"cli malwarebazaar opticombat payload";
        let sha = reputation_sha(payload);
        let dir = std::env::temp_dir().join(format!("oc_cli_ti_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("malwarebazaar_sha256.txt"), format!("{sha}\n")).unwrap();
        let p = tmp_file(payload, "bin");
        let (code, out, _) =
            run_capture(&s(&["--intel", dir.to_str().unwrap(), p.to_str().unwrap()]));
        assert_eq!(code, 2, "{out}");
        assert!(out.contains("1 hash MalwareBazaar"), "{out}");
        assert!(out.contains("reputation :: MalwareBazaar:Malware"), "{out}");
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pire_verdict_l_emporte() {
        assert_eq!(
            worst_of(Verdict::Clean, Verdict::Malicious),
            Verdict::Malicious
        );
        assert_eq!(
            worst_of(Verdict::Malicious, Verdict::Suspicious),
            Verdict::Malicious
        );
        assert_eq!(
            worst_of(Verdict::Inconclusive, Verdict::Clean),
            Verdict::Inconclusive
        );
        assert_eq!(exit_code(Verdict::Suspicious), 1);
    }

    #[test]
    fn parse_args_conserve_l_ordre_des_cibles() {
        let p = parse_args(&s(&["a", "--intel", "d", "b"])).unwrap();
        assert_eq!(p.intel, Some(PathBuf::from("d")));
        assert_eq!(p.targets, vec!["a".to_string(), "b".to_string()]);
    }

    fn reputation_sha(data: &[u8]) -> String {
        reputation::ReputationEngine::sha256_hex(data)
    }
}
