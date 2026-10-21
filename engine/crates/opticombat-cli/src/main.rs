//! opticombat — CLI de démonstration du cœur moteur (feuille de route : GUI/CLI).
//!
//! Usage : opticombat <chemin> [<chemin>...]
//! Scanne chaque cible via le dispatcher et imprime le verdict corrélé.
//! Code de sortie : 0 = propre, 1 = suspect, 2 = malveillant, 3 = erreur d'usage.

use std::path::Path;
use std::process::ExitCode;

use dispatcher::Dispatcher;
use engine_core::Verdict;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: opticombat <chemin> [<chemin>...]");
        return ExitCode::from(3);
    }

    let dispatcher = Dispatcher::new();
    let mut worst = Verdict::Clean;

    for arg in &args {
        let path = Path::new(arg);
        match dispatcher.scan_path(path) {
            Ok(decision) => {
                println!("[{}] {}", arg, decision.summary);
                for r in &decision.reasons {
                    println!(
                        "    - {} :: {} (+{}) {}",
                        r.engine, r.name, r.score, r.explanation
                    );
                }
                worst = worst_of(worst, decision.verdict);
            }
            Err(e) => {
                eprintln!("[{arg}] erreur: {e}");
                worst = worst_of(worst, Verdict::Suspicious);
            }
        }
    }

    match worst {
        Verdict::Clean | Verdict::Inconclusive => ExitCode::from(0),
        Verdict::Suspicious => ExitCode::from(1),
        Verdict::Malicious => ExitCode::from(2),
    }
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
