//! oc-bench — banc de performance du pipeline de scan (débit Mo/s, latence).
//!
//! Génère des fichiers synthétiques de tailles variées, les scanne via le
//! `Dispatcher` complet (réputation → moteurs → corrélation) et mesure le
//! **débit** et la **latence par fichier**. Donne un budget de performance
//! réel et reproductible (graine fixe).

use std::time::Instant;

use dispatcher::Dispatcher;

/// RNG déterministe (LCG) pour des contenus reproductibles.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.0 >> 33) as u8;
        }
    }
}

struct Case {
    label: &'static str,
    size: usize,
    count: usize,
}

/// Mesure d'un cas (débit et latences).
#[derive(Debug)]
struct CaseResult {
    label: &'static str,
    count: usize,
    bytes: u64,
    mbps: f64,
    mean_ms: f64,
    p95_ms: f64,
}

const DEFAULT_CASES: [Case; 3] = [
    Case {
        label: "4 KiB",
        size: 4 * 1024,
        count: 500,
    },
    Case {
        label: "64 KiB",
        size: 64 * 1024,
        count: 200,
    },
    Case {
        label: "1 MiB",
        size: 1024 * 1024,
        count: 40,
    },
];

fn main() {
    let dir = std::env::temp_dir().join(format!("oc_bench_{}", std::process::id()));
    let disp = Dispatcher::new();
    match run(&DEFAULT_CASES, &dir, &disp, &mut std::io::stdout().lock()) {
        Ok(results) => println!("{}", slowest_case(&results)),
        Err(e) => {
            eprintln!("bench : {e}");
            std::process::exit(1);
        }
    }
}

/// Résumé du cas le plus lent (latence p95), pour repérer une régression d'un coup d'œil.
fn slowest_case(results: &[CaseResult]) -> String {
    match results
        .iter()
        .max_by(|a, b| a.p95_ms.total_cmp(&b.p95_ms))
    {
        Some(r) => format!(
            "Cas le plus lent : {} ({} fichiers, {} octets) — p95 {:.3} ms, moyenne {:.3} ms, {:.1} Mo/s",
            r.label, r.count, r.bytes, r.p95_ms, r.mean_ms, r.mbps
        ),
        None => "Aucun cas mesuré.".to_string(),
    }
}

/// Exécute les cas et imprime le tableau ; renvoie les mesures (pour les tests).
fn run(
    cases: &[Case],
    dir: &std::path::Path,
    disp: &Dispatcher,
    out: &mut dyn std::io::Write,
) -> std::io::Result<Vec<CaseResult>> {
    std::fs::create_dir_all(dir)?;
    let mut rng = Rng::new(0xB0BAFE77);

    writeln!(out, "== Banc de performance optiCombat ==")?;
    writeln!(
        out,
        "{:<10} {:>7} {:>12} {:>14} {:>14}",
        "Taille", "N", "Débit Mo/s", "Latence moy.", "Latence p95"
    )?;

    let mut results = Vec::with_capacity(cases.len());
    let mut grand_bytes = 0u64;
    let mut grand_nanos = 0u128;

    for c in cases {
        if c.count == 0 {
            continue;
        }
        // Pré-génère les fichiers (hors mesure).
        let mut paths = Vec::with_capacity(c.count);
        let mut buf = vec![0u8; c.size];
        for i in 0..c.count {
            rng.fill(&mut buf);
            let p = dir.join(format!("{}_{}.bin", c.label.replace(' ', ""), i));
            std::fs::write(&p, &buf)?;
            paths.push(p);
        }

        // Mesure : un timing par fichier.
        let mut latencies = Vec::with_capacity(c.count);
        let t0 = Instant::now();
        for p in &paths {
            let s = Instant::now();
            let _ = disp.scan_path(p);
            latencies.push(s.elapsed().as_nanos());
        }
        let total = t0.elapsed();
        let bytes = (c.size * c.count) as u64;
        grand_bytes += bytes;
        grand_nanos += total.as_nanos();

        latencies.sort_unstable();
        let mean_ms = latencies.iter().sum::<u128>() as f64 / latencies.len() as f64 / 1e6;
        let p95_ms = latencies[(latencies.len() * 95 / 100).min(latencies.len() - 1)] as f64 / 1e6;
        let secs = total.as_secs_f64().max(f64::MIN_POSITIVE);
        let mbps = (bytes as f64 / (1024.0 * 1024.0)) / secs;

        writeln!(
            out,
            "{:<10} {:>7} {:>12.1} {:>12.3}ms {:>12.3}ms",
            c.label, c.count, mbps, mean_ms, p95_ms
        )?;

        for p in &paths {
            let _ = std::fs::remove_file(p);
        }
        results.push(CaseResult {
            label: c.label,
            count: c.count,
            bytes,
            mbps,
            mean_ms,
            p95_ms,
        });
    }

    let overall = if grand_nanos == 0 {
        0.0
    } else {
        (grand_bytes as f64 / (1024.0 * 1024.0)) / (grand_nanos as f64 / 1e9)
    };
    writeln!(
        out,
        "------------------------------------------------------------"
    )?;
    writeln!(
        out,
        "Débit global : {overall:.1} Mo/s sur {} Mio",
        grand_bytes / (1024 * 1024)
    )?;
    let _ = std::fs::remove_dir_all(dir);
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_deterministe() {
        let (mut a, mut b) = (Rng::new(1), Rng::new(1));
        let (mut x, mut y) = ([0u8; 16], [0u8; 16]);
        a.fill(&mut x);
        b.fill(&mut y);
        assert_eq!(x, y);
        assert_ne!(x, [0u8; 16]);
    }

    #[test]
    fn petit_banc_mesure_et_nettoie() {
        let dir = std::env::temp_dir().join(format!("oc_bench_test_{}", std::process::id()));
        let cases = [
            Case {
                label: "1 KiB",
                size: 1024,
                count: 3,
            },
            Case {
                label: "vide",
                size: 16,
                count: 0,
            },
        ];
        let mut out = Vec::new();
        let r = run(&cases, &dir, &Dispatcher::new(), &mut out).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].label, "1 KiB");
        assert_eq!(r[0].count, 3);
        assert_eq!(r[0].bytes, 3072);
        assert!(r[0].mbps > 0.0 && r[0].mean_ms >= 0.0 && r[0].p95_ms >= 0.0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Débit global"), "{text}");
        assert!(!dir.exists(), "le dossier temporaire doit être supprimé");
        assert_eq!(DEFAULT_CASES.len(), 3);
        assert!(slowest_case(&r).starts_with("Cas le plus lent : 1 KiB"));
        assert_eq!(slowest_case(&[]), "Aucun cas mesuré.");
    }

    #[test]
    fn dossier_impossible_a_creer() {
        let file = std::env::temp_dir().join(format!("oc_bench_file_{}", std::process::id()));
        std::fs::write(&file, b"x").unwrap();
        let mut out = Vec::new();
        assert!(run(
            &DEFAULT_CASES,
            &file.join("sub"),
            &Dispatcher::new(),
            &mut out
        )
        .is_err());
        let _ = std::fs::remove_file(file);
    }
}
