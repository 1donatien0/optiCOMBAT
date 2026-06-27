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

fn main() {
    let cases = [
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

    let dir = std::env::temp_dir().join(format!("oc_bench_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("création répertoire bench");
    let mut rng = Rng::new(0xB0BAFE77);
    let disp = Dispatcher::new();

    println!("== Banc de performance optiCombat ==");
    println!(
        "{:<10} {:>7} {:>12} {:>14} {:>14}",
        "Taille", "N", "Débit Mo/s", "Latence moy.", "Latence p95"
    );

    let mut grand_bytes = 0u64;
    let mut grand_nanos = 0u128;

    for c in &cases {
        // Pré-génère les fichiers (hors mesure).
        let mut paths = Vec::with_capacity(c.count);
        let mut buf = vec![0u8; c.size];
        for i in 0..c.count {
            rng.fill(&mut buf);
            let p = dir.join(format!("{}_{}.bin", c.label.replace(' ', ""), i));
            std::fs::write(&p, &buf).unwrap();
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
        let mbps = (bytes as f64 / (1024.0 * 1024.0)) / total.as_secs_f64();

        println!(
            "{:<10} {:>7} {:>12.1} {:>12.3}ms {:>12.3}ms",
            c.label, c.count, mbps, mean_ms, p95_ms
        );

        for p in &paths {
            let _ = std::fs::remove_file(p);
        }
    }

    let overall = (grand_bytes as f64 / (1024.0 * 1024.0)) / (grand_nanos as f64 / 1e9);
    println!("------------------------------------------------------------");
    println!(
        "Débit global : {overall:.1} Mo/s sur {} Mio",
        grand_bytes / (1024 * 1024)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
