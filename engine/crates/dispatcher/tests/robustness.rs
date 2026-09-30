//! Harnais de robustesse (durcissement, Phase 9).
//!
//! Objectif : garantir qu'**aucune entrée malformée ou aléatoire ne provoque
//! de panic** dans les parseurs hostiles (PE, YARA, archives) ni dans le
//! pipeline complet. Le parsing de fichiers attaquants est la première cible
//! d'un adversaire ; un panic = déni de service. Le succès du test = absence
//! de panic sur des milliers de cas.

use std::io::Write;

use dispatcher::{detect_kind, Dispatcher};

/// Générateur pseudo-aléatoire déterministe (LCG) — pas de dépendance externe,
/// reproductible pour le débogage.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = (self.next_u64() as usize) % (max_len + 1);
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            v.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        v.truncate(len);
        v
    }
}

fn tmp(data: &[u8], idx: u64, ext: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("oc_fuzz_{}_{}.{ext}", std::process::id(), idx));
    std::fs::File::create(&p).unwrap().write_all(data).unwrap();
    p
}

#[test]
fn parseurs_ne_paniquent_jamais() {
    let mut rng = Lcg::new(0xDEADBEEF);
    let disp = Dispatcher::new();

    for i in 0..3000u64 {
        let buf = rng.bytes(2048);

        // 1) Parseur PE sur octets arbitraires.
        let _ = pe_analysis::analyze_bytes(&buf);

        // 2) Parseur de règles YARA sur texte arbitraire.
        let text = String::from_utf8_lossy(&buf);
        let _ = yara_engine::parse_rules(&text);

        // 3) detect_kind ne doit jamais paniquer.
        let _ = detect_kind(&buf, std::path::Path::new("x.bin"));

        // 4) Pipeline complet via fichier temporaire.
        let p = tmp(&buf, i, "bin");
        let _ = disp.scan_path(&p);
        let _ = std::fs::remove_file(&p);
    }
}

#[test]
fn entetes_malformes_cibles() {
    let disp = Dispatcher::new();
    let mut rng = Lcg::new(0x1234_5678);

    for i in 0..500u64 {
        let mut tail = rng.bytes(512);

        // PE malformé : MZ + e_lfanew délirant + garbage.
        let mut pe = vec![b'M', b'Z'];
        pe.extend(std::iter::repeat(0u8).take(0x3A));
        pe.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x7F]); // e_lfanew énorme
        pe.append(&mut tail.clone());
        let p = tmp(&pe, 100000 + i, "exe");
        let _ = disp.scan_path(&p);
        let _ = std::fs::remove_file(&p);

        // ZIP malformé : signature locale + garbage.
        let mut zip = vec![b'P', b'K', 0x03, 0x04];
        zip.append(&mut tail);
        let z = tmp(&zip, 200000 + i, "zip");
        let _ = disp.scan_path(&z);
        let _ = std::fs::remove_file(&z);

        // Règle YARA tronquée.
        let _ = yara_engine::parse_rules("rule x { strings: $a = \"abc");
        let _ = yara_engine::parse_rules("rule { condition: }");
        let _ = yara_engine::parse_rules("}}}{{{ of them them");
    }
}
