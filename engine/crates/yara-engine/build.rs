//! Embarque les règles du dépôt sous forme **masquée** (XOR) dans le binaire.
//!
//! Les règles contiennent en clair des chaînes « malveillantes » (EICAR,
//! messages de rançon, commandes PowerShell…). Embarquées telles quelles via
//! `include_str!`, elles faisaient détecter `opticombat_engine.dll` comme malveillante
//! par son propre moteur (auto-détection) et par les antivirus tiers.

use std::path::PathBuf;

/// Clé de masquage — doit rester identique à `RULES_MASK` dans `lib.rs`.
const MASK: u8 = 0xA5;

const RULE_FILES: &[&str] = &[
    "test_rules.yar",
    "malware_signatures.yar",
    "suspicious_strings.yar",
];

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let rules_dir = manifest.join("../../../runtime/rules");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    for name in RULE_FILES {
        let src = rules_dir.join(name);
        println!("cargo:rerun-if-changed={}", src.display());
        let data = std::fs::read(&src)
            .unwrap_or_else(|e| panic!("règles YARA introuvables ({}): {e}", src.display()));
        let masked: Vec<u8> = data.iter().map(|b| b ^ MASK).collect();
        std::fs::write(out_dir.join(format!("{name}.masked")), masked).unwrap();
    }
}
