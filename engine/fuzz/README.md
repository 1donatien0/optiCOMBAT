# Fuzzing — optiCOMBAT

Harnais [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) ciblant
les parseurs de fichiers hostiles, première surface d'attaque d'un antivirus.

## Cibles

| Cible | Couvre |
|---|---|
| `pe_parse` | `pe_analysis::analyze_bytes` (en-têtes PE, sections, imports). |
| `yara_parse` | `yara_engine::parse_rules` (grammaire des règles). |

## Lancer

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run pe_parse     # boucle jusqu'à un crash
cargo +nightly fuzz run yara_parse -- -max_total_time=60
```

Le harnais déterministe `crates/dispatcher/tests/robustness.rs` couvre le même
objectif (zéro panic) en CI stable ; cargo-fuzz va plus loin en explorant
l'espace d'entrée par couverture, à activer en intégration continue planifiée.
