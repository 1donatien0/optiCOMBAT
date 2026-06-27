# optiCOMBAT — cœur moteur (Rust)

Cœur de détection antivirus en Rust, exposé via une frontière FFI stable. Workspace Cargo modulaire : chaque moteur renvoie un **résultat normalisé** (`EngineResult`) consommé par un corrélateur central.

## Crates

| Crate | Rôle |
|---|---|
| `engine-core` | Traits et types partagés (`Engine`, `SignatureEngine`, `EngineResult`, `Severity`, `Verdict`, `ScanContext`). |
| `dispatcher` | Routage moteurs, archives ZIP récursives, corrélation, court-circuit réputation. |
| `clamav` | Client `clamd` (INSTREAM/PING) avec repli EICAR hors-ligne. |
| `yara-engine` | Chargeur/évaluateur de règles `.yar`. |
| `pe-analysis` | Parseur PE (goblin) : sections, W^X, entropie, imports. |
| `heuristics` | Règles pondérées → score → bandes de risque. |
| `sandbox` | Indicateurs comportementaux et séquences d’attaque. |
| `ml-classifier` | Features PE → softmax → familles. |
| `correlator` | Fusion des résultats et seuils configurables. |
| `reputation` | Whitelist / blacklist / source cloud par hash. |
| `quarantine` | AES-256-GCM + SHA-256, restauration vérifiée. |
| `updater` | Manifestes signés ed25519. |
| `memory-scanner` | Shellcode + YARA sur buffer. |
| `platform` | `KeyProvider`, `MemoryRegionProvider`. |
| `scan-service` | Orchestration scan + quarantaine automatique. |
| `opticombat-cli` | Binaire `opticombat <chemin>`. |
| `opticombat-ffi` | Cdylib C ABI consommé par optiCOMBAT (P/Invoke). |

## Build & test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

Cdylib FFI :

```bash
cargo build -p opticombat-ffi --release
# → target/release/opticombat.dll (Windows)
```

Déploiement Windows : `scripts/build-engine.ps1` copie `opticombat.dll` à côté de `optiCombat.exe`.

## Pont C#

Voir `ffi-demo/` : `opticombat.h`, `smoke.c`, `OptiCombatNative.cs`, `OptiCombatScanner.cs` — intégrés dans `optiCombat/Services/OptiCombat/`.
