# optiCOMBAT — cœur moteur (Rust)

Cœur de détection antivirus en Rust, conçu pour remplacer progressivement les
moteurs managés d'optiCOMBAT derrière une frontière FFI stable. Workspace Cargo
modulaire : chaque moteur renvoie un **résultat normalisé** (`EngineResult`)
consommé par un corrélateur central.

## Crates

| Crate | Rôle |
|---|---|
| `engine-core` | Traits et types partagés (`Engine`, `SignatureEngine`, `EngineResult`, `Severity`, `Verdict`, `ScanContext`). |
| `dispatcher` | Détection de type, routage vers les moteurs pertinents, déballage d'archives ZIP récursif, corrélation, court-circuit réputation. |
| `clamav` | Backend composite : client `clamd` (INSTREAM/PING) avec repli EICAR hors-ligne. |
| `yara-engine` | Chargeur/évaluateur de règles `.yar` (règles du dépôt embarquées). |
| `pe-analysis` | Parseur PE (goblin) : sections, characteristics W^X, entropie, imports IAT. |
| `heuristics` | Table de règles pondérées → score → bandes (OK/Suspicious/Danger/Malware). |
| `sandbox` | Analyse comportementale : indicateurs d'API + séquence téléchargement→exécution. |
| `ml-classifier` | Features PE → softmax → familles (Benign/Ransomware/RAT/Dropper). |
| `correlator` | Fusion des résultats → décision explicable, politique de seuils configurable. |
| `reputation` | Réputation par hash : whitelist (anti faux-positif) + blacklist + source cloud abstraite. |
| `quarantine` | AES-256-GCM (nonce/fichier + tag) + SHA-256, restauration vérifiée. |
| `updater` | Mises à jour signées : manifeste ed25519 + SHA-256 par charge utile. |
| `memory-scanner` | Scan de buffer mémoire : indicateurs shellcode (GetPC, PEB) + YARA. |
| `platform` | Abstraction plateforme : `KeyProvider` (clé maîtresse), `MemoryRegionProvider`. |
| `scan-service` | Façade d'orchestration : scan + mise en quarantaine automatique. |
| `opticombat-cli` | Binaire `opticombat <chemin>`. |
| `opticombat-ffi` | Frontière C ABI (cdylib) consommée par `optiCombat.Service` (P/Invoke). |

## Build & test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

Le cdylib FFI (consommé par C#) :

```bash
cargo build -p opticombat-ffi --release
# → target/release/opticombat.dll (Windows) / libopticombat.so (Linux)
```

## Pont C# ↔ Rust

Voir `ffi-demo/` : en-tête `opticombat.h`, test C `smoke.c`, et les classes
P/Invoke `OptiCombatNative.cs` / `OptiCombatScanner.cs` prêtes à intégrer dans
`optiCombat.Service/Interop/`.

## Intégration plateforme (Windows)

Deux pièces restent spécifiques à la plateforme et se branchent derrière les
traits de `platform` :

- **DPAPI** : envelopper la clé maîtresse de quarantaine (déjà disponible côté
  C# via `ProtectedData`, comme dans `QuarantineManager`).
- **`ReadProcessMemory`** : alimenter `memory-scanner` avec les régions des
  processus vivants via un `MemoryRegionProvider` Windows.
