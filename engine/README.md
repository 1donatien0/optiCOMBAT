# optiCOMBAT — cœur moteur (Rust)

Cœur de détection antivirus en Rust, exposé via une frontière FFI stable. Workspace Cargo modulaire : chaque moteur renvoie un **résultat normalisé** (`EngineResult`) consommé par un corrélateur central.

### Pipeline de détection

```text
Fichier → SHA-256 → base de hachage (reputation / MalwareBazaar)
        → extraction / archives → ClamAV
        → règles YARA locales
        → heuristique PE / classifieur ML
        → IOC URL/domaine/IP  (ioc-engine : URLhaus + ThreatFox)
        → verdict + score de confiance
```

Les signatures ClamAV et les règles YARA sont mises à jour par le shell (`FreshclamUpdater`, `YaraForgeUpdater`). Les exports MalwareBazaar, URLhaus et ThreatFox sont téléchargés par le shell (`ThreatIntelFeedUpdater`, Auth-Key abuse.ch obligatoire) dans un dossier que le moteur charge via `ThreatIntelBundle::load_dir` : `Dispatcher::new` lit `OPTICOMBAT_THREAT_INTEL_DIR`, `Dispatcher::with_threat_intel_dir` un dossier explicite, la FFI expose `opticombat_load_threat_intel(dir)` et `opticombat_threat_intel_stats()`, la CLI `--intel <dossier>`. Fichiers reconnus : `malwarebazaar.csv`, `malwarebazaar_sha256.txt`, `urlhaus.csv`, `urlhaus.txt`, `threatfox.csv` (512 Mio max par fichier, 2 millions d'entrées max par flux). Sans dossier, le moteur IOC reste vide. Le cœur Rust ne fait aucun appel réseau. L'étape IOC ne concerne que les scripts et les fichiers de type inconnu.

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
| `reputation` | Whitelist / blacklist / source cloud par hash + `MalwareBazaarDb` (CSV ou liste de hashes). |
| `ioc-engine` | Vérification d'IOC réseau hors-ligne : URLs, domaines, IPv4 (URLhaus + ThreatFox) ; extraction depuis scripts et fichiers texte. |
| `quarantine` | AES-256-GCM + SHA-256, restauration vérifiée. |
| `updater` | Manifestes signés ed25519. |
| `memory-scanner` | Shellcode + YARA sur buffer. |
| `platform` | `KeyProvider`, `MemoryRegionProvider`. |
| `scan-service` | Orchestration scan + quarantaine automatique. |
| `opticombat-cli` | Binaire `opticombat <chemin>`. |
| `opticombat-ffi` | Cdylib C ABI consommé par optiCOMBAT (P/Invoke). |
| `ml-train` | Entraînement du classifieur (corpus étiqueté dans `ml-train/corpus/`). |
| `bench` | Banc de performance (débit, latence). |
| `qualify` | Binaire `oc-qualify` du panel de qualification (`scripts/qualify-detection.ps1`). |

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
# → target/release/opticombat_engine.dll (Windows)
```

Déploiement Windows : `scripts/build-engine.ps1` copie `opticombat_engine.dll` à côté de `optiCombat.exe` (sortie WinUI et publish) ; l’installateur l’embarque si elle existe.

En CI (`.github/workflows/ci.yml`) : `cargo test --workspace` sous Windows et `cargo audit` ; CodeQL analyse le code Rust. La feature `windows-platform` (DPAPI, `ReadProcessMemory`) n’est pas activée par défaut et n’est donc pas testée en CI.

## Pont C#

Intégration livrée : `optiCombat.Application/Services/OptiCombat/` — `OptiCombatScanEngine.cs` (P/Invoke + `IScanEngine`) et `OptiCombatServiceRegistration.cs` (`UseOptiCombatEngine()`, appelé dans `ServiceRegistration`, repli ClamAV + YARA si la DLL est absente ou bloquée).

`ffi-demo/` garde les exemples de référence : `opticombat.h`, `smoke.c`, `OptiCombatNative.cs`, `OptiCombatScanner.cs`.
