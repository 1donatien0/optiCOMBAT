# Pont FFI — optiCOMBAT ↔ cœur Rust (exemples de référence)

Ce dossier montre comment le code C# appelle le **cœur moteur Rust** via une frontière
**C ABI** stable. L’intégration effectivement livrée se trouve dans
`optiCombat.Application/Services/OptiCombat/` (voir [integration/README.md](integration/README.md)).

## Composants

| Fichier | Rôle |
|---|---|
| `opticombat.h` | En-tête C de l'ABI (verdict, scan, JSON, libération mémoire). |
| `smoke.c` | Test C : appelle la bibliothèque, prouve la consommation hors-Rust. |
| `OptiCombatNative.cs` | Exemple P/Invoke minimal. |
| `OptiCombatScanner.cs` | Exemple d’enrobage injectable (`IOptiCombatScanner`). |

## Bibliothèque

La crate `engine/crates/opticombat-ffi` produit :
- `opticombat_engine.dll` (Windows) / `libopticombat_engine.so` (Linux) — `crate-type = ["cdylib"]`.

Build :

```bash
cd engine
cargo build -p opticombat-ffi --release
# → engine/target/release/opticombat_engine.dll (ou libopticombat_engine.so)
```

## Contrat mémoire

- Les chaînes de `opticombat_scan_json` sont libérées par `opticombat_string_free`
  (côté C#, `OptiCombatNative.ScanJson` le fait dans un `finally`).
- `opticombat_version` renvoie une chaîne statique : ne pas libérer.
- `opticombat_threat_intel_stats` renvoie un JSON à libérer par `opticombat_string_free`.

## Threat intel hors-ligne

`opticombat_load_threat_intel(dir)` lit les exports abuse.ch déposés dans `dir`
(`malwarebazaar.csv`, `malwarebazaar_sha256.txt`, `urlhaus.csv`, `urlhaus.txt`,
`threatfox.csv`) et remplace le dispatcher partagé : MalwareBazaar alimente la
réputation par hash, URLhaus et ThreatFox le moteur IOC. Renvoie le nombre
d'entrées chargées, ou `-1` si le dossier est invalide. Aucun accès réseau : le
téléchargement est fait par `ThreatIntelFeedUpdater` côté C#. La variable
d'environnement `OPTICOMBAT_THREAT_INTEL_DIR` produit le même effet au premier
appel, et la CLI accepte `--intel <dossier>`.
- Sûreté : chaque point d'entrée Rust est enveloppé dans `catch_unwind`, et le
  profil release est `panic = "abort"` — aucun panic ne traverse la frontière.

## Intégration côté service

```csharp
var verdict = OptiCombatNative.ScanPath(@"C:\chemin\fichier.exe");
if (verdict == OptiCombatVerdict.Malicious)
{
    var details = OptiCombatNative.ScanJson(@"C:\chemin\fichier.exe");
    // → router vers QuarantineManager existant, journaliser, notifier l'UI.
}
```

À terme, `ProtectionServiceHost` route les requêtes RTP vers ce cœur au lieu des
moteurs managés, derrière l'IPC déjà authentifié.

## Intégration de haut niveau (Phase 6)

`OptiCombatScanner.cs` enrobe le P/Invoke derrière `IOptiCombatScanner`
(injectable), parse le JSON (`score`, `severity`) et expose un
`OptiCombatResult`. Enregistrement DI :

```csharp
services.AddSingleton<IOptiCombatScanner, OptiCombatScanner>();
```

Le flux exact (scan_path → scan_json → string_free) est couvert côté Rust par
le test d'intégration `engine/crates/opticombat-ffi/tests/service_flow.rs`
(exécuté par `cargo test --workspace` en CI). `smoke.c` se compile et se lance
à la main ; il n’y a pas de job CI dédié.
