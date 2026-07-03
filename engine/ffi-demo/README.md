# Pont FFI — optiCOMBAT ↔ optiCombat.Service (Phase 3)

Ce dossier montre comment le service C# existant (`optiCombat.Service`) appelle le
**cœur moteur Rust** sans réécrire l'UI (WinUI 3 / WPF legacy), via une frontière **C ABI** stable.

## Composants

| Fichier | Rôle |
|---|---|
| `opticombat.h` | En-tête C de l'ABI (verdict, scan, JSON, libération mémoire). |
| `smoke.c` | Test C : appelle la bibliothèque, prouve la consommation hors-Rust. |
| `OptiCombatNative.cs` | Exemple P/Invoke à intégrer dans `optiCombat.Service/Interop/`. |

## Bibliothèque

La crate `engine/crates/opticombat-ffi` produit :
- `opticombat.dll` (Windows) / `libopticombat.so` (Linux) — `crate-type = ["cdylib"]`.

Build :

```bash
cd engine
cargo build -p opticombat-ffi --release
# → engine/target/release/opticombat.dll (ou libopticombat.so)
```

## Contrat mémoire

- Les chaînes de `opticombat_scan_json` sont libérées par `opticombat_string_free`
  (côté C#, `OptiCombatNative.ScanJson` le fait dans un `finally`).
- `opticombat_version` renvoie une chaîne statique : ne pas libérer.
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
le test d'intégration `engine/crates/opticombat-ffi/tests/service_flow.rs`, et
par le job CI `ffi-native` (compile `smoke.c`, le lie au cdylib, scanne EICAR).
