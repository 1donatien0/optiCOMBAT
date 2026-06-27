# Intégration optiCOMBAT ↔ optiCombat.Service (à coller)

Fichiers **prêts à intégrer** dans le projet C# optiCOMBAT. Ils ne sont pas inclus
dans le build par défaut pour ne pas imposer la DLL native ni risquer la chaîne
`TreatWarningsAsErrors`. Ils sont écrits contre les interfaces réelles
(`IScanEngine`, `ScanResult`, `ThreatInfo`, enums) du dépôt.

## Contenu

| Fichier | Rôle | Copier vers |
|---|---|---|
| `OptiCombatScanEngine.cs` | `IScanEngine` adossé au cdylib Rust ; mappe le JSON natif → `ScanResult`/`ThreatInfo`. | `optiCombat/Services/OptiCombat/` |
| `OptiCombatServiceRegistration.cs` | Extension DI `UseOptiCombatEngine()` (override `IScanEngine`, repli ClamAV). | `optiCombat/Services/OptiCombat/` |

## Étapes

1. Construire la bibliothèque native :
   ```bash
   cd engine && cargo build -p opticombat-ffi --release
   ```
   Copier `engine/target/release/opticombat.dll` à côté de `optiCombat.exe`
   (ou l'ajouter comme contenu copié du `.csproj`).
2. Copier les deux fichiers ci-dessus dans `optiCombat/Services/OptiCombat/`.
3. Après `services.AddOpticombatCoreServices();`, ajouter :
   ```csharp
   services.UseOptiCombatEngine();
   ```
4. Compiler et tester sur Windows. `IsAvailable` assure un **repli automatique**
   sur ClamAV si la DLL est absente — la bascule est donc sans risque.

## Ce qui ne change pas

`ScanOrchestrator`, `QuarantineManager`, l'UI WPF (Donaby Design), le RTP et le
service consomment `IScanEngine` **inchangé** : seule l'implémentation derrière
l'interface est remplacée. C'est l'aboutissement de la stratégie *strangler fig*.
