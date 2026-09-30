# Intégration C# du cœur Rust (copie de référence)

Ces deux fichiers sont une **copie de référence** de l’intégration livrée dans
`optiCombat.Application/Services/OptiCombat/`. La version compilée et à jour est
celle du projet `optiCombat.Application` ; ce dossier n’est pas inclus dans le build.

| Fichier | Rôle | Version livrée |
|---|---|---|
| `OptiCombatScanEngine.cs` | `IScanEngine` adossé au cdylib Rust ; mappe le JSON natif → `ScanResult` / `ThreatInfo`. | `optiCombat.Application/Services/OptiCombat/OptiCombatScanEngine.cs` |
| `OptiCombatServiceRegistration.cs` | Extension DI `UseOptiCombatEngine()` (override `IScanEngine`, repli ClamAV + YARA). | `optiCombat.Application/Services/OptiCombat/OptiCombatServiceRegistration.cs` |

## Fonctionnement

1. `ServiceRegistration` appelle `services.UseOptiCombatEngine()`.
2. Si `opticombat.dll` est présente à côté de `optiCombat.exe` et se charge, `ScanOrchestrator`
   délègue au cœur Rust ; sinon (DLL absente, bloquée par Smart App Control `0x800711C7`,
   ou remplacée par erreur) repli automatique sur ClamAV + YARA.
3. Construire et déployer la DLL :
   ```powershell
   .\scripts\build-engine.ps1
   ```

`ScanOrchestrator`, `QuarantineManager`, l’UI WinUI 3, la RTP et le service consomment
`IScanEngine` sans changement : seule l’implémentation derrière l’interface change.
