# Checklist de release — cœur optiCOMBAT

État de préparation à la mise en production du cœur moteur Rust et de son
intégration dans optiCOMBAT. Cases cochées = livré et vérifié dans ce dépôt ;
cases vides = ancrage plateforme / chantier restant.

## Qualité du cœur Rust

- [x] Workspace compile (`cargo build --workspace`).
- [x] Tests verts (`cargo test --workspace`, 56 tests).
- [x] Clippy sans avertissement (`-D warnings`).
- [x] Format vérifié (`cargo fmt --all --check`).
- [x] Harnais de robustesse anti-crash (3 500+ entrées malformées, zéro panic).
- [x] Harnais `cargo-fuzz` (`pe_parse`, `yara_parse`) — exécution locale / nightly manuelle.
- [x] Optimisation multi-motif **Aho-Corasick** (YARA) — débit ≈ 15,8 → **≈ 120 Mo/s** (×7,6).
- [x] Banc de performance (`bench`) — débit mesuré ≈ 120 Mo/s, latence p95 ≈ 12 ms/Mio.

## Détection

- [x] ClamAV via clamd (INSTREAM/PING) + repli hors-ligne.
- [x] YARA : règles réelles du dépôt chargées et évaluées.
- [x] Analyse PE réelle (goblin) + heuristiques à score.
- [x] Sandbox comportementale (indicateurs + séquences + chronologie injection).
- [x] Classifieur ML (familles), interface d'inférence en place.
- [x] Modèle ML entraîné (softmax, crate `ml-train`, ~89 % d'exactitude, poids appris baqués).
- [x] Réputation par hash (whitelist/blacklist + cloud HTTP via feature `http` + `OPTICOMBAT_REPUTATION_URL`).
- [x] Scan d'archives ZIP récursif (garde-fous anti zip-bomb).
- [x] Scan mémoire (indicateurs shellcode + YARA sur buffer).
- [ ] yara-x pour compatibilité YARA totale (hex/regex/modules).
- [ ] libclamav en FFI directe (alternative à clamd).
- [x] Modèle ML entraîné sur **corpus réel étiqueté** (`ml-train/corpus/`, holdout ≥ 70 %).
- [ ] Formats d'archives supplémentaires (7z, RAR, imbrication).

## Sécurité & conformité

- [x] Quarantaine AES-256-GCM (nonce/fichier, tag d'authentification).
- [x] Restauration vérifiée (tag GCM + SHA-256), altération détectée.
- [x] Mises à jour signées ed25519 + hash par charge utile.
- [x] Soumission de hash cloud conditionnée au consentement (RGPD).
- [x] Frontière FFI sûre (`catch_unwind`, `panic = abort` en release).
- [x] Binding DPAPI Rust (`DpapiKeyProvider`, feature `windows-platform`) — validé en CI Windows (round-trip + ReadProcessMemory).
- [ ] Signature du driver et de l'exécutable (certificat EV) — scripts `sign-release.ps1` + `verify-signatures.ps1` prêts.

## Intégration optiCOMBAT

- [x] cdylib C ABI (`opticombat_scan_path`, `scan_json`, `version`, `string_free`).
- [x] En-tête C + exemples P/Invoke (`OptiCombatNative.cs`, `OptiCombatScanner.cs`).
- [x] Façade d'orchestration `scan-service` (scan + quarantaine auto).
- [x] `IScanEngine` adossé au cœur Rust (`OptiCombatScanEngine.cs`) — **intégré dans `optiCombat/Services/OptiCombat/`**.
- [x] DI câblée : `UseOptiCombatEngine()` appelée dans `ServiceRegistration` (override `IScanEngine`, repli ClamAV).
- [x] Scan UI (`ScanViewModel` → `ScanOrchestrator` → cœur Rust) routé quand `opticombat.dll` est présente.
- [x] CI Windows : compile **et teste** les bindings `windows-platform` (DPAPI / `ReadProcessMemory`).
- [x] Déploiement : `scripts/build-engine.ps1` (copie multi-sorties) + entrée `opticombat.dll` dans l'installateur.

- [x] Build C# Windows confirmé **avec** l'intégration (compilation OK).
- [x] **Détection réelle validée de bout en bout** : EICAR détecté via l'UI par le moteur Rust (`opticombat.dll` déployée).
- [x] `ProtectionScanGateway` : RTP / processus routés via IPC si service joignable, repli orchestrateur local.
- [x] `--service-host` : scans in-process (pas de boucle IPC) ; pipe expose `engine=opticombat;native=1` si DLL présente.
- [ ] Qualification panel exécutée en CI avec échantillons réels (au-delà EICAR + synthétiques + bénins).
- [x] Panel qualification CI : EICAR + behavior-dropper.ps1 + 4 bénins, seuils 100 % / 0 % FPR.
- [ ] `WindowsMemoryRegionProvider` exercé sur processus tiers en CI Windows (`explorer.exe`).
