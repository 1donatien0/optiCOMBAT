# Changelog

Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [Unreleased]

### Added

- Tests de couverture : Historique (`HistoryViewModel`), export HTML, nettoyage (analyse, pas d’exécution destructive), signatures / `UpdateService`, posture, modèles (`ByteSizeFormat`, `ScanProgress`, `ClamdConfSupport`, `ThreatInfo`, …)
- Tests des ViewModels du shell (Antivirus, Options, Nettoyage, Mises à jour, Tweaks) via `TestSupport/IsolatedServices` : conteneur complet dans un dossier temporaire, moteurs ClamAV / YARA, winget et API GitHub factices
- Tests : pipeline `ScanOrchestrator` (YARA, listes de fichiers, exclusions), `RiskScoringService`, restauration de quarantaine, rapports PDF, routage des toasts, flux complet YARA-Forge (intégrité SHA-256), analyse de la sortie winget
- CI : job **Format** (`dotnet format whitespace`, `cargo fmt --check`), `cargo clippy -D warnings`, couverture Rust `cargo-llvm-cov` (plancher 65 %, cible 75 %)
- Architecture du shell WinUI 3 : `docs/SHELL_WINUI.md`

### Changed

- CI : plancher de couverture lignes .NET **62 %**, cible **65 %** (au lieu de 53 % / 60 %)
- Suite Release : **618 / 618** tests C# et **62** tests Rust verts (au lieu de 449 / 62) ; couverture .NET **66,4 %** des lignes
- `AntivirusViewModel`, `OptionsViewModel`, `CleanViewModel`, `UpdatesViewModel`, `TweaksViewModel` et `WinUiThemePacks` déplacés dans `optiCombat.Application` (namespace inchangé) : mesurés par la couverture ; `OptionsViewModel` pilote le thème via `IShellThemeController`
- `UserPreferences` / `ExclusionSettings` : racine de stockage redirigeable pour les tests (`OpticombatDataRoots`, interne)
- Moteur Rust : `cargo fmt` appliqué, MSRV 1.74 respectée dans `qualify` (`map_or` au lieu de `is_none_or`)

### Security (audit 360 — 2026-10-21)

- **Élévation de privilèges** : `SystemTweaksService.RunElevatedBatch` n’écrit plus de script `.cmd` dans `%TEMP%` avant l’invite UAC (réécrivable par tout processus de l’utilisateur) ; les commandes passent directement sur la ligne de commande élevée
- **Élévation SYSTEM** : le script « historique Defender » exécuté au démarrage (tâche SYSTEM) était copié depuis `%TEMP%` vers `%ProgramData%\optiCombat` (pré-créable par un utilisateur standard) ; il est désormais généré par le processus élevé sous `Program Files\optiCombat\helpers`
- **Quarantaine** : un manifeste non signé (« v1 ») n’est plus signé automatiquement au démarrage (forge d’entrées → restauration administrateur vers System32) ; chemins de blob confinés au dossier de quarantaine ; blobs legacy XOR restaurés seulement avec empreinte SHA-256 ; clé DPAPI illisible conservée au lieu d’être écrasée ; une restauration n’écrase plus un fichier recréé
- **Exclusions Defender** : processus exclus par **chemin complet** (et non plus par nom : tout `optiCombat.exe`/`clamscan.exe` du disque échappait à Defender) ; anciennes exclusions par nom retirées ; le script de dev n’exclut plus `dotnet.exe` / `MSBuild.exe`
- **IPC** : délai de lecture par client (un client muet bloquait tout le pipe) ; tramage JSON sans réanalyse quadratique, taille alignée sur le plafond AMSI
- Moteur Rust : dépendances vulnérables corrigées (RUSTSEC-2026-0381, RUSTSEC-2026-0382 — `rustls-webpki`, `webpki-roots`, passage à `ureq` 3) ; réputation cloud limitée à HTTPS ; clé DPAPI nulle refusée

### Fixed (audit 360)

- **Faux positifs critiques YARA** (`Possible_Ransomware`) : `.enc` matchait `.encode(`/`.encrypted`, `.crypto` matchait `window.crypto`, « how to restore » ou « pay within » suffisaient seuls → textes, scripts Python/JS et documentation classés **Malicious / Critical**
- Règles YARA `medium`/`low` : verdict **Suspicious** (et non plus Malicious)
- Cœur Rust : `opticombat.dll` se détectait **elle-même** (règles et chaîne EICAR embarquées en clair) → règles et EICAR masqués à la compilation
- Cœur Rust : DLL Microsoft (`vcruntime140.dll`, `mscordbi.dll`) et `clamscan.exe` classées **Malicious** par cumul heuristique/ML → contribution ML plafonnée, Malicious sans signature exigeant un score ≥ 150
- Cœur Rust : routage insensible à la casse (`.PS1`, `.DOCM`), formats Office à macros et scripts `hta`/`wsf`/`vbe`/`jse` routés, fichiers temporaires d’archive uniques (`create_new`), budget global de décompression (anti zip-bomb)
- **Cœur Rust opt-in** (Options → « Cœur natif Rust (expérimental) », désactivé par défaut) : la simple présence de `opticombat.dll` court-circuitait clamscan et les règles YARA Forge ; il respecte désormais les exclusions, ne signale que les verdicts Malicious (une menace par fichier), n’interrompt plus une analyse complète au premier dossier inaccessible et ne fige plus l’UI
- Build Release cassé par l’analyseur **CA1838** (`ScanPathValidation`, `StringBuilder` en P/Invoke)
- Tests Rust compilables hors Windows (`share_mode` conditionnel) ; test `windows-platform` qui ne compilait pas (`find_process_pid`)
- CI : CodeQL v4, Dependabot réactivé (limite 0 → 5) ; MSRV Rust déclarée 1.88 (exigée par `zip` 9)

### Removed / Security (audit 360 — suite)

- **Tweak « Vider l’historique et la quarantaine Windows Defender » retiré** (comportement anti-forensique, tâche SYSTEM) ; l’installateur supprime la tâche `optiCombat-ClearDefenderHistory` et son script laissés par la v1.0.0
- Exclusions implicites : `ps-script-<guid>.ps1` et `ps-state-out-*` dans `%TEMP%` ne sont plus exclus (contournement de la RTP par simple nommage) ; `__PSScriptPolicyTest_*` seulement s’il fait ≤ 128 octets
- Pipe IPC : première instance en `FILE_FLAG_FIRST_PIPE_INSTANCE`, instance suivante créée avant de libérer la courante (plus d’usurpation possible du serveur), clients distants refusés
- Cœur Rust : dispatcher mis en cache dans la DLL (clamd re-sondé toutes les 30 s), fichier lu une seule fois pour tous les moteurs, imports « textuels » comptés seulement si l’IAT semble masquée, sections MSVC/MinGW reconnues, `VirtualAlloc` 25 → 10, indicateurs d’injection non comptés deux fois sur un PE, motifs de détection masqués dans le binaire (`opticombat.dll` n’est plus détectée par elle-même), champ JSON `clamd`
- Cœur natif côté C# : verdict heuristique ignoré pour un binaire signé Authenticode de confiance (`AuthenticodeVerifier`) ; avertissement si clamd est injoignable
- `updater` : `verify_manifest_newer_than` refuse le rejeu d’un ancien manifeste signé
- `platform` : plus de repli sur la clé fixe `opticombat-dev-key`
- Mises à jour winget : une application dont le nom commence par un chiffre (ex. **7-Zip**) n’est plus retirée de la liste (confondue avec la ligne de bilan)

## [1.0.0] — 2026-10-19

Première release publique sous la marque **optiCOMBAT**. Shell livré : **WinUI 3** (`optiCombat.exe`).

### Added

- Application WinUI 3 .NET 8 : scans ClamAV (clamscan / clamd) + YARA en parallèle
- Cœur moteur Rust (`opticombat.dll`) avec repli managé si absent
- Protection temps réel user-mode, quarantaine AES-GCM, historique chiffré
- Exclusions utilisateur (DPAPI) et exclusions implicites RTP : scripts IDE (`ps-script-*.ps1` dans `%TEMP%`), dépôt de dev, fichiers signatures AppData (`ScanImplicitExclusions`)
- Interface entièrement FR / EN (`loc:Loc`), thèmes Donaby **Combat Aqua** (clair / sombre / contraste renforcé), presets d’accent Combat / Minuit / Océan / Braise, couleur perso `#RRGGBB`
- Shell : `WinUiStyles` (cartes, tuiles, puces), Mica, barre d’état live (scan / signatures)
- Accueil : posture /100, statistiques 30 j., recommandations, cadran de scan, menu d’analyse (rapide / complète / personnalisée), `ScrollViewer`, tuiles 2×2 sous 720 px
- **Optimiser** : `SelectorBar` **Nettoyage**, **Mises à jour** (winget, accès à Windows Update) et **Tweaks** (14 réglages) ; journal vide / occupé
- Nettoyage : temporaires, caches de 7 navigateurs, corbeille, journaux Windows, cache Windows Update, DNS, historique de navigation Chromium, bouton **Copier le journal**
- Antivirus : `SelectorBar` Analyse / Signatures / Quarantaine, tuiles de scan, état vide menaces, actions par menace (Réputation VirusTotal, Ignorer, Quarantaine, Supprimer), puces Récents, quarantaine paginée, **Arrêter** et barre de progression pour les signatures
- Options : **Lancer maintenant** (analyse planifiée), dossier des journaux, contrat de licence, mode complément de Defender, exclusions Defender **opt-in**, **Analyser en administrateur**
- Score de sécurité : corrections en un clic (pare-feu, UAC, partages, RTP, MAJ auto, analyse)
- Historique : cartes `AppCardStyle`, puces `FilterChipStyle`, **Traiter dans Analyse** / **Voir en quarantaine**, export HTML/PDF
- Installateur Inno bilingue self-contained `optiCombat_Setup_v1.0.0.exe` ; mise à jour sur place
- Scripts release : `prepare-release.ps1`, exclusions Defender, qualification détection
- CI GitHub (C# + Rust, CodeQL, Gitleaks, Dependency Review) ; Dependabot vers `dev` (PRs groupées, branches temporaires)

### Changed

- Identité de l’installateur : `AppId` Inno propre à optiCOMBAT ; cohabitation possible avec optiSCAN
- Contraste renforcé dans Options ; interrupteur **Suivre le thème de Windows** ; accent Combat Aqua
- Raccourcis Ctrl+1…5 via `PreviewKeyDown` (sans infobulle KeyboardAccelerator) ; fenêtre minimale 720×480
- Revenir sur une section rafraîchit ses données ; sélecteurs de fichiers / dossiers Win32 natifs (admin)
- `generate-brand-assets.py` écrit dans `assets/` et `installer/`
- `prepare-release.ps1` : outils de poste de dev non versionnés appelés seulement s’ils existent ; `-SkipFreshclam` autorise l’absence de base CVD

### Fixed

- Thème clair : barre de navigation claire ; textes et icônes figés passent par des brosses de thème
- Les détections RTP et surveillance des processus laissent une session dans l’Historique
- Confirmation obligatoire avant suppression définitive
- freshclam : plus de directive `CVDCertsDirectory` rejetée par ClamAV 1.4+
- Tests EICAR : chemins des règles et binaires YARA de test corrigés (`runtime/`)

### Security

- Crate `zip` 9 (RUSTSEC-2026-0367/0368/0369)
- Plafond de débit sur le pipe IPC (`scan_path` / `scan_buffer`)
- Vérification d’intégrité des paquets de règles YARA-Forge avant installation
- Validation des chemins d’analyse externes
- ACL restreinte sur la quarantaine et sur `%LocalAppData%\optiCombat` quand les exclusions Defender sont ajoutées

### Notes

- Couche plateforme (service Windows, AMSI, minifiltre) incluse mais **inactive** — protection sans pilote signé
- Windows Defender reste la protection temps réel recommandée
- Canal de mise à jour OTA non configuré (`UpdateService` en attente)

[1.0.0]: https://github.com/1donatien0/optiCOMBAT/releases/tag/v1.0.0
