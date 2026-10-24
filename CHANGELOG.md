# Changelog

Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [Unreleased]

### Added

- **Téléchargement des flux abuse.ch** : `ThreatIntelFeedUpdater` récupère MalwareBazaar (`recent.csv`), URLhaus (`online.csv`) et ThreatFox (`full.csv.zip`) avec l'Auth-Key abuse.ch (champ dans les Options, stocké dans les préférences), toutes les 12 h (6 h minimum), taille plafonnée, clé masquée dans les journaux ; intégré à la mise à jour des signatures (étape « Threat intel »).
- **Chargement Threat Intel dans le moteur natif** : `ThreatIntelBundle` (crate `dispatcher`), `Dispatcher::with_threat_intel_dir`, variable `OPTICOMBAT_THREAT_INTEL_DIR`, FFI `opticombat_load_threat_intel` / `opticombat_threat_intel_stats`, option CLI `--intel`. Les détections MalwareBazaar remontent avec `DetectedBy = "MalwareBazaar"`.
- **Vérification des nouvelles versions** : `UpdateService` interroge la dernière release GitHub et oriente vers la page de téléchargement (rien n'est installé automatiquement).
- **Infrastructure de tests** : exécutable factice `optiCombat.TestFakes` (winget, freshclam, clamscan, YARA, schtasks, clamd), faux serveur clamd TCP côté Rust, fixtures PE ; 943 tests C#, 170 tests Rust.
- **`ISystemShell`** : processus et registre (tweaks, exclusions Defender, `sc.exe`, AMSI / minifiltre, relance UAC, langue, démarrage automatique, menu contextuel, MpCmdRun) passent par un seul point, remplacé dans les tests par un enregistreur (`RecordingShell`) qui vérifie la commande ou la clé exacte sans rien exécuter. Seule exclusion de couverture : l'enveloppe `WindowsSystemShell`, sans logique.
- **Garde-fou global des tests** (`TestSupport/TestDataRoot`) : toute l'exécution des tests est redirigée vers un `%APPDATA%` / `%LOCALAPPDATA%` temporaire et utilise un shell inerte — même un test sans redirection explicite ne peut plus écrire dans le profil réel ni lancer de processus système.
- Tests des chemins d'échec de la quarantaine, de la surface IPC (`Dispatch`), de `SecureStore`, du nettoyage sur arborescence factice, des toasts, du statut plateforme, des actions système, des lecteurs USB, de la surveillance des processus et de la bascule service / protection locale.
- **Threat intel hors-ligne dans le cœur Rust** : crate `ioc-engine` (`IocKind`, `IocFeed`, `IocEngine::check_all`), parseurs URLhaus (texte et CSV, URL en colonne 2) et ThreatFox (format court et export réel à 15 colonnes), `MalwareBazaarDb` (SHA-256 en colonne 1, famille en colonne 8). L'étape IOC ne concerne que les scripts et les fichiers de type inconnu, et seulement si un feed est chargé. Le cœur Rust ne fait aucun appel réseau : c'est le shell qui écrit les CSV.
- Tests de couverture : Historique (`HistoryViewModel`), export HTML, nettoyage, signatures / `UpdateService`, posture, modèles (`ByteSizeFormat`, `ScanProgress`, `ClamdConfSupport`, `ThreatInfo`, …)
- Tests des ViewModels du shell via `TestSupport/IsolatedServices` : conteneur dans un dossier temporaire, moteurs et API GitHub factices
- Tests : pipeline `ScanOrchestrator`, `RiskScoringService`, restauration de quarantaine, rapports PDF, toasts, YARA-Forge, sortie winget
- CI : job **Format**, `cargo clippy -D warnings`, couverture Rust `cargo llvm-cov`
- Architecture du shell WinUI 3 : `docs/SHELL_WINUI.md`

### Changed

- **Bibliothèque native renommée `opticombat_engine.dll`** (`libopticombat_engine.so`) : `opticombat.dll` entrait en collision avec `optiCombat.dll` sur NTFS (insensible à la casse) dans le dossier de publication.
- Planchers de couverture CI : **.NET 85 %** (cible 90 %), **Rust 90 %** (cible 95 %). Mesures : .NET **87,1 %** des lignes et **80,5 %** des branches sous Linux (16 tests réservés à Windows non exécutés), **89,8 %** des lignes (10 724 / 11 939) et **84,3 %** des branches sous Windows (943 tests verts ; plancher 85 % tenu, cible 90 % non) ; Rust **92,6 %**.
- **Copies de sécurité neutralisées** : l'option « Copie de sécurité avant quarantaine » écrit désormais `<nom>.ocsafe`, contenu masqué (XOR 0x5A, `ThreatRemediationService.DecodeSafetyCopy` pour le récupérer), au lieu d'une copie exécutable en clair.
- `PlatformProtectionStatusService.Evaluate` : la décision est séparée des sondes système (registre AMSI, `fltmc`, service Defender, IPC).
- `AntivirusViewModel`, `OptionsViewModel`, `CleanViewModel`, `UpdatesViewModel`, `TweaksViewModel` et `WinUiThemePacks` déplacés dans `optiCombat.Application` (namespace inchangé) : mesurés par la couverture ; `OptionsViewModel` pilote le thème via `IShellThemeController`
- `UserPreferences` / `ExclusionSettings` : racine de stockage redirigeable pour les tests (`OpticombatDataRoots`, interne)
- Moteur Rust : `cargo fmt` appliqué, MSRV 1.74 respectée dans `qualify` (`map_or` au lieu de `is_none_or`)

### Fixed

- **Langue de l'installateur** : la boîte « English / Français » ne s'affichait que si aucune langue ne correspondait à Windows (`ShowLanguageDialog=auto`) — sur un Windows français, impossible d'installer en anglais. Elle s'affiche désormais toujours, présélectionnée sur la langue de Windows. Les cases et raccourcis de l'assistant (bureau, démarrage, signatures, « Lancer… », « Désinstaller… ») sont traduits. Le choix fait à la réinstallation est appliqué par l'application même si une autre langue était enregistrée dans ses préférences (marqueur `UiCulturePending`). Sans préférence ni installateur, la langue de Windows est utilisée au lieu du français imposé.
- **Test instable `ProtectionPipeClientTests`** : le faux serveur créait chaque instance du tube trop tard (le client pouvait se connecter avant) ; l'instance suivante est créée dès qu'une connexion est acceptée.
- **Quarantaine — fichier perdu** : si l'écriture du manifeste échouait, l'original était déjà supprimé et le blob chiffré effacé au retour en arrière. Ordre corrigé : blob, puis manifeste, puis suppression de l'original.
- **Quarantaine — manifeste rejeté écrasé** : un manifeste rejeté (HMAC invalide, non signé, ou clé DPAPI régénérée) n'était jamais copié malgré le commentaire ; deux enregistrements écrasaient le manifeste puis son `.bak`. Il est conservé en `.rejected-…` avant tout enregistrement.
- **Boutons des notifications sans effet** : « Ouvrir l'antivirus », « Ouvrir », « Historique » et « Ignorer » ne faisaient rien (`ToastArguments.Get` lève une exception sur une clé absente). Seul « Mettre en quarantaine » fonctionnait.
- **Attente de 5 s par fichier scanné** : avec le service de protection désactivé (toutes les installations), chaque scan temps réel / processus / USB sondait d'abord le tube IPC, qui réessaie jusqu'au délai de 5 s. L'IPC n'est tenté que si le service est activé, avec 30 s de pause après un échec.
- **Copies de sécurité en double** : RTP, surveillance des processus et remédiation créaient une copie puis appelaient la quarantaine, qui en créait une seconde.
- **Lecteurs USB scannés deux fois** : le minuteur et l'événement WMI modifiaient le même ensemble sans verrou ; les nouveaux lecteurs sont maintenant réservés de façon atomique.
- **Nettoyage « Historique » seul ignoré** : `CleanSelection.AnySelected` ne tenait pas compte de l'historique de navigation.
- **IPC `ScanBuffer`** : un base64 invalide levait une exception au lieu d'une réponse d'erreur ; un nom de contenu avec caractères interdits faisait échouer l'écriture du fichier temporaire.
- **Analyse Defender ciblée** : le chemin passé à `MpCmdRun` était concaténé entre guillemets (injection d'options possible) ; il est passé comme argument distinct.
- **Tests qui touchaient le poste** : le test du menu contextuel écrivait puis supprimait le vrai menu « Scanner avec optiCombat » ; plusieurs tests enregistraient les vraies préférences (`UserPreferences.Current.Save()`) ; `SecureStore` et les copies de sécurité utilisaient la vraie clé HMAC et le vrai `%LOCALAPPDATA%`.
- Les tests n'écrivent plus dans le `%LOCALAPPDATA%` réel (configuration clamd/freshclam, exclusions) et ne modifient plus les exclusions Defender sous Windows.
- Test instable `ClamScanLineParser` (rapports `Progress<T>` asynchrones).
- Plafonds mémoire sur les flux IOC (2 millions d'entrées) et les hachages MalwareBazaar.

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
