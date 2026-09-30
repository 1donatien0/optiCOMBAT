# Guide Complet — optiCOMBAT v1.0

> **Vue d’ensemble du dépôt** : [README.md](../README.md) · **CI** : [`.github/workflows/`](../.github/workflows/)  
> **Marque** : **optiCOMBAT** (prose). **Technique** : `optiCombat.exe`, projets `optiCombat.*`, données `%LocalAppData%\optiCombat`.

## Sommaire

| Chapitre | Contenu |
|:---:|:---|
| **1** | Architecture technique (projets, couches, arborescence) |
| **2** | Donaby Design — thèmes WinUI 3 |
| **3** | ClamAV, YARA et moteur Rust |
| **4** | Application mono-fenêtre (sections, antivirus, pipeline, persistance, exports, accueil, optimiser) |
| **5** | Services complémentaires (RTP, USB/SD, planification, notifications, scoring) |
| **6** | Démarrage, fermeture et ligne de commande |
| **7** | Bonnes pratiques (droits, performances, faux positifs, Defender) |
| **8** | Publication, installateur et checklist release |
| **9** | Langues de l’interface (fr-FR / en-US) |
| **10** | Dépendances et licences |
| **11** | Périmètre fonctionnel |
| **12** | Qualité, tests et CI |
| **13** | Sécurité (posture /100, modèle de menace) |
| **14** | Crédits |

**Nomenclature** — **v1.0** : nom de release. **1.0.0** : assembly et installateur (`Directory.Build.props`). **Design system** : Donaby Design (Combat Aqua). © 2026 Donatien Byakombe.

**Dépôt** : [github.com/1donatien0/optiCOMBAT](https://github.com/1donatien0/optiCOMBAT) — développement sur **`dev`**, release sur **`main`**. Voir aussi [CHANGELOG.md](../CHANGELOG.md) et [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## 1. Architecture technique

### Stack

| Couche | Technologie |
|---|---|
| Shell UI | **WinUI 3** (Windows App SDK 1.8), .NET 8, `net8.0-windows10.0.19041.0` — binaire `optiCombat.exe` |
| Métier partagé | `optiCombat.Application` (.NET 8, `net8.0-windows10.0.17763.0`) |
| Contrats IPC | `optiCombat.Platform` (.NET 8, portable) |
| Service Windows | `optiCombat.Service` (Microsoft.Extensions.Hosting.WindowsServices) — **inactif par défaut** |
| Moteurs | ClamAV 1.4.x (clamscan / clamd), YARA 4.5.x, cœur **Rust** `opticombat.dll` (FFI, optionnel) |
| Natif | `native/optiCombat.AmsiProvider` (C++), `native/optiCombat.Minifilter` (stub WDK) |

Le shell WPF d’origine a été retiré du dépôt ; son code métier vit dans `optiCombat.Application`. Historique de la migration : [MIGRATION_WINUI3.md](MIGRATION_WINUI3.md).

```
optiCombat.WinUI ──┐
optiCombat.Service ┼──► optiCombat.Application ──► optiCombat.Platform
optiCombat.Tests ──┘              │
                                  └──► opticombat.dll (Rust, P/Invoke, si présente)
```

### Architecture plateforme (protection système)

> **Couche plateforme inactive.** `PlatformProtectionFeatureGate.IsUserActivatable = false` : aucune option UI ne l’active et l’installateur ne crée pas le service. La protection temps réel livrée est **user-mode** (`FileSystemWatcher` + surveillance des processus). Service, AMSI et minifiltre nécessitent un **pilote signé** (certificat EV + Partner Center) — voir [GUIDE_DISTRIBUTION.md](GUIDE_DISTRIBUTION.md) et [SIGNATURE_PROCEDURE.md](SIGNATURE_PROCEDURE.md).

Architecture cible, déjà présente dans le code :

```
optiCombat.exe (UI WinUI 3)
    ↔ IPC nommé \\.\pipe\optiCombat_Protection (optiCombat.Platform)
optiCombat.Service.exe  →  optiCombat.exe --service-host
    ├── RTP + ProcessStartMonitor + scan USB
    ├── ProtectionPipeServer (scan_path / scan_buffer pour AMSI, débit plafonné)
    ├── optiCombat.AmsiProvider.dll (COM AMSI → IPC)     [build MSVC]
    └── optiCombat.Minifilter.sys (noyau, stub + test signing)
```

| Composant | Rôle |
|---|---|
| `optiCombat.Platform` | Contrats JSON IPC (`ping`, `scan_path`, `scan_buffer`, `status`, `shutdown`), client, jeton d’arrêt |
| `ProtectionPipeServer` / `ProtectionPipeAcl` | Serveur IPC, ACL du pipe, buffer ≤ 96 Mo base64, `IpcScanRateLimiter` (120 scans/min, 4 simultanés) |
| `ProtectionScanGateway` | RTP / processus routés vers le service si joignable, sinon orchestrateur local |
| `--service-host` | Moteur sans UI : RTP, IPC, enregistrement AMSI/minifiltre |
| `ThreatRepairService` | Quarantaine + recours Defender ciblé (`MpCmdRun`) |
| `WindowsDefenderExclusionService` | Exclusions Defender **opt-in** — Options, `--defender-exclusions`, script manuel |
| `CloudThreatIntelService` / `ThreatReputationService` | Réputation VirusTotal (hash SHA-256, clé API utilisateur) |

### Arborescence du dépôt

```
(racine)
├── README.md · CHANGELOG.md · CONTRIBUTING.md · SECURITY.md · LICENSE.txt
├── Directory.Build.props        ← Version 1.0.0, NetAnalyzers latest-recommended, TreatWarningsAsErrors (Release)
├── .editorconfig · .gitattributes
├── .github/
│   ├── workflows/ci.yml         ← Tests C# + couverture, tests Rust, cargo audit, publish + SBOM (main)
│   ├── workflows/codeql.yml     ← CodeQL C#, Rust, Actions
│   ├── workflows/gitleaks.yml   ← Recherche de secrets
│   ├── workflows/dependency-review.yml
│   └── dependabot.yml           ← NuGet, Cargo, GitHub Actions
├── optiCombat.sln
├── optiCombat.WinUI/            ← Shell WinUI 3 (optiCombat.exe)
│   ├── App.xaml(.cs)            ← Mutex, modes headless, lancement fenêtre
│   ├── MainWindow.xaml(.cs)     ← NavigationView, systray, raccourcis, événements services
│   ├── Themes/                  ← Combat.Light / Combat.Dark / Combat.HighContrast (mêmes clés, vérifiées en CI)
│   ├── Views/                   ← OverviewPage, CleanPage, AntivirusPage, HistoryPage, OptionsPage
│   ├── ViewModels/              ← AntivirusViewModel, CleanViewModel, OptionsViewModel
│   └── Services/                ← WinUiServiceHost, WinUiThemeManager, Loc (i18n XAML), WinUiNativeDialogs,
│                                   WinUiUserConfirmService, WinUiThreadScheduler, WinUiTrayHost, …
├── optiCombat.Application/      ← Métier partagé (aucune dépendance WinUI)
│   ├── Models/                  ← ThreatInfo, ScanResult, ScanSession, ActivityEntry, …
│   ├── Services/                ← Moteurs, orchestrateur, quarantaine, persistance, RTP, USB, MAJ, IPC, …
│   │   ├── DependencyInjection/ServiceRegistration.cs
│   │   └── OptiCombat/          ← OptiCombatScanEngine (cœur Rust), UseOptiCombatEngine()
│   ├── Coordinators/            ← Navigation, AntivirusActionResult, RealTimeThreat, UsbScanStatus, Onboarding,
│   │                               HistoryThreatRemediation, OverviewRefresh, ToastActivation, ShellSections
│   ├── ViewModels/              ← HistoryViewModel, HistoryThreatRow
│   ├── Views/                   ← Contrats IOverviewPanel, IAntivirusSignaturesPanel
│   ├── Localization/            ← LocalizationService, ShellContextMenuSupport
│   ├── Resources/               ← UiStrings.resx (FR) + UiStrings.en.resx (EN)
│   └── Strings/OpticombatStrings.cs ← URLs, constantes UI
├── optiCombat.Platform/         ← IPC (client, contrats, framing JSON, jeton d’arrêt)
├── optiCombat.Service/          ← Service Windows (supervise --service-host)
├── optiCombat.Tests/            ← xUnit + Moq + coverlet
├── engine/                      ← Workspace Cargo du cœur Rust (voir engine/README.md)
├── native/                      ← AmsiProvider (C++), Minifilter (stub)
├── runtime/                     ← ClamAV / YARA / règles copiés dans la sortie WinUI (binaires non versionnés)
├── assets/                      ← Icône et images consommées par WinUI ; assets/branding/ = sources et variantes
├── installer/                   ← setup.iss (Inno, FR/EN), build-release-setup.ps1
├── qualification/               ← Panel détection / faux positifs
├── tools/AdminRestoreQuarantine ← Outil admin de restauration de quarantaine
└── scripts/                     ← fetch/verify runtime, prepare-release, SBOM, signature, Defender, …
```

**Règles de séparation**
- `optiCombat.Application` ne référence pas WinUI : services injectables (`Microsoft.Extensions.DependencyInjection` + `ServiceContainer`), coordinateurs testables via des hôtes typés (`Host`).
- `optiCombat.WinUI` : pages XAML + ViewModels de présentation ; `WinUiServiceHost` expose le conteneur et les ViewModels aux pages.
- `MainWindow.xaml.cs` : câblage (navigation, systray, messages fenêtre, abonnements `UiEventBus`) — pas de logique métier.

---

## 2. Donaby Design — thèmes WinUI 3

La palette **Combat Aqua** repose sur un accent **teal** (`AccentBrush` `#0F9F8F`), des fonds clairs froids en mode clair et navy en mode sombre.

Les brosses sont déclarées dans `optiCombat.WinUI/Themes/` et fusionnées dans les dictionnaires de thème d’`App.xaml` :

| Ressource | Clair (`Combat.Light`) | Sombre (`Combat.Dark`) | Contraste renforcé (`Combat.HighContrast`) |
|---|---|---|---|
| `AppBackgroundBrush` | `#F5F7FB` | `#0F172A` | `#FFFFFF` |
| `SidebarBackgroundBrush` | `#FFFFFF` | `#0B1220` | `#FFFFFF` |
| `CardBackgroundBrush` / `CardAltBackgroundBrush` | `#FFFFFF` / `#F8FAFC` | `#1E293B` / `#162032` | `#FFFFFF` |
| `CardBorderBrush` | `#E2E8F0` | `#334155` | `#000000` |
| `TextMutedBrush` | `#64748B` | `#94A3B8` | `#1A1A1A` |
| `OnAccentForegroundBrush` | `#FFFFFF` | `#042F2E` | `#FFFFFF` |
| `AccentBrush` / `AccentTintBrush` | `#0F9F8F` / `#ECFDF5` | `#2DD4BF` / `#0E2A22` | `#00564C` / `#FFFF00` |
| `InfoBrush` / `VioletBrush` | `#2563EB` / `#7C3AED` | `#93C5FD` / `#C4B5FD` | `#1E3A8A` / `#5B21B6` |
| `WarningBrush` / `WarningTintBrush` / `WarningBorderBrush` | `#D97706` / `#FFF7ED` / `#FDBA74` | `#F59E0B` / `#3A2A14` / `#B45309` | `#6B3F00` / `#FFF1B8` / `#6B3F00` |
| `DangerBrush` | `#C0392B` | `#F87171` | `#8B0000` |

Règles :
- Les trois fichiers déclarent **exactement les mêmes clés** et les vues les référencent en **`{ThemeResource}`**, jamais en `{StaticResource}` (sinon elles ne suivent pas le thème). `scripts/check-winui-theme-keys.ps1` le vérifie, en local et en CI.
- Dans le code-behind, `WinUiThemeManager.GetBrush("Clé")` résout la brosse du thème **affiché** (et non celui de Windows).

**`WinUiThemeManager`** :
- **Thème sombre** (bouton lune / soleil de la barre latérale ou Options) : choix explicite, désactive le suivi de Windows.
- **Suivre le thème de Windows** (Options) : clair / sombre selon le réglage des applications Windows.
- **Contraste renforcé** (Options) : fusionne `Combat.HighContrast.xaml` en dernier dans le dictionnaire clair et force le thème clair ; activé aussi quand le contraste élevé de Windows est actif.
- L’accent Combat Aqua est injecté dans `SystemAccentColor*` : les contrôles WinUI (interrupteurs, boutons d’accent, sélection) suivent la marque au lieu de la couleur d’accent de Windows.

Styles partagés (`App.xaml`) : `OverviewCardStyle`, `OptionRowStyle`, `SectionHeaderStyle`, `OptionToggleStyle`, `OptionCaptionStyle`. Préférences `DarkTheme`, `SyncWindowsTheme`, `HighContrastEnabled` dans `%AppData%\optiCombat\preferences.dat` (DPAPI + HMAC).

---

## 3. ClamAV, YARA et moteur Rust

### 3.1 Récupérer les binaires

Les binaires ClamAV et YARA ne sont **pas versionnés**. Versions et URL : `scripts/runtime-versions.json` (ClamAV **1.4.2** win x64, YARA **4.5.2** win64).

```powershell
.\scripts\fetch-runtime-deps.ps1                  # ClamAV + YARA → runtime\
.\scripts\fetch-runtime-deps.ps1 -RunFreshclam    # + bases de signatures (~200+ Mo, long)
.\scripts\verify-runtime-deps.ps1                 # après publish
```

> Utiliser le ZIP **win.x64** de ClamAV (pas ARM64 : erreur `0xc000007b` sur Intel/AMD).

Le projet WinUI copie `runtime\` dans sa sortie (build et publish) :

| Dossier (à côté de `optiCombat.exe`) | Contenu |
|---|---|
| `clamav/x64/` | `clamscan.exe`, `clamd.exe`, `freshclam.exe`, DLL ClamAV |
| `clamav/database/` | Bases `.cvd` / `.cld` (ou téléchargées au premier lancement) |
| `clamav/certs/clamav.crt` | Certificat racine CVD |
| `yara/` | `yara64.exe`, `yarac64.exe` |
| `rules/` | Règles `.yar` (versionnées : `malware_signatures`, `suspicious_strings`, `test_rules`) + cache compilé |

Au démarrage, `RuntimeDependencies` journalise l’état des dépendances.

### 3.2 Mise à jour des signatures ClamAV (freshclam)

`FreshclamUpdater` génère un `freshclam.conf` minimal (sans BOM, marqueur `generated by optiCombat vN`) dans `%LocalAppData%\optiCombat\clamav\` et lance freshclam avec `--config-file`.

- **Pas de directive `CVDCertsDirectory`** : ClamAV 1.4+ la rejette (« Can't open/parse freshclam.conf »). Les certificats passent par la variable d’environnement **`CVD_CERTS_DIR`**. Un conf existant qui contient la directive est renommé `.v1.bak` et régénéré (`FreshclamConfSupport`).
- Version locale : lecture de l’en-tête `ClamAV-VDB:{date}:{version}:…` des `.cvd` / `.cld`.

Codes de sortie `clamscan` : **0** aucune menace · **1** menace(s) · **2** erreur.

### 3.3 Règles YARA-Forge

`YaraForgeUpdater` interroge `api.github.com/repos/YARAHQ/yara-forge/releases/latest`, télécharge le paquet **core**, puis :

1. vérifie l’intégrité (`YaraForgePackageIntegrity`) : en-tête ZIP, taille annoncée, **digest SHA-256** publié par GitHub, taille ≤ 256 Mo — un paquet invalide est **rejeté** et les règles actuelles conservées ;
2. extrait les `.yar` et invalide le cache compilé (`_compiled.yarc` / stamp, `YaraRulesCacheSupport`).

### 3.4 Cœur Rust (`opticombat.dll`)

`ScanOrchestrator` délègue au cœur Rust **si `opticombat.dll` est déployée** à côté de l’exe (`UseOptiCombatEngine()` dans `ServiceRegistration`) ; sinon ClamAV et YARA tournent en parallèle. Un chargement bloqué (Smart App Control, `0x800711C7`) ne fait jamais planter l’UI : repli automatique.

```powershell
.\scripts\build-engine.ps1     # cargo build -p opticombat-ffi --release + copie de la DLL
```

Détails : [engine/README.md](../engine/README.md).

---

## 4. Application mono-fenêtre

### 4.1 Sections de `MainWindow`

`MainWindow.xaml` contient un `NavigationView` et un hôte de page ; chaque page est créée à la première visite puis conservée.

| Raccourci | Tag | Section | Page | Rôle |
|---|---|---|---|---|
| `Ctrl+1` | `overview` | Accueil | `OverviewPage` | Score de sécurité /100, état de protection, dernière analyse, statistiques, recommandations |
| `Ctrl+2` | `clean` | Optimiser | `CleanPage` | Onglets **Nettoyage**, **Mises à jour** (winget) et **Tweaks** (§4.12) |
| `Ctrl+3` | `antivirus` | Antivirus | `AntivirusPage` | Onglets **Analyse**, **Quarantaine**, **Signatures** |
| `Ctrl+4` | `history` | Historique | `HistoryPage` | Timeline, filtres, traitement des menaces, exports |
| `Ctrl+5` | `options` | Options | `OptionsPage` | Préférences, protection, exclusions, analyse planifiée (+ **Lancer maintenant**), mise à jour, diagnostic (dossier des journaux, licence) |

Revenir sur une section déjà ouverte **rafraîchit ses données** (`NavigationRefreshCoordinator` : accueil, antivirus, historique), les pages étant gardées en cache.

La navigation programmatique passe par `INavigationService` (`WinUiNavigationService`) ; les événements métier (demande de MAJ signatures, rafraîchissement historique, menace RTP, statut USB, action terminée, toast activé) arrivent par `UiEventBus` via `WinUiServiceEventCoordinator`.

### 4.2 Fenêtre, zone de notification et pied de page

- Taille initiale 1280 × 720, minimum 1024 × 600.
- **Fermer la fenêtre la masque** dans la zone de notification (`WinUiTrayHost`) : double-clic ou menu **Ouvrir** pour la rouvrir, **Quitter** pour arrêter. Seul **Quitter** (ou l’installateur via `--exit`, ou la fin de session Windows) arrête réellement l’application.
- Pied de page : texte de statut dynamique (section, scan, MAJ, USB, actions).
- Instance unique : mutex `Global\optiCombat_UniqueInstance` ; une seconde instance envoie un message fenêtre (`SingleInstanceMessaging` : afficher, scan contextuel, quitter) à la première.

### 4.3 Antivirus

- **Analyse** : analyse rapide, analyse complète, scanner un fichier, scanner un dossier, arrêter l’analyse ; puces **Récents** (relancent la dernière cible : rapide, complète, dossier ou fichier) ; compteurs fichiers / menaces ; liste des menaces détectées avec, par ligne, **Réputation** (VirusTotal), **Ignorer**, **Quarantaine** et **Supprimer** (confirmation obligatoire) ; **Tout mettre en quarantaine**. Quand une action réussit, la ligne disparaît et quarantaine, historique et accueil sont rafraîchis.
- **Quarantaine** : éléments isolés (pages de 200, **Charger plus d’entrées**), **Restaurer** / **Supprimer** (confirmation obligatoire), **Vider toute la quarantaine** (confirmation, irréversible).
- **Signatures** : versions ClamAV / YARA, **Mettre à jour les signatures** (freshclam puis YARA-Forge), bouton **Arrêter** et barre de progression pendant la mise à jour (annule freshclam et YARA-Forge), journal.

Les onglets de l’Antivirus et de l’Optimiseur ne sont pas fermables. Depuis l’accueil, « Mettre à jour » ouvre l’onglet **Signatures** et lance la mise à jour ; la tuile d’analyse ouvre un menu (rapide / complète / personnalisée).

Menu contextuel Explorateur « Scanner avec optiCOMBAT » (fichiers et dossiers) → `optiCombat.exe --scan "<chemin>"`. Le chemin est validé (`ScanPathValidation` : pas de chemin de périphérique `\\.\` / `\\?\`, pas de caractère de contrôle, chemin existant), puis relance UAC si le chemin l’exige (`ElevationHelper`), ou transmission à l’instance déjà ouverte.

Les sélecteurs de fichier / dossier (analyse, exclusions, exports) sont les boîtes Win32 natives (`WinUiNativeDialogs`) : les sélecteurs WinRT échouent quand l’application tourne en administrateur.

### 4.4 Traiter une menace

`clamscan` **détecte** mais ne répare pas : la désinfection passe par l’isolement ou la suppression.

| Action (Analyse et Historique) | Service | Comportement |
|---|---|---|
| **Quarantaine** | `AntivirusActions` → `QuarantineManager` | AES-256-GCM, restaurable |
| **Supprimer** | `AntivirusActions` | Confirmation obligatoire (`IUserConfirmService`, « Non » par défaut), puis suppression définitive |
| **Ignorer** / **Exclure** | `AntivirusActions` / `ExclusionSettings` | Retire la menace / exclut le chemin |
| **Tout mettre en quarantaine** | `HistoryThreatRemediationCoordinator` | Traitement groupé de la session |
| **Traiter dans Analyse** | `UiEventBus.RequestReviewHistorySession` | Charge les menaces de la session dans l’onglet **Analyse** de l’Antivirus (`LoadThreatsFromHistorySession`) pour les traiter comme après un scan |
| **Voir en quarantaine** / **Gérer dans l’Antivirus** | `UiEventBus.RequestOpenQuarantineTab` | Ouvre l’onglet **Quarantaine** de l’Antivirus |
| **Voir scan source** | Navigation | Sélectionne la session d’origine d’un élément en quarantaine |

> Toujours préférer la quarantaine à la suppression : elle permet de restaurer un faux positif.

### 4.5 Pipeline de détection

```
AntivirusViewModel → ScanOrchestrator
    ├─ opticombat.dll présente → cœur Rust (ClamAV/clamd + YARA + heuristiques + ML + réputation)
    └─ sinon, en parallèle (Task.WhenAll) :
         ├─ CompositeClamAvBackend (clamd TCP 127.0.0.1:3310 → repli clamscan.exe)
         └─ YaraEngine (un seul yara64.exe --recursive, règles compilées en cache)
       → ScanThreatMerger (fusion) → MultiTargetScanAggregator (dédup multi-cibles)
    └─ ScanProgressRelay → progression monotone vers l’UI
```

- **clamd** : option **Options → Utiliser le moteur ClamD** ; démon préchauffé (`ClamdHost`), repli automatique sur `clamscan.exe`.
- **Périmètres protégés** : installation et `%LocalAppData%\optiCombat` exclus de toute analyse (`OpticombatProtectedPaths`) ; exclusions implicites RTP (`ScanImplicitExclusions`) ; exclusions utilisateur (`ExclusionSettings`).
- **`RiskScoringService`** : score et sévérité de chaque menace (toasts, historique, PDF).
- **Identifiant menace** : `ThreatInfo.Id` = SHA-256 déterministe de `FilePath|VirusName|DetectedAt`, stable entre redémarrages.

### 4.6 Mise à jour des signatures

- **Manuelle** : onglet **Signatures** ou carte **Mise à jour** de l’accueil — `SignatureUpdateCoordinator` enchaîne freshclam puis YARA-Forge (délai max 5 min).
- **Automatique** (`SignatureUpdatePolicy`) : ClamAV toutes les **4 h**, YARA-Forge toutes les **24 h** ; mode **agressif** (Options) : **2 h** / **12 h**. **Options → Mise à jour auto des signatures** coupe ou réactive les deux.

### 4.7 Exclusions

`ExclusionSettings` → `%LocalAppData%\optiCombat\exclusions.dat` (DPAPI + HMAC). Gestion : **Options → Exclusions et seuils**.

**Périmètres protégés** (`OpticombatProtectedPaths`) — jamais analysés ni mis en quarantaine automatiquement. La quarantaine, et `%LocalAppData%\optiCombat` dès que les exclusions Defender sont ajoutées, reçoivent une **ACL restreinte** (propriétaire, SYSTEM, Administrateurs — `DirectoryHardening`) pour qu’un autre compte local ne puisse pas y déposer de fichier hors de portée de Defender :

| Périmètre | Contenu |
|---|---|
| Installation | `{autopf}\optiCombat`, dossier du processus, chemin d’installation Inno (registre) |
| Données | `%LocalAppData%\optiCombat\` — base ClamAV, règles, quarantaine, logs, conf clamd/freshclam |

- Racines protégées ajoutées automatiquement à la liste et non supprimables.
- Règles YARA exclues par défaut : `SuspiciousDownloads` (trop agressive sur Téléchargements).
- ClamAV / clamd : un `--exclude` / `ExcludePath` par racine protégée.
- RTP et scan USB appliquent les mêmes exclusions.

**Exclusions Windows Defender** (`WindowsDefenderExclusionService`) — **opt-in uniquement**. Un antivirus qui s’exclut silencieusement de Defender adopte un comportement de malware, et l’opération échoue de toute façon si la protection contre la falsification est active. Defender reste la protection temps réel recommandée ; optiCOMBAT la complète.

| Moment | Comportement |
|---|---|
| Installation | Rien — le script est seulement copié dans `{app}\scripts\` |
| Démarrage | Rien |
| **Options → Exclusions Windows Defender** | « Ajouter les exclusions » ; relance UAC (`--defender-exclusions`) si nécessaire |
| Manuel | `.\scripts\add-defender-exclusions.ps1` (console administrateur) |

Chemins : racines de `OpticombatProtectedPaths`. Processus : `optiCombat.exe`, `optiCombat.Service.exe`, `clamscan.exe`, `freshclam.exe`, `clamd.exe`, `yara64.exe`.

### 4.8 Quarantaine (`QuarantineManager`)

- Stockage `%LocalAppData%\optiCombat\Quarantine\` : `{guid}.quar` (format `OPTQ`, **AES-256-GCM**) + `manifest.json` signé **HMAC-SHA256** (un manifeste v2 sans HMAC est rejeté ; migration v1 → v2 automatique).
- Clé maîtresse 256 bits protégée par **DPAPI CurrentUser**.
- Rollback : si la suppression de l’original ou l’écriture du manifeste échoue, le blob est supprimé et la quarantaine annulée.
- Restauration vers l’emplacement d’origine ou un dossier choisi ; chemins sensibles (System32, Windows, Program Files, ProgramData, Démarrage) refusés.
- Dossier protégé par une ACL restreinte (`DirectoryHardening`).
- Option **Sauvegarde avant quarantaine**. Outil admin de secours : `tools/AdminRestoreQuarantine`.

### 4.9 Journaux et historique

Tous sous `%LocalAppData%\optiCombat\Logs\` :

| Fichier | Service | Rôle |
|---|---|---|
| `activity_log.dat` | `ActivityLogService` | Timeline Historique (DPAPI + HMAC), **150** événements max |
| `scan_history.dat` / `clean_history.dat` | `ScanLogManager` | Sessions détaillées ; rotation **100 → 50** |
| `optiCombat.log` | `ScanLogManager` | Journal texte de diagnostic, **non chiffré**, chemins caviardés (`PathRedaction`) |
| `opticombat-AAAA-MM-JJ.log` | `AppLogger` | Logs applicatifs ; purge au-delà de **30 jours** (au plus 1×/jour, marqueur `.lastcleanup`) |
| `winui-crash.log` | `App` | Exceptions non gérées de l’UI |

**Page Historique** (`HistoryPage` + `HistoryViewModel`) :
- Timeline triée par date décroissante, recherche, **5 filtres** : Tout, Menaces, Scans sains, Nettoyages, Quarantaine.
- Au rafraîchissement, `ReconcileQuarantinedThreats` retire des sessions les menaces déjà en quarantaine.
- Détail d’une session : actions du §4.4 ; détail quarantaine / nettoyage en lecture.

### 4.10 Exports

- **HTML** : `HtmlExportService` — bouton **Export HTML** (Historique).
- **PDF** : `PdfReportGenerator` (QuestPDF) — bouton **Export PDF** (session sélectionnée) ; couleurs de sévérité `PdfRiskPalette`.

### 4.11 Accueil

`OverviewPage`, alimentée par `WinUiServiceHost.RefreshOverviewAsync` et `OverviewRefreshCoordinator` :
- **État de protection** (« Votre ordinateur est sécurisé » ou alerte), **dernière analyse**, bouton **Lancer une analyse**.
- **Score de sécurité /100** (`SecurityPostureService`, §13) et bandeau d’analyse partielle sans droits administrateur.
- **Cartes** : Antivirus, Optimiser, Historique, Mise à jour ; états ClamAV, YARA, signatures (dernière MAJ).
- **Statistiques** 30 jours (`OverviewProtectionStatsFormatter`) et **Recommandations** (`OverviewRecommendationsBuilder`, seuils réglables dans Options).

- **Corriger en un clic** (`PostureFixService`) pour les contrôles du score : pare-feu (`netsh`), UAC (registre, redémarrage requis), partages réseau (`net share … /delete`), protection temps réel, MAJ auto des signatures, analyse récente. Confirmation puis **une seule** invite UAC (`ElevatedCommandRunner`) ; les noms de partage contenant des métacaractères `cmd.exe` sont ignorés. Windows Update garde un lien vers les Paramètres.
- **Analyser en administrateur** : libère l’instance unique, relance optiCOMBAT élevé puis ferme l’instance courante (instance conservée si l’UAC est refusée).

### 4.12 Optimiser (`CleanPage`)

Page à trois onglets non fermables (`TabView`) :

- **Nettoyage** (`CleanViewModel` + `SystemCleanService`) : **Analyser** mesure l’espace récupérable, **Nettoyer maintenant** l’exécute et enregistre une session dans l’Historique. Cibles : temporaires Windows / utilisateur, corbeille, journaux Windows, caches de 7 navigateurs, **cache Windows Update** (arrêt du service → une invite UAC), **cache DNS** (`ipconfig /flushdns`) et **historique de navigation** des navigateurs Chromium (Firefox exclu : `places.sqlite` contient aussi les favoris). Le journal est copiable (**Copier le journal**).
- **Mises à jour** (`UpdatesViewModel` + `WingetUpdateService`) : applications à mettre à jour via winget (individuellement ou en groupe) et accès aux paramètres Windows Update.
- **Tweaks** (`TweaksViewModel` + `SystemTweaksService`) — 14 réglages appliqués d’un coup par **Appliquer** ; les réglages système sont regroupés dans **un seul** script administrateur (une invite UAC) :
  - *Performances* : plan d’alimentation Haute performance, effets visuels réduits ;
  - *Confidentialité* : télémétrie, identifiant publicitaire, suggestions, expériences personnalisées ;
  - *Interface* : extensions de fichiers, fichiers cachés, barre des tâches à gauche, widgets masqués, recherche en icône, Explorateur sur « Ce PC » ;
  - *Maintenance* : nettoyage des composants Windows (DISM, lent), historique Windows Defender (au prochain démarrage).

  Un bouton ouvre le gestionnaire des applications de démarrage.

---

## 5. Services complémentaires

### RealTimeProtection — temps réel user-mode

`FileSystemWatcher` sur les dossiers de `RealTimeWatchPaths` (cibles du scan rapide `ScanTargets.QuickScanTargets()` + `ProgramData` et `Downloaded Program Files`, moins les exclusions), filtre `RiskyFileExtensions`, délai de stabilisation, déduplication, **3 scans simultanés** max. Complété par **ProcessStartMonitor** (WMI, exécutables et hôtes de scripts au lancement — Options → Surveillance des processus). Activation : **Options → Protection en temps réel**.

**Trace des détections** : chaque détection de la RTP et de `ProcessStartMonitor` est enregistrée dans l’Historique par `DetectionHistoryRecorder` (session `ScanType.RealTime`, libellé « Protection temps réel ») avant l’éventuelle quarantaine automatique. Elle apparaît dans **Historique → Menaces** avec Quarantaine / Ignorer / Supprimer tant que le fichier n’est pas traité ; une fois mis en quarantaine, l’évènement « Mis en quarantaine » reste dans la chronologie. `ScanLogManager.SaveScanResult` est verrouillé (appels concurrents RTP / USB / UI). Le toast seul ne laissait auparavant aucune trace.

### DefenderCoexistenceService — mode complément de Defender

**Options → Protection → Laisser le temps réel à Windows Defender** (désactivé par défaut, proposé au premier lancement si Defender est actif) : coupe la RTP et la surveillance des processus d’optiCOMBAT ; Defender surveille en continu, optiCOMBAT fait les analyses à la demande, planifiées et USB. Évite deux antivirus temps réel sur les mêmes fichiers.

### OnboardingCoordinator — premier lancement

Guide court (boîtes natives) au premier lancement, sauté si des analyses existent déjà : présentation, choix de cohabitation avec Defender (si actif), mise à jour des signatures, première analyse. Refuser le guide ne le repropose plus.

### TamperProtectionService — anti-sabotage

Option **Protection anti-sabotage** : tâche planifiée `optiCombat_Watchdog` qui lance `optiCombat.exe --watchdog`. Si la protection temps réel est activée mais qu’aucune instance d’optiCOMBAT ne tourne, l’application est relancée.

### RemovableDriveScanService — clés USB et cartes SD

| Aspect | Comportement |
|---|---|
| Détection | Insertion via WMI + polling de secours (4 s) ; lecteurs amovibles ou fixes reconnus USB |
| Déjà branché au démarrage | Enregistré sans scan |
| Mode rapide (défaut) | Fichiers à extension à risque (max **4 000**, énumération **90 s**), ClamAV puis YARA **en série**, timeout **10 min** |
| Mode détaillé (Options) | Scan récursif complet, timeout **45 min** |
| Taille max. | **64 Go** (`RemovableDriveMaxSizeGb`, 0 = illimité) |
| Analyse complète | Option **Inclure les USB dans l’analyse complète** |
| Retour | Toasts début / fin, statut dans le pied de page, historique `ScanType.RemovableDrive`, quarantaine auto si activée |

Un seul lecteur à la fois ; RTP suspendue pendant le scan.

### ScheduledScanService — analyse planifiée

Tâche `schtasks` **`optiCombat_DailyScan`** : `optiCombat.exe --fullscan --quiet`, **`/RL LIMITED`**, heure réglable (**Options → Analyse planifiée quotidienne**, affichage de la prochaine exécution).

### NotificationService — toasts Windows

`Microsoft.Toolkit.Uwp.Notifications` : `ShowThreatDetected`, `ShowQuarantined`, `ShowRemovableDriveScanStarted` / `Completed`, `ShowScanCompleted`, `ShowUpdateAvailable`, `ShowRealTimeProtectionStarted`. Les clics sont routés par `ToastActivationCoordinator`. **Mode jeu** (`DistractionFreeMonitor`) : notifications suspendues en plein écran.

### RiskScoringService — score de risque

Score cumulé à partir de :
1. **Nom de la menace** — critique (ransom, rootkit, bootkit, backdoor, wannacry…) = 60 pts ; majeur (trojan, worm, spyware, keylogger…) = 40 ; mineur (adware, pup, pua, hacktool…) = 20 ; informationnel = 5.
2. **Chemin** — System32 / SysWOW64, exécutables, documents à macros, Temp.
3. **Bonus / malus** — double détection ClamAV + YARA, taille du fichier.

| Score | Sévérité | Couleur (PDF) |
|---|---|---|
| ≥ 80 | Critique | `#C0392B` |
| ≥ 50 | Majeur | `#E67E22` |
| ≥ 25 | Mineur | `#F1C40F` |
| < 25 | Informationnel | `#27AE60` |

---

## 6. Démarrage, fermeture et ligne de commande

```
optiCombat.exe
 ├─ LocalizationService.Initialize() (préférence, sinon culture de l’installateur)
 ├─ --exit            → demande à l’instance ouverte de quitter (installateur)
 ├─ --scan <chemin>   → chemin validé (ScanPathValidation) ; élévation si nécessaire ; transmis à l’instance ouverte ou scanné au démarrage
 ├─ --watchdog        → vérification anti-sabotage, puis sortie
 ├─ --defender-exclusions → ajoute les exclusions Defender (relance élevée), puis sortie
 ├─ --service-host    → moteur sans UI (IPC + RTP + processus), mutex Global\optiCombat_ServiceHost
 ├─ --fullscan | --quickscan [--quiet] → scan headless, journal, quarantaine auto si activée,
 │                       toast si menaces (sauf --quiet) ; reporté si mode jeu actif
 └─ (aucun)           → instance unique → MainWindow
                          ├─ première activation : AppWindow, systray, hooks messages, thème
                          └─ WinUiStartupCoordinator : préférences, services, préchauffage YARA,
                             rafraîchissement accueil / antivirus / historique, scan contextuel en attente

FERMETURE
 ├─ bouton Fermer   → masquage dans la zone de notification
 └─ Quitter / --exit / fin de session → ServiceContainer.Shutdown() (RTP, USB, minuteries, moteurs)
```

---

## 7. Bonnes pratiques

### Droits

`app.manifest` : **`asInvoker`**. Les opérations qui l’exigent (analyse d’un chemin protégé, exclusions Defender) demandent une **élévation UAC ponctuelle** (`ElevationHelper`). Une analyse complète sans élévation est partielle : le bandeau de l’accueil propose **Analyser en administrateur** (relance élevée de l’application).

### Performances

| Technique | Effet |
|---|---|
| Sonde `clamscan --version` en cache 60 s | Pas de lancement de processus à chaque navigation |
| ClamAV + YARA en parallèle | Temps de scan réduit |
| clamd résident (option) | Base chargée une seule fois |
| Règles YARA compilées en cache, préchauffage au démarrage | Premier scan plus rapide |
| `MultiTargetScanAggregator` | Pas de doublons sur cibles qui se chevauchent |
| RTP limitée à 3 scans simultanés, USB 1 lecteur à la fois | Charge maîtrisée |
| `ServiceContainer` singleton | Une instance de chaque moteur pour toute l’app |

### Faux positifs

- Quarantaine plutôt que suppression ; confirmation avant toute action destructrice.
- `SuspiciousDownloads` exclue par défaut.
- EICAR : règle `EICAR_Test` dans `runtime/rules/test_rules.yar` ; ClamAV le détecte aussi si la base est à jour.

### Exclusion Windows Defender

Voir [§4.7](#47-exclusions). En bref : **opt-in** (*Options → Exclusions Windows Defender*), uniquement si Defender bloque ClamAV, YARA ou freshclam ; jamais par l’installateur ni au démarrage. Manuel (administrateur) :

```powershell
.\scripts\add-defender-exclusions.ps1
```

Si la protection contre la falsification est active, ajouter les chemins dans *Sécurité Windows → Protection contre les virus et menaces → Exclusions*.

---

## 8. Publication, installateur et checklist release

### Prérequis machine de build

- Windows 10/11 x64, .NET 8 SDK, Inno Setup 6, Python 3 + Pillow (assets branding), Rust stable (moteur, optionnel)
- Réseau (ClamAV, YARA, signatures)

### Chaîne automatique

```powershell
.\scripts\prepare-release.ps1                      # complet
.\scripts\prepare-release.ps1 -SkipFreshclam       # sans base CVD (téléchargée au 1er lancement)
.\scripts\prepare-release.ps1 -SkipInstaller       # publish seulement
.\scripts\prepare-release.ps1 -Sign                # avec signature (voir SIGNING.md)
```

Étapes : nettoyage → `fetch-runtime-deps` (+ freshclam) → assets branding (`generate-brand-assets.py` → `assets/` et `installer/optiCombat.ico`) → tests Release → `dotnet publish` WinUI (profil `FolderProfile-SelfContained`) + service → moteur Rust → `verify-runtime-deps` → signature (option) → installateur Inno.

Les scripts de poste de dev non versionnés (`unblock-dev-build`, `sign-dev-local`, `sync-installer-icon`) ne sont appelés que s’ils existent.

- Sortie publish : `optiCombat.WinUI\bin\Release\net8.0-windows10.0.19041.0\publish\win-x64\` (**self-contained**, runtime .NET embarqué).
- Installateur : `installer\output\optiCombat_Setup_v1.0.0.exe` — x64, bilingue FR/EN.
- Chaîne alternative : `.\installer\build-release-setup.ps1`.

### Comportement de l’installateur

- **Mise à jour sur place** : même `AppId` (`8E7178EF-E038-413D-BF79-FFB925BB2543`, propre à optiCOMBAT — distinct d’optiSCAN, avec `InnoUninstallGuid` aligné) ; ferme `optiCombat.exe`, le service et les moteurs (`CloseApplications=force` + `taskkill`), remplace les fichiers ; `%LocalAppData%\optiCombat` est conservé.
- Répare un `freshclam.conf` cassé laissé par une ancienne version.
- Tâches proposées : icône bureau, démarrage avec Windows, MAJ auto des signatures ; l’option « protection système » affiche seulement un message (couche plateforme inactive).
- Menu contextuel Explorateur FR/EN.
- **N’applique pas** d’exclusions Defender.
- **Désinstallation** : arrête et supprime les services, puis **propose** de supprimer les données utilisateur (`%LocalAppData%` et `%AppData%\optiCombat`).

### Checklist release

- [ ] `dotnet test` Release vert ; CI verte (tests, couverture ≥ 40 %, CodeQL, Gitleaks)
- [ ] `.\scripts\verify-runtime-deps.ps1` vert sur le dossier publish
- [ ] `clamscan.exe`, `freshclam.exe`, `clamd.exe`, `yara64.exe`, règles `.yar`
- [ ] Base `clamav\database\` présente, ou MAJ signatures vérifiée au premier lancement
- [ ] VM propre : installation, scan fichier, quarantaine, historique, exports HTML/PDF, clé USB, FR/EN
- [ ] Mise à jour par-dessus une installation existante : historique conservé
- [ ] SHA-256 du setup publié ; signature Authenticode si disponible

### Signature Authenticode

Sans certificat, Windows affiche « Éditeur inconnu ». Voir [SIGNING.md](SIGNING.md) et [SIGNATURE_PROCEDURE.md](SIGNATURE_PROCEDURE.md) ; exemple Inno : [`installer/setup.iss.signing.example`](../installer/setup.iss.signing.example).

---

## 9. Langues de l’interface (fr-FR / en-US)

| Canal | Comportement |
|---|---|
| Installateur Inno | Choix FR / EN → `HKCU\Software\optiCombat\UiCulture` (culture du premier lancement) |
| Options → Langue de l’interface | Français / English, appliqué **immédiatement** à toutes les pages, sans redémarrage |
| Ressources | `optiCombat.Application/Resources/UiStrings.resx` (FR) + `UiStrings.en.resx` (EN) — **886** clés chacune, parité vérifiée par tests |
| Menu contextuel | « Scanner avec optiCOMBAT » / « Scan with optiCOMBAT » |

**Libellés XAML** — propriétés attachées `Loc` (`optiCombat.WinUI/Services/Loc.cs`), aucun texte en dur dans les vues :

```xml
xmlns:loc="using:optiCombat.WinUI.Services"
<TextBlock loc:Loc.Text="Nav_Home" />
<Button loc:Loc.Content="Av_Restore" loc:Loc.Tip="Av_Restore" />   <!-- Tip = infobulle + nom d’accessibilité -->
<TextBox loc:Loc.Placeholder="Hist_SearchPlaceholder" />
<TabViewItem loc:Loc.Header="Av_TabScan" />
```

Au changement de langue (`LocalizationService.CultureChanged`), tous les libellés vivants sont réappliqués sans recréer les pages. Dans le code : `LocalizationService.GetString` / `Format`.

Ajouter une clé : même nom dans les deux `.resx`.

```powershell
dotnet test optiCombat.Tests\optiCombat.Tests.csproj -c Release --filter Localization
```

Non traduit volontairement : sorties brutes ClamAV / freshclam / YARA, noms de menaces, chemins.

---

## 10. Dépendances et licences

| Composant | Version | Licence | Usage |
|---|---|---|---|
| Windows App SDK (WinUI 3) | 1.8 | MIT | Shell UI |
| .NET | 8.x | MIT | Runtime (embarqué, self-contained) |
| QuestPDF | 2024.12.2 | Community (gratuite open source) | Rapports PDF |
| Microsoft.Toolkit.Uwp.Notifications | 7.1.3 | MIT | Toasts |
| Microsoft.Extensions.DependencyInjection / Hosting.WindowsServices | 8.0.1 | MIT | DI, service Windows |
| System.Management, ProtectedData, ServiceController | 8.0.x | MIT | WMI, DPAPI, services |
| ClamAV | 1.4.2 | GPLv2 | Moteur de signatures |
| Base de signatures ClamAV | — | ClamAV License | database.clamav.net |
| YARA | 4.5.2 | BSD-3-Clause | Moteur de règles |
| Règles YARA-Forge | — | Diverses open source | Règles de détection |
| Inno Setup | 6.x | Freeware | Installateur |
| Crates Rust (goblin, aho-corasick, aes-gcm, ed25519…) | voir `engine/Cargo.lock` | MIT / Apache-2.0 | Cœur moteur |

Tests : xUnit, Moq, coverlet. Mise à jour de l’application (`UpdateService`) : **canal OTA non configuré** volontairement (dossier de staging uniquement).

---

## 11. Périmètre fonctionnel v1.0

- **Analyse** — rapide, complète, fichier, dossier, USB/SD, menu contextuel ; ClamAV (clamd / clamscan) + YARA ; cœur Rust si `opticombat.dll` présente.
- **Protection** — RTP user-mode + surveillance des processus, anti-sabotage, quarantaine AES-GCM, exclusions DPAPI, analyse planifiée, posture /100 avec corrections en un clic, mode complément de Defender, réputation VirusTotal (opt-in), mode jeu.
- **Optimisation** — nettoyage (temporaires Windows / utilisateur, caches Edge, Chrome, Firefox, Brave, Opera, Vivaldi, Arc, corbeille, journaux Windows, cache Windows Update, cache DNS, historique de navigation Chromium), mises à jour des applications (winget) et 14 tweaks Windows.
- **Historique** — timeline chiffrée, filtres, traitement des menaces, exports HTML / PDF.
- **Interface** — WinUI 3 mono-fenêtre Combat Aqua, clair / sombre / contraste renforcé, entièrement traduite FR / EN, guide de premier lancement, zone de notification.
- **Publication** — installateur Inno self-contained, mise à jour sur place.

Hors périmètre v1.0 : couche plateforme (service, AMSI, minifiltre), mise à jour OTA de l’application.

---

## 12. Qualité, tests et CI

```powershell
dotnet test optiCombat.Tests\optiCombat.Tests.csproj -c Release
cargo test --workspace --manifest-path engine/Cargo.toml
```

- **≈ 329 cas de test** C# (271 `[Fact]` + 14 `[Theory]` / 58 jeux de données), `Release` avec **TreatWarningsAsErrors** et NetAnalyzers `latest-recommended`.
- **64** tests Rust (`#[test]`) dans le workspace `engine/`.

| Domaine | Tests représentatifs |
|---|---|
| Accueil / posture | `OverviewRecommendationsBuilderTests`, `OverviewProtectionStatsFormatterTests`, `OverviewRefreshCoordinatorTests`, `SecurityPostureServiceTests` |
| Scan | `ScanOrchestratorTests`, `CompositeClamAvBackendTests`, `ClamdClientTests`, `ScanThreatMergerTests`, `MultiTargetScanAggregatorTests`, `ScanProgressRelayTests` |
| RTP / USB | `RealTimeProtectionTests`, `RealTimeWatchPathsTests`, `RemovableDriveDiscoveryTests`, `RemovableDriveScanServiceTests` |
| Quarantaine / exclusions | `QuarantineManagerTests`, `QuarantineManagerSecurityTests`, `ExclusionSettingsTests`, `OpticombatProtectedPathsTests`, `WindowsDefenderExclusionServiceTests` |
| Historique | `ActivityLogServiceTests`, `ScanLogManagerTests`, `HistoryThreatRemediationCoordinatorTests`, `DestructiveActionConfirmationTests` |
| Shell / coordinateurs | `ShellSectionsTests`, `NavigationRefreshCoordinatorTests`, `AntivirusActionResultCoordinatorTests`, `RealTimeThreatCoordinatorTests`, `UsbScanStatusCoordinatorTests`, `OnboardingCoordinatorTests`, `ToastActivationCoordinatorTests` |
| Sécurité locale | `ScanPathValidationTests`, `DirectoryHardeningTests`, `DefenderCoexistenceServiceTests` |
| IPC / plateforme | `ProtectionPipeServerTests` (dont plafond de débit), `IpcScanRateLimiterTests`, `ProtectionScanGatewayTests`, `PlatformProtectionFeatureGateTests` |
| Signatures | `FreshclamConfSupportTests`, `YaraForgePackageIntegrityTests`, `SignatureUpdatePolicyTests`, `SignatureStatusServiceTests` |
| Persistance / i18n | `SecureStoreTests`, `UserPreferencesStorageTests`, `LocalizationServiceTests` |
| Intégration EICAR | `EicarIntegrationTests`, `OptiCombatEicarIntegrationTests` (no-op si moteur absent) |

### CI GitHub

| Workflow | Déclencheur | Contenu |
|---|---|---|
| `ci.yml` | push / PR `main`, `dev` | Contrôle des thèmes WinUI, build Release, tests + couverture (**plancher 40 %**, cible 50 %), tests Rust, `cargo audit` ; sur `main` : publish win-x64 + SBOM CycloneDX (artefacts) |
| `codeql.yml` | push / PR + hebdo | CodeQL C#, Rust, GitHub Actions |
| `gitleaks.yml` | push / PR + hebdo | Recherche de secrets |
| `dependency-review.yml` | PR | Bloque les dépendances vulnérables *high* |
| `dependabot.yml` | hebdo | NuGet, Cargo (`engine/`), Actions → `dev` |

Le panel de qualification (`scripts/qualify-detection.ps1`, [qualification/README.md](../qualification/README.md)) se lance localement ; il n’est pas encore exécuté en CI.

### 12.1 Architecture UI et dette connue

- Coordinateurs testables dans `optiCombat.Application/Coordinators` (hôtes typés `Host`, aucune dépendance WinUI) : navigation, résultat d’action antivirus, menace temps réel, statut USB, premier lancement, remédiation historique, accueil, toasts. `MainWindow` ne fait plus que les brancher.
- Abstractions : `IUserConfirmService` (boîte native `WinUiUserConfirmService`, refus par défaut tant que la fenêtre n’existe pas) et `IUiThreadScheduler` (`WinUiThreadScheduler`, synchrone dans les tests).
- **Dette restante** : une partie de la logique reste dans les pages et ViewModels WinUI (scan, nettoyage, options) ; les pages WinUI ne sont compilées que sous Windows (compilateur XAML).

---

## 13. Sécurité (posture et menaces)

### Note posture /100 (Accueil)

`SecurityPostureService` — somme des poids des contrôles réussis :

| Id | Poids | Contrôle |
|---|---|---|
| `firewall` | 15 | Pare-feu actif sur les profils Domaine / Privé / Public (registre) |
| `uac` | 10 | `EnableLUA` |
| `wupdate` | 15 | Windows Update récent (`IWindowsUpdateProbe` : registre, WMI, WUA) |
| `shares` | 10 | Pas de partage SMB exposé |
| `opticombat` | 25 | ClamAV + YARA + RTP opérationnels |
| `scan` | 15 | Dernière analyse &lt; 7 jours |
| `sigauto` | 10 | MAJ automatique des signatures |

Limite : les profils pare-feu sont lus au registre, pas le profil réseau actif en temps réel.

### Modèle de menace (périmètre local)

**Actifs** : fichiers analysés, quarantaine, préférences et exclusions, clé VirusTotal optionnelle.

**Contrôles** : quarantaine AES-GCM + manifeste HMAC ; persistance DPAPI + HMAC (`SecureStore`) ; périmètres protégés (`OpticombatProtectedPaths`) ; exclusions Defender opt-in ; pipe IPC avec ACL, taille de buffer bornée et **débit plafonné** (`IpcScanRateLimiter`) ; chemins d’analyse externes validés (`ScanPathValidation`) ; ACL restreinte sur la quarantaine et les données exclues de Defender (`DirectoryHardening`) ; confirmation avant toute suppression définitive ; **intégrité des paquets YARA-Forge** ; clamd sur `127.0.0.1` uniquement ; UAC ponctuelle ; tâches planifiées en `/RL LIMITED`.

**Limites** : un malware administrateur peut neutraliser un antivirus local ; couche plateforme (AMSI, minifiltre) inactive ; VirusTotal reçoit le hash ; `optiCombat.log` non chiffré (chemins caviardés).

Signalement de vulnérabilités : [SECURITY.md](../SECURITY.md).

---

## 14. Crédits

Développé par **© 2026 Donatien Byakombe**  
Design system : **Donaby Design**
