# Guide Complet — optiCOMBAT v1.0

> **Vue d’ensemble du dépôt** : [README.md](../README.md) · **CI** : [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)  
> **Marque** : **optiCOMBAT** (prose). **Technique** : `optiCombat.exe`, dossiers `optiCombat/`, `%LocalAppData%\optiCombat`.

## Sommaire

| Chapitre | Contenu |
|:---:|:---|
| **1** | Architecture technique (stack, arborescence du dépôt) |
| **2** | Donaby Design (thèmes, tokens) |
| **3** | Installation et configuration ClamAV |
| **4** | Application mono-fenêtre (panneaux, antivirus, pipeline, persistance, exports, vue d’ensemble) |
| **5** | Services complémentaires (RTP, scan USB/SD, planificateur, notifications, scoring) |
| **6** | Workflow démarrage UI et ligne de commande |
| **7** | Bonnes pratiques (droits, perfs, faux positifs, Defender) |
| **8** | Publication, installateur Inno Setup et checklist release |
| **9** | Langues de l’interface (fr-FR / en-US) |
| **10** | Dépendances et licences |
| **11** | Périmètre fonctionnel |
| **12** | Qualité et tests |
| **13** | Sécurité (posture /100, modèle de menace) |
| **14** | Crédits |

**Nomenclature** — **v1.0** : nom de release. **1.0.0** : assembly et installateur. **Design system : Donaby Design (Combat Aqua)**. © 2026 Donatien Byakombe.

**Dépôt** : [github.com/1donatien0/optiCOMBAT](https://github.com/1donatien0/optiCOMBAT) — branche **`main`**. Voir aussi [CHANGELOG.md](../CHANGELOG.md) et [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## 1. Architecture technique

### Choix du langage : C# WPF .NET 8

| Critère | WPF | MAUI | C++ natif |
|---|---|---|---|
| Compatibilité Windows | Oui — natif | Partiel — multi-plateforme (overhead) | Oui — natif |
| Intégration ClamAV | Oui — Process.Start / TCP clamd | Oui — Process.Start | Oui — libclamav directe |
| MVVM + Binding UI | Oui — excellent | Partiel — différent | Non — manuel |
| **Verdict** | **Retenu** | Non nécessaire | Non nécessaire |

### Architecture plateforme (protection système)

> **Couche plateforme inactive par défaut.** Service Windows, minifiltre et AMSI nécessitent un **pilote signé** (certificat EV + Partner Center). optiCOMBAT assure la protection temps réel en **mode user-mode** (`FileSystemWatcher`), sans pilote (`UsePlatformProtectionService = false`). Voir [GUIDE_DISTRIBUTION.md](GUIDE_DISTRIBUTION.md).

optiCOMBAT rapproche un antivirus « classique » via une couche plateforme Windows (activable ultérieurement) :

```
optiCombat.exe (UI WPF)
    ↔ IPC (optiCombat.Platform — pipe optiCombat_Protection)
optiCombat.Service.exe  →  optiCombat.exe --service-host
    ├── RTP + ProcessStartMonitor + scan USB
    ├── ProtectionPipeServer (scan path/buffer pour AMSI)
    ├── optiCombat.AmsiProvider.dll (COM AMSI → IPC)     [build MSVC / WDK]
    └── optiCombat.Minifilter.sys (noyau, stub + test signing)
```

| Composant | Rôle |
|---|---|
| `optiCombat.Platform` | Contrats JSON IPC (`ping`, `scan_path`, `scan_buffer`, `status`, `shutdown`) |
| `optiCombat.Service` | Service Windows qui supervise `optiCombat.exe --service-host` |
| `--service-host` | Moteur sans UI : RTP, IPC, enregistrement AMSI/minifilter |
| `ThreatRepairService` | Quarantaine + recours Defender (`MpCmdRun`) |
| `WindowsDefenderExclusionService` | Exclusions Defender auto (chemins + processus optiCOMBAT) — install, démarrage, `--defender-exclusions` |
| `CloudThreatIntelService` | Enrichissement VirusTotal (cache local) |
| `native/optiCombat.AmsiProvider` | DLL C++ fournisseur AMSI (build VS 2022 x64) |
| `native/optiCombat.Minifilter` | Driver noyau stub (WDK + certificat EV en production) |

**Prérequis** : droits administrateur pour le service, l'enregistrement AMSI et le chargement minifilter (`fltmc`). En développement : `bcdedit /set testsigning on` pour le driver.

**Option UI** : *Service Windows de protection système* (Options → Protection). Si le service est injoignable, repli automatique sur la RTP locale.

---

### Structure des modules

```
(racine du dépôt optiCOMBAT)
├── README.md                          ← Ce fichier (guide complet)
├── docs/
│   └── README.md                      ← Index doc (renvoie vers ce README)
├── .editorconfig                      ← Sévérités analyse Roslyn (alignement IDE / MSBuild)
├── Directory.Build.props              ← Version 1.0.0, NetAnalyzers, TreatWarningsAsErrors (Release)
├── .github/workflows/ci.yml           ← Tests C# + Rust (push main)
├── scripts/
│   ├── fetch-runtime-deps.ps1         ← Télécharge ClamAV + YARA (CI / dev)
│   ├── prepare-release.ps1         ← Chaîne complète release v1
│   ├── clean-before-publish.ps1       ← Nettoyage bin/obj avant release
│   ├── add-defender-exclusions.ps1    ← Exclusions Windows Defender (install / manuel)
│   ├── generate-sbom.ps1              ← SBOM CycloneDX (CI publish)
│   ├── build-amsi.ps1 / stage-amsi.ps1← DLL AMSI native (publish)
│   ├── verify-runtime-deps.ps1        ← Vérifie clamav + clamd + yara + rules
│   ├── validate-release-readiness.ps1 ← Tests Release (+ verify publish optionnel)
│   └── runtime-versions.json          ← Versions URL ClamAV / YARA
├── optiCombat.sln                       ← Solution Visual Studio
├── optiCombat.Platform/                 ← IPC protection système
├── optiCombat.Service/                  ← Service Windows (supervise --service-host)
├── optiCombat.Tests/                    ← Tests unitaires (xUnit)
├── native/
│   ├── optiCombat.AmsiProvider/         ← DLL AMSI (C++, build MSVC)
│   └── optiCombat.Minifilter/           ← Driver noyau stub (WDK)
├── installer/
│   ├── setup.iss                      ← Script Inno Setup (FR + EN)
│   └── build-release-setup.ps1        ← clean + publish + ISCC
└── optiCombat/                          ← Projet C# WPF
    ├── Models/
    │   ├── ThreatInfo.cs              ← Menace détectée
    │   ├── ScanProgress.cs            ← Progression temps réel (IProgress<T>)
    │   ├── ScanResult.cs              ← Résultat global d'un scan (types dont RemovableDrive)
    │   ├── ScanSession.cs             ← Entrée d'historique scan (`Threats[]`)
    │   ├── ActivityEntry.cs           ← Ligne timeline Historique (projection UI)
    │   └── ActivityEventRecord.cs     ← Événement immuable (activity_log.dat)
    │
    ├── ViewModels/                    ← ScanViewModel, HistoryViewModel, HistoryThreatRow, RelayCommand
    ├── Views/                         ← Overview, Antivirus, Clean, History, Options
    │
    ├── Coordinators/                  ← Orchestration UI (MainWindow, Historique) — classes static sans état
    │   ├── MainWindowStartupCoordinator.cs / MainWindowShutdownCoordinator.cs
    │   ├── TrayCoordinator.cs         ← Systray (wrap `SystemTrayHost`)
    │   ├── OverviewRefreshCoordinator.cs / SignatureRefreshCoordinator.cs
    │   ├── HistoryDetailCoordinator.cs / HistoryRefreshCoordinator.cs / HistoryThreatRemediationCoordinator.cs
    │   ├── ExportCoordinator.cs       ← Exports HTML/PDF (via `IHistoryExportService`)
    │   └── … (toast, RTP, USB, signatures manuelles, shell scan, etc.)
    │
    ├── Localization/
    │   ├── LocalizationService.cs     ← Culture fr-FR / en-US, persistance
    │   ├── LocExtension.cs            ← {loc:Loc Key=...} en XAML
    │   └── ShellContextMenuSupport.cs ← Menu « Scanner avec optiCOMBAT » / EN
    ├── Resources/
    │   ├── UiStrings.resx             ← Chaînes UI (français)
    │   └── UiStrings.en.resx          ← Chaînes UI (anglais)
    ├── Strings/
    │   └── OpticombatStrings.cs         ← URLs, confirmations, statuts MAJ
    │
    ├── Converters/
    │   ├── ThreatRiskConverters.cs    ← Colonne « Risque » (RiskScoringService → UI)
    │   └── QuarantinePathVisibilityConverter.cs ← Chemin quarantaine (Historique, lecture seule)
    │
    ├── Services/
    │   ├── ClamAvEngine.cs            ← clamscan.exe (sonde --version mise en cache 60 s)
    │   ├── FreshclamUpdater.cs        ← Mise à jour signatures via freshclam.exe
    │   ├── ThemeManager.cs            ← Bascule Donaby + MaterialDesign (UserPreferences)
    │   ├── ExclusionSettings.cs       ← Exclusions DPAPI (exclusions.dat) + dossiers protégés
    │   ├── OpticombatProtectedPaths.cs  ← Install + %LocalAppData%\optiCombat : anti-autophagie scan/RTP
    │   ├── WindowsDefenderExclusionService.cs ← Exclusions Defender (chemins + processus)
    │   ├── AppInstallPaths.cs         ← Façade racine install + motifs clamscan --exclude
    │   ├── YaraEngine.cs              ← YARA + cache _compiled.yarc / _compiled.stamp
    │   ├── YaraForgeUpdater.cs        ← Mise à jour automatique règles de détection
    │   ├── ServiceContainer.cs        ← Singleton + DI (`IUserPreferencesAccessor`, `IExclusionSettingsAccessor`, `IViewServices`, `IHistoryServices`)
    │   ├── ScanOrchestrator.cs        ← Pipeline ClamAV + YARA en parallèle
    │   ├── ScanProgressRelay.cs       ← Progression monotone (multi-cibles / Clam+YARA)
    │   ├── ScanUserDisplay.cs         ← Libellés scan localisés
    │   ├── ScanThreatMerger.cs        ← Fusion menaces ClamAV + YARA
    │   ├── MultiTargetScanAggregator.cs ← Fusion multi-cibles avec déduplication des menaces
    │   ├── AntivirusActions.cs        ← Quarantaine / suppression / MAJ + ActionCompleted
    │   ├── NavigationService.cs       ← Panneaux + fondu 180 ms
    │   ├── NavigationRefreshCoordinator.cs ← Refresh ciblé après navigation (Services/)
    │   ├── HistoryExportService.cs    ← Export HTML/PDF (`IHistoryExportService`)
    │   ├── SystemTrayHost.cs          ← Icône zone de notification (bas niveau)
    │   ├── OnboardingService.cs       ← Message premier lancement
    │   ├── HeadlessScanArguments.cs   ← --fullscan / --quickscan / --defender-exclusions / --quiet
    │   ├── ScheduledScanApply.cs      ← Logique enable/disable tâche (testable)
    │   ├── ElevationHelper.cs         ← Relance UAC (--scan, analyse complète)
    │   ├── QuarantineManager.cs       ← Quarantaine AES-GCM, manifeste signé
    │   ├── SecureStore.cs             ← Persistance DPAPI + HMAC (prefs, exclusions, historique)
    │   ├── OverviewRecommendationsBuilder.cs ← Recommandations accueil (hygiène + activité)
    │   ├── OverviewProtectionStatsFormatter.cs ← Stats protection 30 j. (accueil, sans doublon reco.)
    │   ├── ActivityLogService.cs      ← Journal unifié activity_log.dat (timeline Historique)
    │   ├── ScanLogManager.cs          ← Sessions scan/nettoyage (.dat), ReconcileQuarantinedThreats, optiCombat.log
    │   ├── SignatureStatusService.cs  ← Versions signatures ClamAV/YARA (cache TTL 30 s)
    │   ├── RealTimeProtection.cs      ← FileSystemWatcher (Options)
    │   ├── RemovableDriveScanService.cs ← Scan auto USB/SD à l'insertion (WMI + polling)
    │   ├── RiskyFileExtensions.cs     ← Extensions à risque (RTP + énumération USB rapide)
    │   ├── ScheduledScanService.cs    ← schtasks (async côté Options)
    │   ├── IpcManager.cs              ← Instance unique : WM_SHOWME
    │   ├── HtmlExportService.cs       ← Rapport HTML
    │   ├── NotificationService.cs     ← Toasts Windows natifs
    │   ├── RiskScoringService.cs      ← Score, sévérités i18n, PDF
    │   └── PdfReportGenerator.cs      ← Export PDF (QuestPDF)
    │
    ├── Themes/
    │   ├── Donaby.Dark.xaml           ← Thème sombre
    │   ├── Donaby.Light.xaml          ← Thème clair
    │   └── Donaby.HighContrast.xaml   ← Contraste renforcé (Options)
    │
    ├── App.xaml                       ← Fusionne Donaby.Light + ThemeManager au démarrage
    ├── MainWindow.xaml                ← Fenêtre unique — 5 panneaux sidebar
    ├── MainWindow.xaml.cs             ← Composition légère (~730 L) : navigation, branchement coordinateurs, événements services
    ├── optiCombat.ico                   ← Icône app
    ├── yara/                          ← Binaires du moteur de détection
    ├── rules/                         ← Règles de détection (.yar) + cache _compiled.yarc
    └── clamav/                        ← Binaires et base ClamAV (x64 / x86 / database)
```

**Règle de séparation :**
- `Models/` — aucune dépendance UI
- `Coordinators/` — orchestration WPF sans état (méthodes `static`, hôtes `Host` typés) ; extrait de `MainWindow` / `HistoryControl`
- `Services/` — aucune dépendance WPF ; injectables via `Microsoft.Extensions.DependencyInjection` + `ServiceContainer`
- `ViewModels/` — logique de présentation (`ScanViewModel`, commandes)
- `Views/` — XAML + code-behind léger ; `Bind(IHistoryServices)` / `IViewServices` pour éviter le couplage à `MainWindow`
- `MainWindow.xaml.cs` — câblage : navigation, systray (`TrayCoordinator`), coordinateurs startup/shutdown/RTP/exports

---

## 2. Donaby Design — Système de thèmes

### 2.1 Vue d'ensemble

optiCOMBAT utilise le **Donaby Design**, un système de design propriétaire basé sur des tokens de couleur WPF (`DynamicResource`). Le thème peut être basculé à chaud (sans redémarrage) entre le mode sombre et le mode clair.

La palette « Combat Aqua » repose sur un **accent bleu-vert (teal / cyan)** : fonds blanc froid épuré en mode clair, navy profond en mode sombre, et un **dégradé signature vert → teal → bleu** réutilisé pour le cadran de scan de l'accueil et les boutons primaires.

Fichiers de thème :

| Fichier | Rôle |
|---|---|
| `Themes/Donaby.Dark.xaml` | Palette sombre |
| `Themes/Donaby.Light.xaml` | Palette claire |
| `Themes/Donaby.HighContrast.xaml` | Bordures et textes renforcés (Options) |
| `Services/ThemeManager.cs` | Clair / sombre / contraste ; sync thème Windows |

### 2.2 ThemeManager

`ThemeManager` est un service `static` initialisé **avant** `InitializeComponent()` dans le constructeur de **`MainWindow`** (thème correct dès le premier rendu XAML) :

```csharp
// MainWindow() — avant InitializeComponent()
ThemeManager.Initialize(); // SyncWindowsTheme par défaut, sinon DarkTheme

// Options — thème opposé à Windows (décocher = resuivre Windows)
ThemeManager.SetAlternateThemeEnabled(true/false);

// Contraste renforcé (Options)
ThemeManager.SetHighContrast(true);

// S'abonner aux changements
ThemeManager.ThemeChanged += (_, isDark) => { /* ... */ };
```

Styles boutons (`Styles/Controls.xaml`) : `GradientPrimaryButton`, `DangerButton`, `WarningButton`, `SuccessButton`, `HubActionCardButton`, etc. — couleurs sémantiques via `TemplateBinding.Background`.

La préférence est persistée dans `%AppData%\optiCombat\preferences.dat` (DPAPI + HMAC). Par défaut **optiCOMBAT suit le thème applications Windows** (`SyncWindowsTheme`). Dans **Options**, une seule case dynamique propose le thème **opposé** à Windows (libellé « Thème clair » si Windows est sombre, « Thème sombre » si Windows est clair). Propriétés : `DarkTheme`, `SyncWindowsTheme`, `HighContrastEnabled`.

### 2.3 Tokens de couleur disponibles

| Token DynamicResource | Rôle |
|---|---|
| `AppBg` / `CardBg` / `HeaderBg` | Fonds principaux |
| `TextDark` / `TextMedium` / `TextSecondary` | Hiérarchie typographique |
| `PrimaryBlue` / `AccentBlue` | Couleur d'accent principale (bleu-vert / teal) |
| `AccentGradient` / `HeroCardGradient` | Dégradé signature vert → teal → bleu (cadran de scan, boutons) |
| `SuccessGreen` / `AlertGold` / `WarningOrange` / `DangerRed` | Statuts |
| `BorderColor` / `BorderSubtle` / `BorderStrong` | Séparateurs |
| `ThemeToggleIcon` / `ThemeToggleLabel` | Libellés dynamiques pour le bouton de thème |

---

## 3. Installation et configuration de ClamAV

### 3.1 Télécharger ClamAV (version x86-64 obligatoire)

```
https://www.clamav.net/downloads#otherversions
→ Windows → clamav-X.Y.Z.win.x64.zip   ← ZIP, pas MSI, pas ARM64
```

> **Attention :** la version `win.arm64` cause l'erreur `0xc000007b` sur les machines Intel/AMD.

### 3.2 Placer les binaires dans le projet

> **Clone git seul** — les binaires ClamAV et YARA ne sont pas versionnés dans Git. Les récupérer automatiquement :
>
> ```powershell
> .\scripts\fetch-runtime-deps.ps1
> .\scripts\fetch-runtime-deps.ps1 -RunFreshclam   # bases signatures (~200+ Mo, long)
> .\scripts\verify-runtime-deps.ps1                # après dotnet publish
> ```
>
> Au démarrage, optiCOMBAT journalise aussi l’état via `RuntimeDependencies` (`opticombat-*.log`).

```
<racine du dépôt>/optiCombat/clamav/x64/
    ├── clamscan.exe
    ├── clamd.exe              ← daemon ClamAV optionnel (TCP 127.0.0.1:3310 si « Moteur clamd » activé)
    ├── freshclam.exe
    ...
```

Dossiers attendus à côté de `optiCombat.exe` (publish ou debug) :

| Dossier | Contenu minimal |
|---|---|
| `clamav/x64/` (ou `x86/`) | `clamscan.exe`, `freshclam.exe` recommandé |
| `yara/` | `yara64.exe`, `yarac64.exe` (ou `32` en processus x86) |
| `rules/` | Au moins un fichier `.yar` (paquet initial ou MAJ YARA-Forge) |

### 3.3 Première mise à jour des signatures

```powershell
.\clamav\x64\freshclam.exe --datadir=".\clamav\x64\database"
```

Télécharge : `main.cvd` (~170 Mo), `daily.cvd` (~60 Mo), `bytecode.cvd` (~200 Ko).

### 3.4 Lecture de la version locale des signatures

`FreshclamUpdater.GetLocalDatabaseVersion()` lit l'en-tête binaire des fichiers `.cvd` / `.cld` :

```
Format réel : ClamAV-VDB:{date texte}:{version}:{signatures}:...
Exemple     : ClamAV-VDB:01 May 2026 06-27 +0000:22988:355446:...
```

La regex utilisée est `ClamAV-VDB:[^:]+:(\d+):` — elle capture le numéro de version
après la date textuelle (le premier champ est une date lisible, pas un entier).

### 3.5 Codes de sortie clamscan

| Code | Signification |
|---|---|
| 0 | Aucune menace |
| 1 | Menace(s) détectée(s) |
| 2 | Erreur de scan |

---

## 4. Architecture mono-fenêtre

Les sous-sections **4.1** à **4.11** suivent une lecture « produit » : navigation et panneaux, détail du panneau Antivirus, menaces et pipeline, options techniques (MAJ, exclusions, quarantaine, logs), exports, puis contenu de la vue d’ensemble.

### 4.1 Les 5 panneaux de MainWindow

Les vues sont empilées dans un seul `Grid` (`MainWindow.xaml`) : une seule est `Visible`, les autres `Collapsed`. La navigation passe par `NavigationService.NavigateTo("…")` (clés insensibles à la casse), enregistrées dans `MainWindow.RegisterPanels()`.

| Clé `NavigateTo` | Panneau | Contrôle | Rôle principal |
|---|---|---|---|
| `Overview` | Vue d'ensemble | `OverviewControl` | Cartes d'action (boutons), bandeau UAC, statut protection, recommandations |
| `Antivirus` | Antivirus | `AntivirusView` | Scans ; onglets **Analyse en cours** / **Quarantaine** / **Historique** / **Signatures** (`ScanViewModel`) |
| `Clean` | Nettoyer | `CleanControl` | Analyse / nettoyage (caches navigateurs, temp, corbeille) + **historique local** (colonne **Libéré** = `BytesDisplay`) |
| `History` | Historique | `HistoryControl` + `HistoryViewModel` | Timeline `ActivityLogService.GetActivityFeed` ; 5 filtres (puces) ; traitement menaces ; exports **HTML** / **PDF** |
| `Options` | Options | `OptionsControl` | **Langue** (fr/en, redémarrage), thème / `SyncWindowsTheme`, scan favori, RTP, **scan USB/SD** (auto à l'insertion, mode complet, inclure dans analyse complète), quarantaine auto, planif. (`ServiceContainer.ScheduledScan`, prochaine exécution, **Lancer maintenant**), exclusions |

Raccourcis clavier : `Ctrl+1` … `Ctrl+5` (`KeyboardShortcuts`) — ordre des panneaux : **Vue d’ensemble**, **Antivirus**, **Nettoyer**, **Historique**, **Options**.

### 4.2 Fenêtre principale, barre système et icône

L'interface repose sur `MainWindow` et la barre latérale (90 px). Le **systray** est géré par `TrayCoordinator` → `SystemTrayHost` (double-clic pour rouvrir, menu Ouvrir / Quitter). Réduire la fenêtre laisse optiCOMBAT actif en arrière-plan. Footer : statut dynamique (scan, MAJ) à gauche ; crédit Vanier à droite.

### 4.3 Panneau Antivirus (`NavigateTo("Antivirus")`)

Panneau divisé en deux colonnes :
- **Colonne gauche (210px)** : boutons de scan, **cibles récentes** (`RecentTargets` / `ScanRecentCommand`), statistiques temps réel
- **Colonne droite** : TabControl avec 4 onglets :
  - **Analyse en cours** — progression, fichier courant, grille menaces (colonne **Risque** + nom virus), actions par menace, quarantaine groupée
  - **Quarantaine** — entrées paginées, restauration / suppression, purge
  - **Historique** — aperçu des dernières sessions (détail et actions dans le panneau **Historique** `Ctrl+4`)
  - **Signatures** — version de la base ClamAV, mise à jour manuelle, journaux freshclam / règles

Après chaque analyse réussie, `StartScanAsync` met à jour les **cibles récentes** (fichier/dossier scanné, ou entrée « analyse rapide » / « analyse complète »).

### 4.4 Nettoyer une menace détectée

`clamscan.exe` est un moteur de **détection uniquement** — il ne répare pas les fichiers infectés. La désinfection passe par l'isolement ou la suppression du fichier source.

Chaque ligne du tableau des menaces (`antivirusThreatsGrid`) propose trois actions :

| Bouton | Handler (`AntivirusView`) | Comportement |
|---|---|---|
| **Quarantaine** | `AntivirusActions.QuarantineThreat` | AES-256-GCM ; nom de menace depuis la ligne |
| **Supprimer** | `AntivirusActions.DeleteThreatFile` | Confirmation utilisateur, puis suppression définitive |
| **Ignorer** | `AntivirusActions.IgnoreThreat` | Exclusion du fichier |

`AntivirusActions.ActionCompleted` met à jour la **barre de statut** (`MainWindow`).

En bas du tableau, le bouton **Tout mettre en quarantaine** (`BtnQuarantineAll_Click`) traite toutes les menaces listées en une seule opération.

> **Attention :** toujours préférer la quarantaine à la suppression directe — elle permet de restaurer le fichier en cas de faux positif.

### 4.5 Pipeline de détection en parallèle

Les scans interactifs passent par `ScanViewModel.StartScanAsync` → `ScanOrchestrator` : pour chaque cible, **ClamAV** (daemon **clamd** ou repli **clamscan.exe**) et **YARA** tournent en parallèle (`Task.WhenAll`), puis fusion. Les scans **multi-dossiers** passent par `MultiTargetScanAggregator`. Les **périmètres protégés** optiCOMBAT (installation + `%LOCALAPPDATA%\optiCombat`) sont exclus (`OpticombatProtectedPaths` + `ExclusionSettings`). **`RiskScoringService`** alimente la colonne **Risque**, les toasts et le PDF.

> **clamd** — si `clamd.exe` est présent et l’option **Moteur clamd** est activée (Options), les scans utilisent le daemon TCP (`127.0.0.1:3310`) ; sinon repli sur **`clamscan.exe`**. Note posture Accueil : [§13 Sécurité](#13-sécurité-posture-et-menaces).

```
ScanViewModel → ScanOrchestrator
    │   ├─→ CompositeClamAvBackend (clamd → clamscan)  ─┐
    │   └─→ YaraEngine (.yarc + stamp)                 ├── Task.WhenAll → fusion
    └─→ Progress<ScanProgress> → UI
```

Posture /100 (Accueil), réputation **VirusTotal** (clé API Options), **mode jeu** (toasts / scans headless atténués), identité **Combat Aqua** (cadran de scan circulaire, accent teal).

**Identifiant menace** — `ThreatInfo.Id` : hash **SHA-256** déterministe (`FilePath|VirusName|DetectedAt`) — stable entre redémarrages (pas `string.GetHashCode()`).

### 4.6 Mise à jour des signatures

**Manuel** — `BtnManualUpdateSignatures_Click` enchaîne `FreshclamUpdater.UpdateAsync()` puis `YaraForgeUpdater.UpdateAsync()` (journal dans l’onglet Signatures).

**Automatique** — À l’instanciation de `ServiceContainer.Default`, les minuteries sont armées : **ClamAV toutes les 4 h**, **paquet YARA-Forge toutes les 24 h**. La case **Mise à jour automatique des signatures** dans **Options** coupe ou réactive **les deux** services (`DisableAutoUpdate` / `EnableAutoUpdate`).

### 4.7 Système d'exclusions

`ExclusionSettings` persiste dans :
```
%LOCALAPPDATA%\optiCombat\exclusions.dat
```
(chiffrement **DPAPI** + **HMAC**).

**Périmètres protégés** (`OpticombatProtectedPaths`) — jamais analysés (scans, RTP, quarantaine auto) pour éviter l’**auto-détection** sur les propres fichiers optiCOMBAT :

| Périmètre | Contenu typique |
|-----------|-----------------|
| **Installation** | `{autopf}\optiCombat` (Program Files), répertoire du processus, chemin registre Inno |
| **Données applicatives** | `%LOCALAPPDATA%\optiCombat\` — bases ClamAV (`clamav\database`), règles YARA, quarantaine, logs, staging MAJ (`Updates`), config clamd |

- **Liste Options** : ajout automatique au chargement (`EnsureProtectedFoldersListed`) ; **non supprimables** par l’utilisateur
- **Dossiers utilisateur** : ajout manuel dans **Options → EXCLUSIONS**
- **Règles exclues** : matches YARA filtrés (ex. `SuspiciousDownloads` — exclu par défaut)
- **ClamAV / clamd** : plusieurs `--exclude` / lignes `ExcludePath` (une par racine protégée)
- **RTP** et **scan USB/SD** : mêmes exclusions ; lecteur entier exclu si son chemin racine est listé

**Exclusions Windows Defender** (`WindowsDefenderExclusionService`) — évite que Defender bloque optiCOMBAT, ClamAV ou YARA :

| Moment | Comportement |
|--------|----------------|
| **Installation** | Inno exécute `{app}\scripts\add-defender-exclusions.ps1` (admin) |
| **Démarrage** | Vérification asynchrone ; relance UAC via `--defender-exclusions` si besoin (max 1× / 24 h) |
| **Manuel** | `.\scripts\add-defender-exclusions.ps1` (élévation auto) |

Chemins : mêmes racines que `OpticombatProtectedPaths`. Processus : `optiCombat.exe`, `optiCombat.Service.exe`, `clamscan.exe`, `freshclam.exe`, `clamd.exe`, `yara64.exe`. Si la **protection contre la falsification** Defender est active, ajout manuel dans *Sécurité Windows → Exclusions* — voir [§7](#exclusion-windows-defender).

Configurable depuis **Options → EXCLUSIONS** (exclusions internes optiCOMBAT uniquement).

### 4.8 QuarantineManager — sécurité des fichiers infectés

Les fichiers en quarantaine sont stockés en **AES-256-GCM** (format binaire `OPTQ`, nonce et tag d’authentification).

- Clé maîtresse 256 bits, **DPAPI CurrentUser** (fichier `.key`).
- Manifeste `manifest.json` signé **HMAC-SHA256** (intégrité).

Stockage : `%LOCALAPPDATA%\optiCombat\Quarantine\` — `{guid}.quar` + `manifest.json`. Restauration par défaut ou vers un dossier choisi : `IThreatStore.RestoreTo(quarantineId, destinationFolder)`.

- Si la **suppression du fichier original** échoue après écriture du blob `.quar`, le blob est **supprimé** (rollback) et la quarantaine est annulée.
- Si la **persistance du manifeste** échoue après écriture du blob, l’entrée est retirée et le blob est supprimé.

Pendant un **scan en cours**, `ScanViewModel.ActiveScanSessionId` lie les quarantaines à la session ; les chemins isolés pendant l’analyse sont exclus du résultat final (`RemoveAlreadyQuarantinedThreats`).

### 4.9 Journaux et historique

| Fichier / service | Rôle |
|---|---|
| `ActivityLogService` → `%LocalAppData%\optiCombat\Logs\activity_log.dat` | Timeline **Historique** (DPAPI + HMAC) ; événements : `ScanCompleted`, `CleanCompleted`, `ThreatQuarantined`, `ThreatRestored`, `QuarantineDeleted` ; rétention **150** événements (`MaxActivityEvents`) |
| `ScanLogManager` → `scan_history.dat` / `clean_history.dat` | Détail des sessions ; rotation **100 → 50** ; `Threats[]` ; alimente `ActivityLogService` à chaque scan/nettoyage |
| `ScanLogManager` → `optiCombat.log` | Journal texte volontairement **non chiffré** (diagnostic) ; `FormatScanDetailCore` applique `PathRedaction` sur cible et chemins de menaces — noms de virus, dates et compteurs restent lisibles ; résumé dans **Historique → Scan Antivirus** |
| `AppLogger` → `opticombat-YYYY-MM-DD.log` | Logs applicatifs (composants, erreurs) ; purge **> 30 jours**, au plus **1×/jour** (marqueur `.lastcleanup` persisté) |

**Panneau Historique** (`HistoryControl` + `HistoryViewModel`, `Ctrl+4`) :

- **Timeline** : `ActivityLogService.GetActivityFeed(quarantine)` → `ActivityEntry`, tri date décroissante ; **5 puces** : **Tout**, **Menaces** (scans avec détections en attente), **Scans sains**, **Nettoyages**, **Quarantaine** ; recherche sur type, résumé, cible ou chemins quarantaine.
- **Sélection stable** : clé `SelectionKey` — `SessionId` pour les scans, `EventId` pour quarantaine/restauration/suppression — conservée après `Refresh()`.
- **Refresh** : `ReconcileQuarantinedThreats` retire des sessions persistées les menaces déjà en quarantaine (même chemin d’origine).
- Détail **scan** : grille via `HistoryThreatRow` ; **Quarantaine** / **Ignorer** / **Supprimer** ; **Tout mettre en quarantaine** ; **Traiter dans Analyse**. Détail **quarantaine** : lecture seule ; chemin masqué (`QuarantinePathVisibilityConverter`).
- Types affichés : analyse rapide/complète, fichier, dossier, **lecteur amovible** (`ScanType.RemovableDrive`), nettoyage système, événements quarantaine.

### 4.10 Exports PDF et HTML

- **PDF** — `PdfReportGenerator` : déclenché via `ServiceContainer` (`ExportScanSessionPdfRequested` → `MainWindow.TryExportScanSessionPdf`). Bouton **Historique** : **PDF (sélection)** sur la ligne choisie dans Scan Antivirus.
- **HTML** — `HtmlExportService` : `RequestExportScanHistoryHtml()` depuis **Historique**.

### 4.11 Vue d'ensemble (dashboard)

Le panneau **Vue d'ensemble** (`OverviewControl`, clé `Overview`) regroupe :

- **Hero** : à gauche, titre de protection (« Votre ordinateur est protégé » ou « Protection incomplète » selon les moteurs), **dernière analyse** et bouton **Analyser** (vers l'onglet Antivirus) ; à droite, un **cadran de scan circulaire** (anneau au dégradé vert → bleu en rotation, emblème central pulsant, badge de coche). Pas de détail ClamAV/YARA sur cet écran (voir onglet **Antivirus**).
- **Quatre cartes d'action** : Nettoyer, Antivirus, Historique, mise à jour des signatures (navigation via `ServiceContainer` / `INavigationService`).
- **Deux colonnes** sous les cartes :
  - **Statistiques de protection** : `OverviewProtectionStatsFormatter` (30 j., analyses / fichiers / menaces depuis l’historique) — distinct des recommandations pour éviter le doublon « activité ».
  - **Recommandations** : `OverviewRecommendationsBuilder` (hygiène signatures, suggestion nettoyage) ; `MainWindow` collecte le contexte et met à jour `OverviewControl`.

---

## 5. Services avancés (modules complémentaires)

### RealTimeProtection — surveillance temps réel

`RealTimeProtection.cs` : `FileSystemWatcher` sur dossiers sensibles (profil utilisateur, `ProgramData`, `Temp`, etc.), filtre sur extensions à risque (`RiskyFileExtensions`), délai de stabilisation, déduplication et **SemaphoreSlim(3)** parallèle. Une instance est créée dans **`ServiceContainer`** ; **Options** active ou coupe la surveillance et persiste le réglage. Les menaces détectées remontent vers l’UI (badge / liste) via événements consommés par **`MainWindow`**.

### RemovableDriveScanService — clés USB et cartes SD

`RemovableDriveScanService.cs` : à l’**insertion** d’un volume (WMI `Win32_VolumeChangeEvent` + polling de secours), analyse automatique en arrière-plan si l’option est activée (**Options → Analyser les clés USB et cartes SD**, activée par défaut).

| Aspect | Comportement |
|---|---|
| Détection | `DriveType.Removable` **ou** lecteur `Fixed` reconnu USB via WMI (`InterfaceType`, `PNPDeviceID`, `MediaType`) |
| Déjà branché au démarrage | Enregistré sans scan (évite une vague au lancement) |
| Mode rapide (défaut) | `CollectRiskyFiles` par **extension à risque** (`RiskyFileExtensions`, plafond **4 000**, délai énumération **90 s**) ; **ClamAV `--file-list`** puis **YARA par lots en série** (`scanEnginesSequentially: true`, évite verrous USB) ; **timeout 10 min** ; repli `ScanFolderBackgroundAsync` si erreur/annulation |
| Mode complet (option) | `ScanFolderBackgroundAsync` récursif (ClamAV + YARA en parallèle, **sans pré-dénombrement YARA**) ; **timeout 45 min** |
| Taille max. | **64 Go** par défaut (`RemovableDriveMaxSizeGb` ; `0` = illimité) |
| Analyse complète manuelle | Option **Inclure les lecteurs amovibles** → `ScanTargets.FullScanTargets(includeRemovable: true)` |
| UI / notifications | Toasts début/fin (`ShowRemovableDriveScanStarted` / `ShowRemovableDriveScanCompleted`) si notifications activées ; barre de statut **Démarré** / **Terminé** / **Échec** via `ScanStatusChanged` (`MainWindow`) |
| Menace détectée | Historique (`ScanType.RemovableDrive`), quarantaine auto si activée, liste **Analyser** via `ThreatDetected` (même handler que la RTP) ; RTP **suspendue** pendant le scan |

Un seul scan USB à la fois (**SemaphoreSlim(1)**). `ServiceContainer.ApplyRemovableDriveScan` / `ApplyPreferencesOnStartup` démarrent ou arrêtent le service.

### ScheduledScanService — tâche planifiée Windows

Instance unique : **`ServiceContainer.Default.ScheduledScan`** (partagée avec **Options**, pas d’instance locale isolée). Enveloppe **`schtasks.exe`** pour **`optiCombat_DailyScan`** (`optiCombat.exe --fullscan --quiet`, **`/RL LIMITED`**, heure configurable). **Options** : case planification, sélecteur d’heure, libellé **prochaine exécution** (`GetNextRunTime`), bouton **Lancer maintenant** (`RunNow`). **`App.xaml.cs`** : `--fullscan` / `--quickscan` / `--quiet` en headless (quarantaine auto si activée) — les résultats ne remontent pas dans la grille menaces de la session UI ouverte.

### NotificationService — toasts Windows natifs

`NotificationService.cs` utilise `Microsoft.Toolkit.Uwp.Notifications` pour envoyer des toasts système Windows :

| Méthode | Contenu |
|---|---|
| `ShowThreatDetected(threat)` | Alerte longue avec boutons Quarantaine / Ignorer / Ouvrir |
| `ShowQuarantined(threat)` | Confirmation de mise en quarantaine |
| `ShowScanCompleted(files, threats)` | Résumé de fin de scan |
| `ShowUpdateAvailable(version)` | Nouvelle mise à jour disponible |
| `ShowRealTimeProtectionStarted()` | Confirmation d'activation de la RTP |

### RiskScoringService — score de risque par menace

`RiskScoringService.cs` attribue un score numérique (0–100+) à chaque menace. Affichage : colonne **Risque** dans la grille Antivirus (`ThreatRiskConverters`), toasts, rapport PDF. Critères cumulatifs :

**Critère 1 — Nom du virus (mots-clés)**

| Niveau | Mots-clés |
|---|---|
| CRITIQUE | ransom, rootkit, bootkit, backdoor, worm.win32, wannacry, notpetya… |
| MAJEUR | trojan, worm, spyware, keylogger, dropper, banker, infostealer… |
| MINEUR | adware, pup, pua, hacktool, riskware… |
| INFORMATIONNEL | suspicious, detected |

**Critère 2 — Chemin du fichier**

| Condition | Niveau |
|---|---|
| `\Windows\System32\` ou `\SysWOW64\` | CRITIQUE |
| Extension exécutable (`.exe`, `.dll`, `.ps1`…) | MAJEUR |
| Document avec macro (`.docm`, `.xlsm`…) | MAJEUR |
| Dossier `\Temp\` | MINEUR |

**Critère 3 — Bonus/malus**

- Double détection ClamAV + YARA : **+20 pts**
- Fichier < 1 Mo (payload potentiel) : **+10 pts**
- Fichier > 50 Mo (risque plus faible) : **-10 pts**

**Table de décision finale**

| Score | Niveau | Couleur | Recommandation |
|---|---|---|---|
| ≥ 80 | CRITIQUE | `#C0392B` | Quarantaine/suppression immédiate |
| ≥ 50 | MAJEUR | `#E67E22` | Quarantaine dès que possible |
| ≥ 25 | MINEUR | `#F1C40F` | Surveillance ou quarantaine préventive |
| < 25 | INFORMATIONNEL | `#27AE60` | Aucune action immédiate |

---

## 6. Workflow utilisateur

```
DÉMARRAGE (UI)
    │
    ├─→ Mutex single-instance (2e instance → IPC « afficher » la fenêtre existante)
    ├─→ `App.OnStartup` → `InstallGlobalCrashHandlers()` puis `LocalizationService.Initialize()` (fr-FR / en-US : prefs, registre installateur)
    ├─→ `ThemeManager.Initialize()` (préférence `UserPreferences`)
    ├─→ `MainWindow` : `BindAllViewPanels` avant navigation sidebar ; `ServiceContainer.Default` (ClamAV, YARA, orchestrateur, MAJ, quarantaine, planif., logs, `AntivirusActions`, `ThreatLookup` → VM)
    ├─→ Minuteries MAJ : freshclam **4 h**, règles YARA **24 h** (désactivables via Options)
    ├─→ `ScanViewModel.InitializeAsync` : versions, base, YARA, historique, quarantaine
    ├─→ Protection temps réel : état selon **Options** (`ServiceContainer.RealTimeProtection`)
    ├─→ Scan USB/SD : `ServiceContainer.RemovableDriveScan` si option activée
    └─→ Fenêtre principale + icône zone de notification (réduction possible sans quitter)
            │
            ├─→ [VUE D'ENSEMBLE] — hero (protection + dernière analyse + cadran de scan circulaire), cartes d’action, statistiques 30 j., recommandations
            ├─→ [NETTOYER] — temporaires, caches navigateurs (Edge, Chrome, Firefox, Brave, **Opera**, **Vivaldi**, **Arc**), corbeille, journaux Windows
            ├─→ [ANTIVIRUS] — scans rapide/complet/dossier/fichier, quarantaine, historique de session, signatures
            ├─→ [HISTORIQUE] — timeline `activity_log.dat` (5 filtres) ; sessions : détections, quarantaine / ignorer / supprimer, **Traiter dans Analyse** ; exports **HTML** / **PDF**
            └─→ [OPTIONS] — langue FR/EN, thème (sync Windows par défaut), scan favori, démarrage auto, MAJ auto, RTP, scan USB/SD, quarantaine auto, planification, exclusions

FERMETURE
    └─→ `MainWindow.OnWindowClosing` → `MainWindowShutdownCoordinator.PerformCleanShutdown` → `ServiceContainer.Shutdown()` (RTP, scan USB, minuteries MAJ, moteurs)

DÉMARRAGE (ligne de commande)
    `--fullscan` / `--quickscan` [+ `--quiet` ] → `App.RunHeadlessAsync` : orchestrateur, journal, quarantaine auto si `ExclusionSettings.Current.AutoQuarantineEnabled`, notification fin si menaces et non quiet.
```

---

## 7. Bonnes pratiques

### Permissions et droits

L’application est publiée en **`asInvoker`** (`app.manifest`) : exécution avec les droits de l’utilisateur connecté. Les opérations sur chemins protégés (ex. analyse large sous `C:\Windows`) peuvent demander une **élévation UAC ponctuelle** (`ElevationHelper`) plutôt qu’un administrateur permanent.

### Performance

| Technique | Impact |
|---|---|
| `IsClamAvInstalled()` cache 60 s | Évite un `clamscan --version` à chaque changement d’onglet |
| Pipeline parallèle (Task.WhenAll) | ClamAV + YARA simultanés sur chaque cible |
| `MultiTargetScanAggregator` dédup | Pas de doublons si cibles qui se chevauchent |
| Règles pré-compilées (_compiled.yarc) | Scan comportemental accéléré |
| SemaphoreSlim(3) RTP | `RealTimeProtection` (activable depuis Options) |
| SemaphoreSlim(1) scan USB | `RemovableDriveScanService` (un lecteur à la fois) |
| Scan rapide limité aux dossiers critiques | `ScanTargets.QuickScanTargets()` |
| ExclusionSettings.Current (singleton lazy) | Pas de rechargement JSON par fichier |
| ServiceContainer (singleton services) | Une instance ClamAV/YARA/orchestrateur pour toute l’app |
| ThemeManager + UserPreferences | Bascule de thème sans redémarrage |

### Faux positifs

- `SuspiciousDownloads` exclue par défaut (trop agressive sur le dossier Downloads)
- Ne jamais supprimer automatiquement — toujours mettre en quarantaine en premier
- L'utilisateur confirme avant toute action destructrice (boîte de dialogue `MessageBoxButton.YesNo`)
- Le test EICAR est couvert par la règle YARA embarquée `rules/test_rules.yar` (`EICAR_Test`) ; ClamAV le détecte aussi si la base est à jour

### Exclusion Windows Defender

Voir aussi [§4.7](#47-système-dexclusions) (détail technique). Résumé :

- **À l’installation** (installateur Inno, droits admin) : chemins `Program Files\optiCombat` et `%LOCALAPPDATA%\optiCombat`, plus les processus `optiCombat.exe`, `clamscan.exe`, `freshclam.exe`, `clamd.exe`, `yara64.exe`, etc.
- **Au démarrage** de l’application : même logique si une exclusion manque encore.

Commande manuelle (console **administrateur**) :

```powershell
.\scripts\add-defender-exclusions.ps1
```

Si la **protection contre la falsification** de Defender est active, l’ajout peut échouer — ajoutez les chemins dans *Sécurité Windows → Protection contre les virus et menaces → Exclusions*.

---

## 8. Publication, installateur et checklist release

> **Publication** : assembly **1.0.0** (`Directory.Build.props`, Inno Setup). Build et installateur via `scripts/prepare-release.ps1` (machine de build locale).

### Prérequis machine de build

- Windows 10/11 x64, .NET 8 SDK, Inno Setup 6
- Réseau (téléchargement ClamAV, YARA, signatures freshclam)
- Binaires **non versionnés** dans Git : `.\scripts\fetch-runtime-deps.ps1`

### Chaîne automatique (recommandée)

```powershell
# Depuis la racine du dépôt (dossier contenant optiCombat.sln)
.\scripts\prepare-release.ps1
```

Équivalent manuel : `clean-before-publish` → `fetch-runtime-deps -RunFreshclam` → `dotnet test` → `dotnet publish` → `verify-runtime-deps` → `build-release-setup.ps1`.

Sortie publish : `optiCombat\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\` (chemin attendu par `installer\setup.iss`). Installateur typique : `installer\output\optiCombat_Setup_v1.0.0.exe`.

**Chaîne locale alternative** : `.\installer\build-release-setup.ps1` (nettoie, publie, lance ISCC).

### Ordre recommandé (équipe)

1. Gel fonctionnel : `.\scripts\validate-release-readiness.ps1` (ou `dotnet test` Release — **300** tests).
2. Dépendances : `.\scripts\fetch-runtime-deps.ps1` (+ `-RunFreshclam` pour l’installateur).
3. Publish local : `.\scripts\prepare-release.ps1` (ou étapes manuelles ci-dessous).
4. VM propre : installer `optiCombat_Setup_v1.0.0.exe` ; scan, RTP, clamd, posture, FR/EN.
5. Signature (opt.) : Authenticode — `installer/setup.iss.signing.example`.
6. Tag / distribution : `git tag v1.0.0`, publier `optiCombat_Setup_v1.0.0.exe`.

### Étapes manuelles détaillées

**Étape 0 — nettoyage (recommandé)**

```powershell
.\scripts\clean-before-publish.ps1 -IncludeObj -IncludeInstallerOutput -IncludeCiPublish
```

**Étape A — publication .NET**

```powershell
dotnet publish .\optiCombat\optiCombat.csproj -c Release /p:PublishProfile=FolderProfile
```

**Étape B — première base ClamAV** (adapter `$pub` si vous publiez ailleurs)

```powershell
$pub = ".\optiCombat\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64"
& "$pub\clamav\x64\freshclam.exe" --datadir="$pub\clamav\database"
```

**Étape C — compilateur Inno Setup**

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" .\installer\setup.iss
```

**Installateur** : assistant **bilingue** (français / English) ; langue choisie → `UiCulture` en registre pour le premier lancement de l’app.

**Contenu de l'installateur (~260 Mo avec signatures initiales) :**

```
optiCombat_Setup_v1.0.0.exe
    ├── optiCombat.exe
    ├── optiCombat.ico
    ├── *.dll (runtime .NET 8)
    ├── clamav/x64/          ← Binaires x86-64 (clamscan + clamd) + base de signatures
    ├── yara/                ← Binaires du moteur de détection
    ├── rules/               ← Règles de détection initiales
    └── scripts/             ← add-defender-exclusions.ps1 (exclusions Defender post-install)
```

### Checklist binaire (bloquant)

- [ ] `dotnet test` Release — **300** tests OK
- [ ] `.\scripts\verify-runtime-deps.ps1` — vert sur dossier publish
- [ ] `clamscan.exe`, `freshclam.exe`, **`clamd.exe`**, `yara64.exe`, règles `.yar`
- [ ] `clamav\database\` — au moins un `main.cvd` / `daily.cvd` (via freshclam)
- [ ] Installateur FR/EN, sidebar **v1.0**, options clamd / VT / mode jeu, accueil posture /100 + cadran Combat Aqua
- [ ] Test post-install : scan fichier, quarantaine, historique, exports PDF/HTML ; clé USB ; exclusions Defender

### Qualité, tests et CI

**GitHub Actions** ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) : à chaque push sur `main`, `fetch-runtime-deps` → `dotnet test` Release + `cargo test --workspace`.

**Couverture** : cible progressive **≥ 50 %** lignes ; minimum recommandé **40 %** avant release.

**Freshclam** : `FreshclamUpdater` génère un `freshclam.conf` minimal dans `clamav\x64\` ; freshclam est invoqué avec `--config-file`.

**Repères de couverture tests (release, 300 au total — voir checklist)** :

| Module | Fichier de tests |
|--------|------------------|
| Recommandations accueil | `OverviewRecommendationsBuilderTests` |
| Stats accueil 30 j. | `OverviewProtectionStatsFormatterTests` |
| Posture /100 | `SecurityPostureServiceTests` |
| Historique / timeline | `ActivityLogServiceTests`, `ScanLogManagerTests` ; `HistoryDetailCoordinatorTests`, `HistoryThreatRemediationCoordinatorTests` |
| Coordinateurs MainWindow | `MainWindowStartupCoordinatorTests`, `WindowTrayBehaviorCoordinatorTests`, `ToastActivationCoordinatorTests`, `ExportCoordinatorTests`, … |
| Scan USB/SD | `RemovableDriveDiscoveryTests`, `RemovableDriveScanServiceTests` |
| Intégration EICAR (YARA) | `EicarIntegrationTests` — règle `EICAR_Test` dans `test_rules.yar` (no-op si `yara64.exe` absent) |
| Signatures (cache TTL) | `SignatureStatusServiceTests` |
| Thème Windows | `ThemeManagerPreferenceTests` |
| Persistance | `SecureStoreTests`, `UserPreferencesStorageTests`, `ExclusionSettingsTests`, `OpticombatProtectedPathsTests`, `WindowsDefenderExclusionServiceTests` |

### Après installation

Persistance chiffrée (`scan_history.dat`, `activity_log.dat`, `exclusions.dat`) sous `%LocalAppData%\optiCombat\`.

Architecture UI : [§12.1](#121-architecture-ui).

### Signature Authenticode (optionnelle)

Windows affiche « Éditeur inconnu » sans certificat. Utile pour release publique ; nécessite un `.pfx` et des secrets CI (`CODESIGN_PFX`). Exemple : [`installer/setup.iss.signing.example`](installer/setup.iss.signing.example). Signer `optiCombat.exe` + `optiCombat_Setup_v1.0.0.exe` (`signtool`).

---

## 9. Langues de l’interface (fr-FR / en-US)

| Canal | Comportement |
|-------|----------------|
| **Installateur Inno** | Choix FR ou EN → `HKCU\Software\optiCombat\UiCulture` |
| **Options → Langue** | Français / English → confirmation → **redémarrage** de l’app |
| **Ressources** | `UiStrings.resx` + `UiStrings.en.resx` (**621** clés FR/EN, parité vérifiée par tests) |
| **Menu contextuel** | « Scanner avec optiCOMBAT » ou « Scan with optiCOMBAT » sur **fichiers et dossiers** (`--scan`) |

Les deux langues sont **incluses dans le même binaire** (pas de pack de langue séparé). Les rapports PDF/HTML exportés et les journaux techniques ClamAV/YARA peuvent rester partiellement en français ou en anglais technique.

### Développeurs et traducteurs

| Fichier | Culture |
|---------|---------|
| `optiCombat/Resources/UiStrings.resx` | Français (défaut) |
| `optiCombat/Resources/UiStrings.en.resx` | Anglais (en-US) |

Ajouter une clé : même nom dans les deux `.resx` → XAML `{loc:Loc Key=...}` ou C# `LocalizationService.GetString` / `Format`.

```powershell
dotnet test optiCombat.Tests\optiCombat.Tests.csproj -c Release --filter Localization
```

Non traduit volontairement : sorties brutes clamscan/freshclam/YARA, noms de menaces, chemins, marques ClamAV/YARA. L’UI **Historique** n’affiche pas le libellé moteur (`DetectedBy`) — réservé au pipeline interne.

---

## 10. Dépendances et licences

| Composant | Version | Licence | Notes |
|---|---|---|---|
| ClamAV | Dernière stable | GPLv2 | Inclure la licence dans l'installateur |
| .NET 8 WPF | 8.x | MIT | Inclus dans le runtime Windows |
| MaterialDesignThemes | 5.3.1 | MIT | Bibliothèque UI (PackIcon, styles) |
| QuestPDF | 2024.12.2 | Community | Rapport PDF — licence gratuite projets open-source |
| Mise à jour binaire optiCOMBAT (`UpdateService`) | — | — | Canal OTA non configuré ; staging `%LocalAppData%\optiCombat\Updates` ; signatures via Antivirus |
| Planificateur de tâches (`schtasks.exe`) | — | — | Natif Windows — voir `ScheduledScanService` |
| Microsoft.Toolkit.Uwp.Notifications | 7.1.3 | MIT | Toasts Windows natifs |
| Inno Setup | 6.x | Freeware | Gratuit pour projets commerciaux |
| Base de signatures ClamAV | — | ClamAV License | Mise à jour depuis database.clamav.net |
| Règles de détection | — | Diverses open-source | Récupérées depuis YARA-Forge |

---

## 11. Périmètre fonctionnel v1.0

Première release **optiCOMBAT** — antivirus Windows (ClamAV + YARA).

- **Analyse** — rapide, complète, fichier, dossier, USB/SD ; ClamAV (clamd / clamscan) + YARA ; moteur Rust `opticombat.dll` (repli ClamAV si absent)
- **Protection** — RTP user-mode, quarantaine AES-GCM, exclusions DPAPI + implicites RTP, planificateur, posture /100
- **Historique** — timeline, exports HTML/PDF, sessions chiffrées
- **Interface** — mono-fenêtre Donaby Combat Aqua (FR/EN), cadran de scan circulaire, thèmes clair / sombre / contraste
- **Publication** — installateur `optiCombat_Setup_v1.0.0.exe`, `scripts/prepare-release.ps1`
- **Qualité** — **300** tests Release, NetAnalyzers, SBOM (`scripts/generate-sbom.ps1`)

---

## 12. Qualité et tests

**300** tests unitaires Release ; CI GitHub : `fetch-runtime-deps` → `dotnet test` + `cargo test`.

Couverture cible : **≥ 40 %** lignes (objectif **50 %**).

```powershell
dotnet test optiCombat.Tests\optiCombat.Tests.csproj -c Release
```

| Domaine | Tests représentatifs |
|---------|----------------------|
| Accueil | `OverviewRecommendationsBuilderTests`, `OverviewProtectionStatsFormatterTests`, `SecurityPostureServiceTests` |
| Historique | `ActivityLogServiceTests`, `ScanLogManagerTests`, `HistoryDetailCoordinatorTests` |
| Scan / RTP | `ScanOrchestratorTests`, `RealTimeProtectionTests`, `EicarIntegrationTests` |
| Quarantaine / exclusions | `QuarantineManagerTests`, `ExclusionSettingsTests`, `OpticombatProtectedPathsTests` |
| i18n | `LocalizationServiceTests` |

### 12.1 Architecture UI

La logique événementielle est dans `optiCombat/Coordinators/`. `MainWindow` enregistre les panneaux, branche `ServiceContainer` et les raccourcis de navigation.

**`optiCombat.log`** — journal diagnostic non chiffré ; chemins redacted via `PathRedaction`.

**Posture accueil** — liens `opticombat://panel/...` et replis `ms-settings` / `control.exe` ; couvert par `SecurityPostureServiceTests`.

---

## 13. Sécurité (posture et menaces)

### Note posture /100 (Accueil)

| Id | Poids | Source |
|----|-------|--------|
| `firewall` | 15 | Domain / Standard / Public (`EnableFirewall`) |
| `uac` | 10 | `EnableLUA` |
| `wupdate` | 15 | `IWindowsUpdateProbe` (registre, WMI, WUA) |
| `shares` | 10 | Partages SMB (`REG_MULTI_SZ`) |
| `opticombat` | 25 | ClamAV + YARA + RTP |
| `scan` | 15 | Dernière analyse &lt; 7 jours |
| `sigauto` | 10 | MAJ signatures auto |

Limite : les trois profils pare-feu sont lus au registre, pas le profil réseau « actif » en temps réel.

Liens **Corriger** (accueil) : `opticombat://panel/{id}` (antivirus, options, history, clean, overview) ; UAC → `UserAccountControlSettings.exe` (+ repli `control.exe`) ; pare-feu → `ms-settings:windowsdefender-firewall` (+ replis) ; partages → `advancedsharing|control.exe` (séparateur `|`).

### Modèle de menace (périmètre local)

**Actifs** : fichiers analysés, quarantaine, prefs/exclusions (`%LocalAppData%\optiCombat`), clé VT optionnelle.

**Contrôles** : quarantaine AES-GCM + HMAC ; exclusions avec frontière `\` ; périmètres protégés optiCOMBAT (`OpticombatProtectedPaths`) ; exclusions Defender automatiques (`WindowsDefenderExclusionService`) ; UAC pour scan complet ; RTP ; clamd sur `127.0.0.1`.

**Limites** : malware admin peut neutraliser l’AV local ; AMSI via `optiCombat.AmsiProvider.dll` (nécessite service + droits admin) ; minifilter encore stub ; VT envoie le hash ; `optiCombat.log` non chiffré mais sans chemins complets (`PathRedaction` sur les lignes de scan).

---

## 14. Crédits

Développé par **© 2026 Donatien Byakombe**  
Design system : **Donaby Design**
