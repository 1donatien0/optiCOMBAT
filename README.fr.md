<p align="center">
  <img src="assets/branding/optiCombat_emblem_transparent.png" alt="optiCOMBAT" width="180">
</p>

<h1 align="center">optiCOMBAT</h1>

<p align="center">
  <strong>Antivirus et optimiseur gratuit pour Windows, avec une interface WinUI 3, ClamAV et YARA.</strong><br>
  Aucun compte, aucune publicité, aucune télémétrie.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v1.0.0-2ea44f?style=for-the-badge&logo=windows" alt="optiCOMBAT v1.0.0 pour Windows">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/plateforme-Windows%2010%20%7C%2011%20x64-0078D6" alt="Plateforme : Windows 10 et 11 x64">
  <img src="https://img.shields.io/badge/.NET-8-512BD4" alt=".NET 8">
  <img src="https://img.shields.io/badge/interface-WinUI%203-0078D4" alt="WinUI 3">
  <a href="https://github.com/1donatien0/optiCOMBAT/actions/workflows/ci.yml"><img src="https://github.com/1donatien0/optiCOMBAT/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/1donatien0/optiCOMBAT/actions/workflows/codeql.yml"><img src="https://github.com/1donatien0/optiCOMBAT/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
</p>

<p align="center">
  <a href="README.md">English</a> · Français
</p>

## Pourquoi optiCOMBAT ?

La plupart des antivirus « gratuits » poussent vers une version payante, collectent des données ou affichent de la publicité. optiCOMBAT est une application Windows qui réunit deux moteurs de détection reconnus, [ClamAV](https://www.clamav.net/) et [YARA](https://virustotal.github.io/yara/), derrière une interface WinUI 3, et y ajoute le nettoyage et les réglages qu’on cherche d’habitude dans un optimiseur à part. Les mises à jour de signatures sont le seul trafic réseau. Il n’y a aucun compte, aucune publicité et aucune télémétrie.

optiCOMBAT est conçu pour **fonctionner à côté de Windows Defender**, pas pour le remplacer. Au premier lancement, si Defender est actif, l’application propose de lui laisser la protection en temps réel. Les exclusions pour optiCOMBAT restent désactivées tant qu’on ne les active pas dans Options.

## Fonctionnalités

**Antivirus**

- Analyse rapide, complète ou personnalisée, d’un fichier ou d’un dossier
- « Scanner avec optiCombat » dans le menu contextuel de l’Explorateur
- ClamAV et YARA en parallèle, avec mise à jour automatique des signatures et des règles YARA-Forge
- Cœur Rust optionnel (`opticombat_engine.dll`), désactivé par défaut : Options → « Cœur natif Rust (expérimental) »
- Protection en temps réel en mode utilisateur et surveillance des processus
- Analyse automatique des clés USB et cartes SD, et analyse planifiée
- Quarantaine chiffrée (AES-GCM), avec restauration et suppression
- Historique des analyses avec rapports HTML et PDF
- Score de sécurité sur 100, avec corrections en un clic
- Mode complément de Windows Defender

**Optimiseur**

- Nettoyage des fichiers temporaires, des caches de sept navigateurs, de la corbeille, des journaux Windows, du cache Windows Update, du cache DNS et de l’historique de navigation
- Mise à jour des applications avec `winget`, et un accès à Windows Update
- Quatorze réglages Windows

**Interface**

- Une seule fenêtre WinUI 3, entièrement en français et en anglais
- Thèmes clair, sombre et contraste renforcé, en suivant le thème de Windows
- Presets d’accent : Combat Aqua, Minuit, Océan, Braise, plus une couleur personnalisée
- Mica, barre d’état en direct, guide de premier lancement et icône dans la zone de notification

## À savoir

La couche plateforme — service Windows, AMSI et minifiltre — est **incluse mais inactive**. La protection fonctionne sans pilote signé. Windows Defender reste la protection en temps réel à laisser active.

Une mise à jour remplace l’application dans le même dossier. L’historique, la quarantaine et les préférences restent en place. Il n’est pas nécessaire de désinstaller.

| Quoi | Où |
|------|-----|
| Programme | `optiCombat.exe` |
| Données d’analyse, historique, quarantaine | `%LocalAppData%\optiCombat` |
| Préférences | `%AppData%\optiCombat` |
| Installateur | `optiCombat_Setup_v1.0.0.exe` (autonome, mise à jour sur place) |

## Installation

1. Lancez **`optiCombat_Setup_v1.0.0.exe`**. Compilez-le avec le script de publication ci-dessous, ou utilisez un binaire publié lorsqu’une release en joint un.
2. Choisissez le français ou l’anglais, puis terminez l’installation. L’installateur demande les droits administrateur. Le runtime .NET est inclus.
3. Ouvrez optiCOMBAT et laissez-le télécharger les signatures ClamAV et les règles YARA. Laissez Windows Defender actif.

**Prérequis :** Windows 10 ou Windows 11, 64 bits.

## Comment ça marche

```
optiCombat.exe              interface WinUI 3 (.NET 8)
    ├── ClamAV              clamd, ou clamscan en repli
    ├── YARA                règles, dont YARA-Forge
    └── opticombat_engine.dll      cœur Rust optionnel, désactivé par défaut
          ├── reputation    listes de hashes ; MalwareBazaarDb si l'appelant charge un CSV
          ├── yara-engine   règles YARA locales
          ├── heuristics    PE, ML
          └── ioc-engine    URLhaus + ThreatFox, vide tant qu'aucun feed n'est chargé

Couche plateforme           service Windows, AMSI, minifiltre
                            livrée avec le produit, inactive
```

Avec une Auth-Key abuse.ch saisie dans les Options (compte gratuit ; exigée par abuse.ch depuis le 30 juin 2025), le shell télécharge les exports MalwareBazaar, URLhaus et ThreatFox toutes les 12 heures (6 heures minimum) dans `%LOCALAPPDATA%\optiCombat\threat_intel`, puis le moteur natif les charge via `opticombat_load_threat_intel`. Sans clé, le moteur IOC reste vide. Le cœur Rust lui-même ne fait aucun appel réseau.

Le guide technique couvre l’architecture, le modèle de sécurité, la compilation et la publication : **[docs/GUIDE_COMPLET.md](docs/GUIDE_COMPLET.md)**.

## Compiler depuis les sources

```powershell
git clone https://github.com/1donatien0/optiCOMBAT.git
cd optiCOMBAT
.\scripts\fetch-runtime-deps.ps1
dotnet build optiCombat.sln -c Release
.\scripts\build-engine.ps1
dotnet test optiCombat.Tests\optiCombat.Tests.csproj -c Release
dotnet run --project optiCombat.WinUI\optiCombat.WinUI.csproj
```

Il faut Windows 10 ou 11 x64, le SDK .NET 8 et Rust. La compilation de l’installateur demande aussi Inno Setup 6. Détail : [CONTRIBUTING.md](CONTRIBUTING.md).

Publication complète (tests, publish, `opticombat_engine.dll`, installateur) :

```powershell
.\scripts\prepare-release.ps1
# Sortie : installer\output\optiCombat_Setup_v1.0.0.exe
```

## Documentation

| Document | Sujet |
|----------|--------|
| [docs/GUIDE_COMPLET.md](docs/GUIDE_COMPLET.md) | Architecture, interface, moteurs, publication, qualité |
| [docs/SHELL_WINUI.md](docs/SHELL_WINUI.md) | Shell WinUI 3 |
| [docs/GUIDE_DISTRIBUTION.md](docs/GUIDE_DISTRIBUTION.md) | Signature et cohabitation avec les autres antivirus |
| [engine/README.md](engine/README.md) | Cœur de détection Rust |
| [SECURITY.md](SECURITY.md) | Vulnérabilités et modèle de menace |
| [CHANGELOG.md](CHANGELOG.md) | Notes de version |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Compilation, tests, contributions |

## Qualité

Tests unitaires Release (xUnit) : **943** tests, ViewModels du shell inclus. Aucun test ne touche le poste : les outils externes (winget, freshclam, clamscan, YARA, schtasks, clamd) sont remplacés par un exécutable factice ; processus et registre (tweaks, exclusions Defender, `sc.exe`, relance UAC, langue, démarrage automatique, menu contextuel) passent par un `ISystemShell` enregistreur ; toute l’exécution est redirigée vers un `%APPDATA%` / `%LOCALAPPDATA%` temporaire. Plancher CI de couverture de lignes **85 %**, cible **90 %**. Dernière mesure Linux : **87,1 %** des lignes (10 393 / 11 939) et **80,5 %** des branches, où 16 tests réservés à Windows ne tournent pas. Sur Windows, avec les mêmes réglages coverlet que la CI, les **943** tests passent : **89,8 %** des lignes (10 724 / 11 939) et **84,3 %** des branches. Le plancher de 85 % est tenu, la cible de 90 % non.

Rust : **170** fonctions `#[test]` exécutées par `cargo test --workspace --manifest-path engine/Cargo.toml`, plus 1 doctest (`extract_host`). Trois tests Windows restent derrière la feature `windows-platform`. Couverture de lignes mesurée **92,6 %**, plancher CI **90 %** (`cargo llvm-cov`, cible 95 %), plus `cargo clippy -D warnings` et `cargo fmt --check`.

La CI lance les tests C# et Rust, CodeQL, Gitleaks, Dependency Review et Dependabot.

## Contribuer

Questions, bogues et faux positifs : [ouvrir une issue](https://github.com/1donatien0/optiCOMBAT/issues).

Failles de sécurité : signalez-les en privé, comme indiqué dans [SECURITY.md](SECURITY.md).

## Licence

optiCOMBAT est un logiciel gratuit distribué selon le [contrat de licence](LICENSE.txt), sans garantie. Vous pouvez l’utiliser et le redistribuer sans le modifier et sans le vendre. ClamAV (GPL-2.0), YARA-Forge et les autres composants livrés gardent leur propre licence.

Conçu par **Dona By (Donatien Byakombe)** à Vanier (Ottawa), Canada.
