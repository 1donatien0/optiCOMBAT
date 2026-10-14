# Changelog

Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [Unreleased]

## [1.0.0] — 2026-09-30

Première release publique sous la marque **optiCOMBAT**. Shell livré : **WinUI 3** (`optiCombat.exe`). Le shell WPF n’est plus dans le dépôt.

### Added

- Application WinUI 3 .NET 8 : scans ClamAV (clamscan / clamd) + YARA en parallèle
- Cœur moteur Rust (`opticombat.dll`) avec repli managé si absent
- Protection temps réel user-mode, quarantaine AES-GCM, historique chiffré
- Exclusions utilisateur (DPAPI) et exclusions implicites RTP : scripts IDE (`ps-script-*.ps1` dans `%TEMP%`), dépôt de dev, fichiers signatures AppData (`ScanImplicitExclusions`)
- Interface entièrement FR / EN, thèmes Donaby **Combat Aqua** (clair / sombre / contraste renforcé)
- Accueil : posture /100, statistiques 30 j., recommandations, cadran de scan, menu d’analyse (rapide / complète / personnalisée)
- **Optimiser** : onglets **Nettoyage**, **Mises à jour** (winget, accès à Windows Update) et **Tweaks** (14 réglages)
- Nettoyage : temporaires, caches de 7 navigateurs, corbeille, journaux Windows, cache Windows Update, DNS, historique de navigation Chromium, bouton **Copier le journal**
- Antivirus : actions par menace (Réputation VirusTotal, Ignorer, Quarantaine, Supprimer), puces Récents, quarantaine paginée, **Arrêter** et barre de progression pour les signatures
- Options : **Lancer maintenant** (analyse planifiée), dossier des journaux, contrat de licence, mode complément de Defender, exclusions Defender **opt-in**, **Analyser en administrateur**
- Score de sécurité : corrections en un clic (pare-feu, UAC, partages, RTP, MAJ auto, analyse)
- Historique : **Traiter dans Analyse** / **Voir en quarantaine**
- Installateur Inno bilingue self-contained `optiCombat_Setup_v1.0.0.exe` ; mise à jour sur place
- Scripts release : `prepare-release.ps1`, exclusions Defender, qualification détection
- CI GitHub (C# + Rust, CodeQL, Gitleaks, Dependency Review) ; Dependabot vers `dev` (PRs groupées, branches temporaires)

### Changed

- Identité de l’installateur : `AppId` Inno propre à optiCOMBAT ; cohabitation possible avec optiSCAN
- Contraste renforcé dans Options ; interrupteur **Suivre le thème de Windows** ; accent Combat Aqua
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

- Plafond de débit sur le pipe IPC (`scan_path` / `scan_buffer`)
- Vérification d’intégrité des paquets de règles YARA-Forge avant installation
- Validation des chemins d’analyse externes
- ACL restreinte sur la quarantaine et sur `%LocalAppData%\optiCombat` quand les exclusions Defender sont ajoutées

### Notes

- Couche plateforme (service Windows, AMSI, minifiltre) incluse mais **inactive** — protection sans pilote signé
- Windows Defender reste la protection temps réel recommandée
- Canal de mise à jour OTA non configuré (`UpdateService` en attente)

[1.0.0]: https://github.com/1donatien0/optiCOMBAT/releases/tag/v1.0.0
