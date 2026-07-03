# Changelog

Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [Unreleased]

### Changed

- Migration **WinUI 3** : shell principal `optiCombat.WinUI` (binaire `optiCombat.exe`), couche partagée `optiCombat.Application`, installateur ciblant le publish WinUI
- Retrait de l’option **Contraste renforcé** dans Paramètres (WinUI et WPF) — réévaluation ultérieure

## [1.0.0] — 2026-06-26

Première release publique sous la marque **optiCOMBAT**.

### Added

- Application WPF .NET 8 : scans ClamAV (clamscan / clamd) + YARA en parallèle
- Cœur moteur Rust (`opticombat.dll`) avec repli managé si absent
- Protection temps réel user-mode, quarantaine AES-GCM, historique chiffré
- Exclusions utilisateur (DPAPI) et exclusions implicites RTP : scripts IDE (`ps-script-*.ps1` dans `%TEMP%`), dépôt de dev, fichiers signatures AppData (`ScanImplicitExclusions`)
- Interface FR/EN (621 clés), thèmes Donaby **Combat Aqua** (clair / sombre / contraste) — accent teal / cyan, fonds blanc et navy
- Accueil : posture /100, statistiques 30 j., recommandations, **cadran de scan circulaire** (anneau vert → bleu, emblème pulsant) et bouton **Analyser**
- Barre latérale : navigation mono-fenêtre, élément actif en pilule teal
- Scan antivirus : rapide, complète, fichier, dossier, clés USB/SD ; réputation VirusTotal (clé API Options) ; mode jeu
- Assets branding : emblème, logo horizontal, hero accueil fond transparent (`generate-brand-assets.py`)
- Installateur Inno bilingue `optiCombat_Setup_v1.0.0.exe`
- Scripts release : `prepare-release.ps1`, exclusions Defender, qualification détection
- **300** tests unitaires Release ; CI GitHub (C# + Rust)
- `RollForward=Major` (.NET Desktop Runtime) pour compatibilité avec les runtimes 8.0.x installés

### Notes

- Couche plateforme (service Windows, AMSI, minifiltre) incluse mais **non activée** par défaut
- Canal de mise à jour OTA non configuré (`UpdateService` en attente)

[1.0.0]: https://github.com/1donatien0/optiCOMBAT/releases/tag/v1.0.0
