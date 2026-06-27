# Changelog

Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [1.0.0] — 2026-06-26

Première release publique sous la marque **optiCOMBAT**.

### Added

- Application WPF .NET 8 : scans ClamAV (clamscan / clamd) + YARA en parallèle
- Cœur moteur Rust (`opticombat.dll`) avec repli managé si absent
- Protection temps réel user-mode, quarantaine AES-GCM, historique chiffré
- Interface FR/EN (621 clés), thèmes Donaby (clair / sombre / contraste)
- Installateur Inno bilingue `optiCombat_Setup_v1.0.0.exe`
- Scripts release : `prepare-release.ps1`, exclusions Defender, signature dev locale
- **300** tests unitaires Release

### Notes

- Couche plateforme (service Windows, AMSI, minifiltre) incluse mais **non activée** par défaut
- Canal de mise à jour OTA non configuré (`UpdateService` en attente)

[1.0.0]: https://github.com/1donatien0/optiCOMBAT/releases/tag/v1.0.0
