# Security Policy — optiCOMBAT

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x (`main`) | Yes |

## Reporting a vulnerability

1. **Do not** open a public GitHub issue for exploitable vulnerabilities.
2. Contact the maintainer with: description, reproduction steps, impact, and version (**1.0.0**).
3. Allow up to **14 business days** for an initial response.

## Security architecture

> **Protection par défaut : user-mode.** Temps réel via `FileSystemWatcher`, sans pilote ni signature Microsoft (`UsePlatformProtectionService = false`). La couche plateforme (service Windows, AMSI, minifiltre) est **dans le code mais inactive** (`PlatformProtectionFeatureGate.IsUserActivatable = false`).

- **Auto-exclusion** : répertoire d’installation et `%LocalAppData%\optiCombat` jamais analysés ni mis en quarantaine automatiquement (`OpticombatProtectedPaths`).
- **Windows Defender** : chemins et processus optiCOMBAT enregistrés au démarrage et à l’installation (`WindowsDefenderExclusionService`, `scripts/add-defender-exclusions.ps1`). La protection contre la falsification peut exiger une exclusion manuelle.
- **Antivirus tiers** : les exclusions Defender ne s’appliquent pas à Kaspersky, Bitdefender, etc. Voir `scripts/kaspersky-exclusions-guide.ps1` ; signature Authenticode recommandée en production (`scripts/sign-release.ps1`).
- **Quarantaine** : AES-256-GCM, manifeste HMAC, clé maîtresse DPAPI ; contrôle des chemins à la restauration.
- **Chemins sensibles** : restauration et scan IPC refusent System32, Windows, ProgramFiles, ProgramData, Startup.
- **Secrets** : préférences (clé VirusTotal) via `SecureStore` DPAPI ; aucun secret dans le dépôt.
- **CI** : `dotnet test` Release (**300** tests) + `cargo test` sur `main`.

## Threat model

optiCOMBAT est un **antivirus de bureau Windows** :

- Protection contre les menaces user-space courantes et les mauvaises configurations.
- **Pas** de garantie contre un malware aux mêmes privilèges utilisateur ou au niveau noyau.
- DPAPI `CurrentUser` protège les données locales des autres utilisateurs, pas d’une session compromise.

## Optional hardening

- Signature Authenticode (exe, DLL, installateur)
- Pilote minifiltre signé (couche plateforme)
