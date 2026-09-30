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

> **Protection par défaut : user-mode.** Temps réel via `FileSystemWatcher` et surveillance des processus (WMI), sans pilote ni signature Microsoft (`UsePlatformProtectionService = false`). La couche plateforme (service Windows, AMSI, minifiltre) est **dans le code mais inactive** (`PlatformProtectionFeatureGate.IsUserActivatable = false`).

- **Auto-exclusion** : répertoire d’installation et `%LocalAppData%\optiCombat` jamais analysés ni mis en quarantaine automatiquement (`OpticombatProtectedPaths`).
- **Windows Defender** : exclusions **opt-in uniquement** (Options → *Exclusions Windows Defender*, ou `scripts/add-defender-exclusions.ps1` en admin). Jamais appliquées par l’installateur ni au démarrage : un antivirus ne doit pas s’exclure silencieusement de Defender. La protection contre la falsification peut exiger un ajout manuel.
- **IPC** : pipe ACL (`ProtectionPipeAcl`), buffers plafonnés, et débit de `scan_path` / `scan_buffer` limité (`IpcScanRateLimiter` : 120/min, 4 simultanés) contre le DoS local.
- **Règles YARA-Forge** : signature ZIP, taille et digest SHA-256 publiés par GitHub vérifiés avant installation (`YaraForgePackageIntegrity`) ; un paquet invalide est rejeté et les règles actuelles sont conservées.
- **freshclam** : aucune directive `CVDCertsDirectory` (rejetée par ClamAV 1.4+) ; certificats via `CVD_CERTS_DIR`, anciens conf régénérés.
- **Antivirus tiers** : les exclusions Defender ne s’appliquent pas à Kaspersky, Bitdefender, etc. Voir `scripts/kaspersky-exclusions-guide.ps1` ; signature Authenticode recommandée en production (`scripts/sign-release.ps1`).
- **Quarantaine** : AES-256-GCM, manifeste HMAC, clé maîtresse DPAPI ; contrôle des chemins à la restauration ; dossier en ACL restreinte (propriétaire, SYSTEM, Administrateurs — `DirectoryHardening`), appliquée aussi à `%LocalAppData%\optiCombat` quand les exclusions Defender sont ajoutées.
- **Chemins d’analyse externes** (`--scan`, ligne de commande, pipe IPC) : validés par `ScanPathValidation` (pas de chemin de périphérique `\\.\` / `\\?\`, pas de caractère de contrôle, chemin existant ; dossiers système refusés côté IPC).
- **Actions destructives** : toute suppression définitive demande une confirmation (« Non » par défaut) ; les corrections système du score de sécurité passent par confirmation puis une seule invite UAC, avec des commandes construites par l’application (aucun métacaractère `cmd.exe` accepté).
- **Chemins sensibles** : restauration et scan IPC refusent System32, Windows, ProgramFiles, ProgramData, Startup.
- **Secrets** : préférences (clé VirusTotal) chiffrées DPAPI + HMAC ; aucun secret dans le dépôt (Gitleaks en CI).
- **Réseau** : seule la réputation VirusTotal (opt-in, clé API de l’utilisateur) envoie une donnée — le hash SHA-256 ; clamd écoute uniquement sur `127.0.0.1:3310`.
- **CI** : `dotnet test` Release avec couverture (plancher 40 %), `cargo test`, `cargo audit` ; CodeQL (C#, Rust, Actions), Gitleaks, Dependency Review, Dependabot (NuGet, Cargo, Actions) ; publish + SBOM CycloneDX sur `main`.

## Threat model

optiCOMBAT est un **antivirus de bureau Windows** :

- Protection contre les menaces user-space courantes et les mauvaises configurations.
- **Pas** de garantie contre un malware aux mêmes privilèges utilisateur ou au niveau noyau.
- DPAPI `CurrentUser` protège les données locales des autres utilisateurs, pas d’une session compromise.

## Optional hardening

- Signature Authenticode (exe, DLL, installateur)
- Pilote minifiltre signé (couche plateforme)
