# optiCOMBAT v1.0

Antivirus Windows open source — shell **WinUI 3** (.NET 8), moteurs **ClamAV** + **YARA**, cœur natif **Rust** (`opticombat.dll`), design **Donaby Combat Aqua**.

> **Branche active** : `dev` — WinUI 3 est le shell unique. Le shell WPF legacy a été retiré (snapshot conservé hors dépôt).

[![CI](https://github.com/1donatien0/optiCOMBAT/actions/workflows/ci.yml/badge.svg)](https://github.com/1donatien0/optiCOMBAT/actions/workflows/ci.yml) [![CodeQL](https://github.com/1donatien0/optiCOMBAT/actions/workflows/codeql.yml/badge.svg)](https://github.com/1donatien0/optiCOMBAT/actions/workflows/codeql.yml)

**Version** : **v1.0** · assembly / installateur **1.0.0**

> Identifiants techniques : `optiCombat.exe`, projets `optiCombat.*`, données `%LocalAppData%\optiCombat` (préférences : `%AppData%\optiCombat`).

---

## Fonctionnalités

| Domaine | Contenu |
|---------|---------|
| **Analyse** | Rapide, complète, fichier, dossier, clés USB/SD, menu contextuel Explorateur ; cœur Rust si `opticombat.dll` est livrée |
| **Protection** | RTP user-mode + surveillance des processus, anti-sabotage, quarantaine AES-GCM, exclusions DPAPI, analyse planifiée, score de sécurité /100 avec corrections en un clic, mode complément de Defender |
| **Optimisation** | Nettoyage (temporaires, caches de 7 navigateurs, corbeille, journaux Windows, cache Windows Update, DNS, historique de navigation), mises à jour des applications (winget) et 14 tweaks Windows |
| **Interface** | Mono-fenêtre WinUI 3 entièrement FR / EN, thèmes clair / sombre / contraste renforcé, guide de premier lancement, zone de notification |
| **Publication** | Installateur Inno self-contained `optiCombat_Setup_v1.0.0.exe`, mise à jour sur place |

La couche plateforme (service Windows, AMSI, minifiltre) est **incluse mais inactive** — protection sans pilote signé. Windows Defender reste la protection temps réel recommandée ; ses exclusions pour optiCOMBAT sont **opt-in** (Options).

---

## Installation

Installez **`optiCombat_Setup_v1.0.0.exe`** (build local ci-dessous ou binaire publié).

Une version déjà présente est remplacée dans le même dossier. L’historique, la quarantaine et les préférences restent dans `%LocalAppData%\optiCombat`. Il n’est pas nécessaire de désinstaller.

Prérequis : Windows 10/11 **x64**, droits administrateur pour l’installateur (runtime .NET embarqué).

---

## Développement

```powershell
git clone https://github.com/1donatien0/optiCOMBAT.git
cd optiCOMBAT
git checkout dev
.\scripts\fetch-runtime-deps.ps1
dotnet build optiCombat.sln -c Release
dotnet test optiCombat.Tests\optiCombat.Tests.csproj -c Release
dotnet run --project optiCombat.WinUI\optiCombat.WinUI.csproj
```

**Moteur Rust** :

```powershell
.\scripts\build-engine.ps1
```

**Release complète** (tests, publish, `opticombat.dll`, installateur) :

```powershell
.\scripts\prepare-release.ps1
# Sortie : installer\output\optiCombat_Setup_v1.0.0.exe
```

---

## Documentation

| Document | Sujet |
|----------|--------|
| [docs/MIGRATION_WINUI3.md](docs/MIGRATION_WINUI3.md) | Migration WinUI 3, architecture, publish |
| [docs/GUIDE_COMPLET.md](docs/GUIDE_COMPLET.md) | Architecture, interface, moteurs, publication, qualité |
| [docs/GUIDE_DISTRIBUTION.md](docs/GUIDE_DISTRIBUTION.md) | Diffusion, signature, cohabitation antivirus |
| [engine/README.md](engine/README.md) | Cœur moteur Rust |
| [docs/README.md](docs/README.md) | Index documentation |
| [SECURITY.md](SECURITY.md) | Vulnérabilités, modèle de menace |
| [CHANGELOG.md](CHANGELOG.md) | Notes de version |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build, tests, contributions |
| [LICENSE.txt](LICENSE.txt) | Licence |

---

## Qualité

- Tests unitaires Release (xUnit) avec couverture mesurée — plancher CI **40 %**
- Tests Rust : `cargo test --workspace --manifest-path engine/Cargo.toml` + `cargo audit`
- CI sur `main` / `dev` : tests C# + Rust, CodeQL, Gitleaks, Dependency Review, Dependabot ; publish + SBOM sur `main`

---

## Crédits

© 2026 **Donatien Byakombe** — **Donaby Design**

ClamAV (GPLv2), YARA, Inno Setup — voir [§10 du guide complet](docs/GUIDE_COMPLET.md#10-dépendances-et-licences).
