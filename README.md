# optiCOMBAT v1.0

Antivirus Windows open source — interface **WPF .NET 8**, moteurs **ClamAV** + **YARA**, cœur natif **Rust** (`opticombat.dll`), design **Donaby Combat Aqua**.

[![CI](https://github.com/1donatien0/optiCOMBAT/actions/workflows/ci.yml/badge.svg)](https://github.com/1donatien0/optiCOMBAT/actions/workflows/ci.yml)

**Version** : **v1.0** · assembly / installateur **1.0.0**

> Identifiants techniques : `optiCombat.exe`, dossiers `optiCombat/`, `%LocalAppData%\optiCombat`.

---

## Fonctionnalités

| Domaine | Contenu |
|---------|---------|
| **Analyse** | Rapide, complète, fichier, dossier, clés USB/SD |
| **Protection** | RTP user-mode, quarantaine AES-GCM, exclusions DPAPI, posture /100 |
| **Interface** | Mono-fenêtre FR/EN, thèmes Combat Aqua (clair / sombre / contraste), cadran de scan circulaire |
| **Publication** | Installateur Inno `optiCombat_Setup_v1.0.0.exe` |

La couche plateforme (service Windows, AMSI, minifiltre) est **incluse mais inactive** par défaut — protection sans pilote signé.

---

## Installation

Installez **`optiCombat_Setup_v1.0.0.exe`** (build local ci-dessous ou binaire publié).

Prérequis : Windows 10/11 **x64**, droits administrateur pour l’installateur.

---

## Développement

```powershell
git clone https://github.com/1donatien0/optiCOMBAT.git
cd optiCOMBAT
.\scripts\fetch-runtime-deps.ps1
dotnet build optiCombat.sln -c Release
dotnet test optiCombat.Tests\optiCombat.Tests.csproj -c Release
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
| [docs/GUIDE_COMPLET.md](docs/GUIDE_COMPLET.md) | Architecture, interface, publication |
| [docs/README.md](docs/README.md) | Index documentation |
| [SECURITY.md](SECURITY.md) | Vulnérabilités, modèle de menace |
| [CHANGELOG.md](CHANGELOG.md) | Notes de version |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build, tests, contributions |
| [LICENSE.txt](LICENSE.txt) | Licence |

---

## Qualité

- **300** tests unitaires Release
- Tests Rust : `cargo test --workspace --manifest-path engine/Cargo.toml`
- CI sur chaque push `main` (C# + Rust)

---

## Crédits

© 2026 **Donatien Byakombe** — **Donaby Design**

ClamAV (GPLv2), YARA, Inno Setup — voir [§10 du guide complet](docs/GUIDE_COMPLET.md#10-dépendances-et-licences).
