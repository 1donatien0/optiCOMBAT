# Contribuer à optiCOMBAT

Merci de votre intérêt pour **optiCOMBAT**. Ce dépôt est maintenu par **1donatien0**.

## Prérequis

- Windows 10/11 x64
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [Inno Setup 6](https://jrsoftware.org/isinfo.php) (installateur uniquement)
- [Rust stable](https://rustup.rs) (moteur `opticombat.dll`, recommandé)
- Python 3 + Pillow (régénération assets : `scripts/generate-brand-assets.py`)

## Clone et build

```powershell
git clone https://github.com/1donatien0/optiCOMBAT.git
cd optiCOMBAT
.\scripts\fetch-runtime-deps.ps1
dotnet build optiCombat.sln -c Release
.\scripts\build-engine.ps1
dotnet test optiCombat.Tests\optiCombat.Tests.csproj -c Release
```

## Environnement de développement

Windows Defender et **Smart App Control** peuvent bloquer les DLL locales (`0x800711C7`).

```powershell
.\scripts\add-defender-exclusions.ps1 -DevWorkspace
# Une fois en admin :
.\scripts\setup-dev-trust-admin.ps1
.\scripts\sign-dev-local.ps1
```

Ne commitez **jamais** : `.pfx`, `.env`, secrets, bases ClamAV `.cvd`, sorties `installer/output/`, `bin/`, `obj/`.

## Branche et commits

- Travaillez sur **`main`** ou une branche feature `feature/...`
- Messages de commit clairs, en français ou anglais
- Un seul auteur sur les commits du dépôt officiel (**1donatien0**)

## Pull requests

1. `dotnet test` Release vert (**300** tests)
2. `cargo test --workspace --manifest-path engine/Cargo.toml` si vous touchez le moteur Rust
3. Pas de régression i18n (clés FR/EN paritaires)
4. Documenter les changements utilisateur dans `CHANGELOG.md`

## Release (maintainers)

```powershell
.\scripts\prepare-release.ps1
git tag v1.0.0
git push origin v1.0.0
# Publier installer\output\optiCombat_Setup_v1.0.0.exe sur GitHub Releases
```

Checklist détaillée : [docs/GUIDE_COMPLET.md §8](docs/GUIDE_COMPLET.md#8-publication-installateur-et-checklist-release-v10).

## Sécurité

Vulnérabilités : voir [SECURITY.md](SECURITY.md) — pas d’issue publique pour les failles exploitables.
