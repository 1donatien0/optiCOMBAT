# Contribuer à optiCOMBAT

Dépôt officiel maintenu par **[1donatien0](https://github.com/1donatien0)**.

## Prérequis

- Windows 10/11 x64
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [Inno Setup 6](https://jrsoftware.org/isinfo.php) (installateur)
- [Rust stable](https://rustup.rs) (moteur `opticombat.dll`)
- Python 3 + Pillow (`scripts/generate-brand-assets.py`)

## Clone et build

```powershell
git clone https://github.com/1donatien0/optiCOMBAT.git
cd optiCOMBAT
.\scripts\fetch-runtime-deps.ps1
dotnet build optiCombat.sln -c Release
.\scripts\build-engine.ps1
dotnet test optiCombat.Tests\optiCombat.Tests.csproj -c Release
```

Ne commitez **jamais** : `.pfx`, `.env`, secrets, bases ClamAV `.cvd`, binaires ClamAV / YARA de `runtime/`, `installer/output/`, `bin/`, `obj/`, échantillons malveillants.

Les scripts de poste de dev (`unblock-dev-build.ps1`, `sign-dev-local.ps1`, `sync-installer-icon.ps1`, `ensure-dev-trust.ps1`) sont ignorés par Git et optionnels.

## Branche et commits

- Branche de développement **`dev`** (WinUI 3) ; **`main`** pour les releases stables
- Branches feature : `feature/...`
- Messages de commit clairs (français ou anglais)
- Commits du dépôt officiel : auteur **1donatien0**

## Lancer l’UI (dev)

```powershell
dotnet run --project optiCombat.WinUI\optiCombat.WinUI.csproj
```

## Pull requests

1. `dotnet test` Release vert ; la CI exige une couverture lignes **≥ 40 %** (cible 50 %)
2. `cargo test --workspace --manifest-path engine/Cargo.toml` (+ `cargo clippy`, `cargo fmt --check`) si le moteur Rust est touché ; `.\scripts\qualify-detection.ps1` si la détection change
3. CodeQL, Gitleaks et Dependency Review verts (aucun secret, aucune dépendance vulnérable *high*)
4. Parité des clés FR/EN ; aucun texte en dur dans les vues XAML (`loc:Loc.Text` / `Content` / `Header` / `Placeholder` / `Tip`)
5. Brosses de thème en `{ThemeResource}`, mêmes clés dans les trois thèmes : `pwsh -File scripts/check-winui-theme-keys.ps1`
6. Commits courts et typés (`fix(installer): …`, `feat(ipc): …`) — une correction = un commit
7. Notes utilisateur dans `CHANGELOG.md` (section `[Unreleased]`)

## Release

```powershell
.\scripts\prepare-release.ps1
# Tag aligné sur Directory.Build.props, publier installer\output\optiCombat_Setup_v1.0.0.exe
```

Checklist : [docs/GUIDE_COMPLET.md §8](docs/GUIDE_COMPLET.md#8-publication-installateur-et-checklist-release).

## Sécurité

Vulnérabilités : [SECURITY.md](SECURITY.md) — pas d’issue publique pour les failles exploitables.
