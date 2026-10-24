# Shell WinUI 3

Le shell livré est `optiCombat.WinUI` (binaire `optiCombat.exe`). La couche métier (models, services, ViewModels, i18n) vit dans `optiCombat.Application`.

## État actuel (branche `dev`)

| Zone | Statut |
|------|--------|
| **`optiCombat.Application`** | Couche métier partagée : models, services, coordinateurs, ViewModels, i18n (aucune dépendance WinUI) |
| **`optiCombat.WinUI`** | Shell principal WinUI 3 (Windows App SDK 1.8) — `NavigationView`, 5 sections |
| **`OverviewPage`** | Données réelles via `WinUiServiceHost` : état de protection, score /100, statistiques, recommandations |
| **`AntivirusPage`** | `SelectorBar` Analyse / Signatures / Quarantaine ; menu contextuel `--scan` |
| **`HistoryPage`** | Timeline, 5 filtres, recherche, actions sur les menaces, exports HTML / PDF |
| **`CleanPage`** | `SelectorBar` Nettoyage / Mises à jour / Tweaks ; `SystemCleanService` (temporaires, 7 navigateurs, corbeille, journaux Windows) + journal |
| **`OptionsPage`** | Langue, thème (sombre, suivi de Windows, contraste renforcé, presets Combat / Minuit / Océan / Braise, accent `#RRGGBB`), protection (dont mode complément de Defender), USB, clamd, cœur Rust, planification, exclusions, seuils, clé VirusTotal, Auth-Key abuse.ch (threat intel hors-ligne), exclusions Defender (opt-in), vérification de version GitHub (lien vers la release, pas d’installation) |
| **Shell** | Systray (fermer = masquer), instance unique + messages fenêtre, toasts, Mica, `Ctrl+1`–`Ctrl+5` via `PreviewKeyDown`, min 720×480, préférences appliquées au démarrage (`WinUiStartupCoordinator`) |
| **Installateur** | Cible le publish WinUI self-contained (`optiCombat.WinUI\bin\Release\net8.0-windows10.0.19041.0\publish\win-x64\`). Une nouvelle version remplace l’installation existante (même AppId), sans désinstallation. |

### Architecture

```
optiCombat.WinUI ──┐
optiCombat.Service ┼──► optiCombat.Application ──► optiCombat.Platform
```

### Publier / installer

```powershell
.\scripts\prepare-release.ps1
# ou
dotnet publish optiCombat.WinUI\optiCombat.WinUI.csproj -c Release /p:PublishProfile=FolderProfile-SelfContained
```

### Lancer en dev

```powershell
dotnet run --project optiCombat.WinUI\optiCombat.WinUI.csproj
```

Les binaires ClamAV / YARA et les règles sont copiés depuis `runtime\` vers la sortie WinUI (`.\scripts\fetch-runtime-deps.ps1` au préalable).

## Shell livré

- **Traduction complète des pages** : propriétés attachées `Loc` (texte, contenu, en-tête, placeholder, infobulle + accessibilité), réappliquées à chaud au changement de langue.
- **Thèmes** : `Themes/Combat.Light|Dark|HighContrast.xaml`, `WinUiStyles.xaml`, `WinUiThemeManager` + `WinUiThemePacks` (suivi de Windows, contraste renforcé, presets d’accent, accent de marque injecté dans les contrôles WinUI), contrôle des clés en CI.
- **Coordinateurs testables** dans `optiCombat.Application/Coordinators` (navigation, actions antivirus, menace temps réel, USB, premier lancement) et abstractions `IUserConfirmService` / `IUiThreadScheduler`.
- **ViewModels** Antivirus, Options, Nettoyage, Mises à jour, Tweaks et Historique dans `optiCombat.Application` (thème via `IShellThemeController`).
- **Boîtes natives** : sélecteurs de fichiers Win32 (`WinUiNativeDialogs`) et confirmations (`WinUiUserConfirmService`) fonctionnant aussi en administrateur.
- **Analyser en administrateur** branché ; corrections du score de sécurité en un clic ; mode complément de Defender ; guide de premier lancement.
- `generate-brand-assets.py` écrit dans `assets/` et `installer/`.

## Suite prévue

- Alléger encore le code-behind des pages XAML (scan, nettoyage, options) vers des coordinateurs testables.
- Protection plateforme / service noyau (inactive, hors v1) ; signature Authenticode de l’installateur (`installer/setup.iss.signing.example`).
