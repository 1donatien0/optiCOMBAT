# Migration WPF vers WinUI 3

Le shell livré est `optiCombat.WinUI` (binaire `optiCombat.exe`). Le projet WPF a été retiré du dépôt ; son code métier vit dans `optiCombat.Application`.

## État actuel (branche `dev`)

| Zone | Statut |
|------|--------|
| **`optiCombat.Application`** | Couche métier partagée : models, services, coordinateurs, ViewModel Historique, i18n (aucune dépendance WinUI) |
| **`optiCombat.WinUI`** | Shell principal WinUI 3 (Windows App SDK 1.8) — `NavigationView`, 5 sections |
| **`OverviewPage`** | Données réelles via `WinUiServiceHost` : état de protection, score /100, statistiques, recommandations |
| **`AntivirusPage`** | Onglets Analyse / Quarantaine / Signatures ; menu contextuel `--scan` |
| **`HistoryPage`** | Timeline, 5 filtres, recherche, actions sur les menaces, exports HTML / PDF |
| **`CleanPage`** | `SystemCleanService` (temporaires, 7 navigateurs, corbeille, journaux Windows) + journal |
| **`OptionsPage`** | Langue, thème (sombre, suivi de Windows, contraste renforcé), protection (dont mode complément de Defender), USB, clamd, planification, exclusions, seuils, VirusTotal, exclusions Defender (opt-in), MAJ app |
| **Shell** | Systray (fermer = masquer), instance unique + messages fenêtre, toasts, `Ctrl+1`–`Ctrl+5`, préférences appliquées au démarrage (`WinUiStartupCoordinator`) |
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

## Fait depuis la migration

- **Traduction complète des pages** : propriétés attachées `Loc` (texte, contenu, en-tête, placeholder, infobulle + accessibilité), réappliquées à chaud au changement de langue.
- **Thèmes** : `Themes/Combat.Light|Dark|HighContrast.xaml`, `WinUiThemeManager` (suivi de Windows, contraste renforcé, accent de marque injecté dans les contrôles WinUI), contrôle des clés en CI.
- **Coordinateurs testables** dans `optiCombat.Application/Coordinators` (navigation, actions antivirus, menace temps réel, USB, premier lancement) et abstractions `IUserConfirmService` / `IUiThreadScheduler`.
- **Boîtes natives** : sélecteurs de fichiers Win32 (`WinUiNativeDialogs`) et confirmations (`WinUiUserConfirmService`) fonctionnant aussi en administrateur.
- **Analyser en administrateur** branché ; corrections du score de sécurité en un clic ; mode complément de Defender ; guide de premier lancement.
- Traces de migration retirées (titre, pied de page, page provisoire) ; `generate-brand-assets.py` écrit dans `assets/` et `installer/`.

## Reste à faire

- Déplacer la logique restante des pages / ViewModels WinUI (scan, nettoyage, options) dans des coordinateurs testables.
- Préréglages de couleur d’accent (non repris).
- Protection plateforme / service noyau (inactive) ; signature Authenticode de l’installateur (`installer/setup.iss.signing.example`).
