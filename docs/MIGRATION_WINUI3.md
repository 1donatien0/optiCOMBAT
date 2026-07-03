# Migration WPF vers WinUI 3

Ce dépôt contient un projet `optiCombat.WinUI` qui remplace progressivement l'application WPF.

## État actuel (branche `dev`)

| Zone | Statut |
|------|--------|
| **`optiCombat.Application`** | Couche métier partagée (models, services, coordinators, ViewModels Historique, i18n) |
| **`optiCombat.WinUI`** | Shell principal WinUI 3 — **binaire `optiCombat.exe`** |
| **`OverviewPage`** | Données réelles via `WinUiServiceHost` |
| **`AntivirusPage`** | Scans, signatures, quarantaine, menu contextuel `--scan` |
| **`HistoryPage`** | Timeline, filtres, actions menaces, détail quarantaine/nettoyage, exports |
| **`CleanPage`** | `SystemCleanService` + journal |
| **`OptionsPage`** | Langue, protection avancée, exclusions, MAJ app, planification |
| **Shell** | Systray, IPC single-instance, toasts, Ctrl+1–5, `ApplyPreferencesOnStartup` |
| **`optiCombat` (WPF)** | UI legacy (coexistence) |
| **Installateur** | Cible WinUI publish (`optiCombat.WinUI\bin\...\publish\win-x64\`) |

### Architecture

```
optiCombat.WinUI ──┐
optiCombat (WPF) ──┼──► optiCombat.Application ──► optiCombat.Platform
optiCombat.Service ┘
```

### Publier / installer

```powershell
dotnet publish optiCombat.WinUI\optiCombat.WinUI.csproj -c Release -r win-x64 --self-contained true
# ou
pwsh -File scripts\publish-release.ps1
```

### Lancer en dev

```powershell
dotnet run --project optiCombat.WinUI\optiCombat.WinUI.csproj
```

Les binaires ClamAV/YARA/règles sont copiés depuis `optiCombat\` vers la sortie WinUI.

## Reste optionnel

- Thème alternatif « suivre Windows » (équivalent `ThemeManager` WPF)
- Protection plateforme / service noyau (UI dormante WPF)
- Signature Authenticode installateur (décommenter dans `setup.iss`)
- Option **Contraste renforcé** (retirée des Paramètres — à réévaluer)
