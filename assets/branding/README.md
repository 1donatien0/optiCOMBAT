# Identité visuelle optiCOMBAT

Marque **optiCOMBAT** / **OPTICOMBAT** ; binaires et projets `optiCombat.*`. Palette **Combat Aqua** (accent teal `#0F9F8F`).

## Fichiers consommés par l’application

Le projet WinUI (`optiCombat.WinUI.csproj`) utilise directement :

| Fichier | Usage |
|---------|-------|
| `assets/optiCombat.ico` | Icône de l’exe (`ApplicationIcon`) et de la fenêtre |
| `assets/optiCombat_hero.png` | Visuel de l’accueil |
| `assets/optiCombat_shield.png` | Emblème de la barre latérale |
| `installer/optiCombat.ico` | Icône de l’installateur Inno |

## Sources et variantes (`assets/branding/`)

| Fichier | Usage |
|---------|-------|
| `optiCombat_emblem_source.png` | Emblème source |
| `optiCombat_logo_horizontal.png` | Logo horizontal source (OPTICOMBAT + tagline) |
| `optiCombat_logo_*`, `optiCombat_emblem_*` | Variantes (clair, sombre, monochrome, favicon, planches) |

## Régénérer

```powershell
python scripts/generate-brand-assets.py
```

Le script écrit directement les fichiers consommés (`assets/optiCombat.ico`, `assets/optiCombat_hero.png`, `assets/optiCombat_shield.png`, `installer/optiCombat.ico`) et les variantes dans `assets/branding/` (dont `optiCombat_logo_banner.png`). `prepare-release.ps1` l’exécute à chaque release. Recompiler ensuite.
