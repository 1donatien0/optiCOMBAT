# Identité visuelle optiCOMBAT

Marque **optiCOMBAT** / **OPTICOMBAT** ; binaires et dossiers `optiCombat.*`.

| Fichier | Usage |
|---------|--------|
| `optiCombat_emblem_source.png` | Emblème Combat Aqua (hero, sidebar, .ico) |
| `optiCombat_logo_horizontal.png` | Logo horizontal (OPTICOMBAT + tagline) |

## Régénérer les assets UI

```powershell
python scripts/generate-brand-assets.py
```

| Sortie | Rôle |
|--------|------|
| `optiCombat/optiCombat.ico` | Exe, installateur, barre des tâches |
| `optiCombat/optiCombat_hero.png` | Accueil (cadran Combat Aqua, fond transparent) |
| `optiCombat/optiCombat_shield.png` | Sidebar |
| `optiCombat/optiCombat.png` | Logo horizontal |
| `assets/branding/*` | Variantes (dark, light, mono, favicon) |

Après modification des sources PNG, relancer le script puis recompiler.
