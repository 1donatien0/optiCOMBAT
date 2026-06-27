# Identité visuelle optiCOMBAT

Convention doc : marque **optiCOMBAT** / **OPTICOMBAT** ; chemins et binaires `optiCombat.*` inchangés.

| Fichier | Usage |
|---------|--------|
| `optiCombat_emblem_source.png` | Bouclier seul (source hero, sidebar, .ico) |
| `optiCombat_logo_horizontal.png` | Logo horizontal (shield + OPTICOMBAT + tagline) |
| `mockup-okay-reference.png` | Référence maquette (non utilisée au runtime) |

## Régénérer les assets UI

```powershell
python scripts/generate-brand-assets.py
```

Produit :

| Sortie | Rôle |
|--------|------|
| `optiCombat/optiCombat.ico` | Exe, installateur Inno, barre des tâches |
| `optiCombat/ico.ico` | Copie legacy |
| `optiCombat/optiCombat_hero.png` | Accueil (bouclier, fond gris) |
| `optiCombat/optiCombat_shield.png` | Sidebar (favicon app) |
| `optiCombat/optiCombat.png` | Logo horizontal (accueil) |
| `assets/branding/*` | Variantes archivées (dark, light, mono, favicon) |

Après remplacement des sources, relancer le script puis recompiler / republier.
