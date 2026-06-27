# Panel de qualification optiCOMBAT

Mesure la détection réelle et le taux de faux positifs au-delà d'EICAR.

## Structure

```
qualification/
  manifest.json          # Liste des échantillons + verdict attendu
  generated/             # Créé par le script (EICAR, etc.)
  benign/                # Fichiers légitimes (ajouter vos échantillons)
  malicious/             # Échantillons malveillants (VM isolée uniquement)
```

## Seuils cibles

| Métrique | Cible CI | Cible produit (panel étendu) |
|----------|----------|------------------------------|
| EICAR | 100 % détection | 100 % |
| Panel malveillant synthétique | 100 % (2 échantillons) | ≥ 85 % |
| Faux positifs bénins | 0 % (4 échantillons) | < 1 % |

## Exécution

```powershell
# Depuis la racine du dépôt (Rust requis)
.\scripts\qualify-detection.ps1

# Seuils personnalisés (panel étendu avec échantillons réels)
.\scripts\qualify-detection.ps1 -MinMaliciousRate 0.85 -MaxFprRate 0.01

# Rapport JSON dans qualification/reports/
```

## Ajouter des échantillons

1. Placer les fichiers dans `benign/` ou `malicious/` (ne jamais committer de malware réel).
2. Mettre à jour `manifest.json` avec le chemin et `expect`: `clean` ou `malicious`.
3. Pour extraire les features ML d'un PE réel : `cargo run -p ml-train -- --extract sample.exe Benign`.

## Sécurité

- Ne jamais committer d'échantillons malveillants actifs dans Git public.
- Utiliser une VM isolée pour la collecte.
- Hashes SHA-256 suffisent pour la réputation cloud.
