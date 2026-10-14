# Documentation optiCOMBAT

**Marque** : **optiCOMBAT**. **Technique** : `optiCombat.exe`, projets `optiCombat.*`, données `%LocalAppData%\optiCombat`.

| Document | Contenu |
|----------|---------|
| [README.md](../README.md) | Présentation et démarrage rapide |
| [GUIDE_COMPLET.md](GUIDE_COMPLET.md) | Architecture, interface, moteurs, publication, qualité, sécurité |
| [MIGRATION_WINUI3.md](MIGRATION_WINUI3.md) | Migration WPF → WinUI 3 : état et reste à faire |
| [GUIDE_DISTRIBUTION.md](GUIDE_DISTRIBUTION.md) | Diffusion : signature, cohabitation antivirus, mise à jour |
| [SIGNING.md](SIGNING.md) · [SIGNATURE_PROCEDURE.md](SIGNATURE_PROCEDURE.md) | Signature Authenticode et pilote |
| [CONFORMITE_RGPD.md](CONFORMITE_RGPD.md) | Données traitées, transferts, RGPD |
| [engine/README.md](../engine/README.md) | Cœur moteur Rust |
| [qualification/README.md](../qualification/README.md) | Panel de détection / faux positifs |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Build, tests, contributions |
| [CHANGELOG.md](../CHANGELOG.md) | Notes de version |
| [SECURITY.md](../SECURITY.md) | Vulnérabilités, architecture de sécurité |

## Index par sujet (guide complet)

| Sujet | Section |
|-------|---------|
| Projets, couches, arborescence | [§1](GUIDE_COMPLET.md#1-architecture-technique) |
| Thèmes, contraste renforcé | [§2](GUIDE_COMPLET.md#2-donaby-design--thèmes-winui-3) |
| ClamAV, freshclam, YARA-Forge, moteur Rust | [§3](GUIDE_COMPLET.md#3-clamav-yara-et-moteur-rust) |
| Sections de l’interface et raccourcis | [§4.1](GUIDE_COMPLET.md#41-sections-de-mainwindow) |
| Optimiser : nettoyage, mises à jour, tweaks | [§4.12](GUIDE_COMPLET.md#412-optimiser-cleanpage) |
| Exclusions / Defender (opt-in) | [§4.7](GUIDE_COMPLET.md#47-exclusions) |
| Quarantaine | [§4.8](GUIDE_COMPLET.md#48-quarantaine-quarantinemanager) |
| Historique / journaux | [§4.9](GUIDE_COMPLET.md#49-journaux-et-historique) |
| RTP, USB/SD, planification, toasts | [§5](GUIDE_COMPLET.md#5-services-complémentaires) |
| Ligne de commande | [§6](GUIDE_COMPLET.md#6-démarrage-fermeture-et-ligne-de-commande) |
| Build, publish, installateur, checklist | [§8](GUIDE_COMPLET.md#8-publication-installateur-et-checklist-release) |
| FR / EN (886 clés, libellés XAML via `loc:Loc`) | [§9](GUIDE_COMPLET.md#9-langues-de-linterface-fr-fr--en-us) |
| Tests et CI | [§12](GUIDE_COMPLET.md#12-qualité-tests-et-ci) |
| Posture /100, modèle de menace | [§13](GUIDE_COMPLET.md#13-sécurité-posture-et-menaces) |

**Version** : **v1.0**, assembly **1.0.0**.
