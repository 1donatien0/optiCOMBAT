# Changelog

Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [Unreleased]

### Added

- **Optimiser** (ex-« Nettoyer ») : page à trois onglets **Nettoyage**, **Mises à jour** (applications via winget, accès à Windows Update) et **Tweaks** (14 réglages : performances, confidentialité, interface, maintenance — un seul script administrateur), portés d’optiSCAN WinUI 3
- Nettoyage : cache **Windows Update**, cache **DNS**, **historique de navigation** Chromium, bouton **Copier le journal**
- Antivirus : actions par menace (**Réputation** VirusTotal, **Ignorer**, **Quarantaine**, **Supprimer**), puces **Récents**, quarantaine paginée (200) avec **Charger plus** et **Vider toute la quarantaine**, bouton **Arrêter** et barre de progression pour la mise à jour des signatures
- Accueil : la tuile d’analyse ouvre un menu (rapide / complète / personnalisée)
- Options : **Lancer maintenant** (analyse planifiée), dossier des journaux et contrat de licence ; `LICENSE.txt` livré avec l’application
- Historique : **Traiter dans Analyse** charge les menaces de la session dans l’onglet Analyse ; **Voir en quarantaine** ouvre l’onglet Quarantaine ; boutons de ligne affichés selon l’état du fichier

### Fixed

- Thème clair : barre de navigation claire (plus de bandeau navy forcé) ; textes et icônes figés (`White`, bleu, violet) passent par des brosses de thème pour rester lisibles en mode sombre
- Les détections de la **protection temps réel** et de la **surveillance des processus** (toasts) laissent désormais une trace : une session « Protection temps réel » est enregistrée dans l’**Historique** (onglet Menaces, actions Quarantaine / Ignorer / Supprimer) ; l’écriture de l’historique est protégée contre les accès concurrents

### Changed

- **Identité de l’installateur** : `AppId` Inno propre à optiCOMBAT (`8E7178EF-…`, ancien identifiant partagé avec optiSCAN) ; `InnoUninstallGuid` aligné — optiCOMBAT et optiSCAN peuvent coexister sans se remplacer. Le menu contextuel « Scan with optiCombat » n’est plus supprimé par les installateurs optiSCAN
- « Nettoyer » devient **Optimiser** (menu, tuile d’accueil, titre de page, FR / EN)
- Onglets de l’Antivirus et de l’Optimiseur non fermables ; « Mettre à jour » depuis l’accueil ouvre l’onglet Signatures

- Migration **WinUI 3** : shell principal `optiCombat.WinUI` (binaire `optiCombat.exe`), couche partagée `optiCombat.Application`, installateur ciblant le publish WinUI
- Mise à jour sur place : relancer `optiCombat_Setup_*.exe` remplace la version installée dans le même dossier. Historique, quarantaine et préférences sont conservés
- Chemins de publication et scripts alignés sur `optiCombat.WinUI` (`net8.0-windows10.0.19041.0`)
- **Contraste renforcé** rétabli dans Options (thème `Combat.HighContrast`, activé aussi par le contraste élevé de Windows) ; nouvel interrupteur **Suivre le thème de Windows** ; accent Combat Aqua appliqué aux contrôles WinUI ; accent sombre éclairci (`#2DD4BF`) pour la lisibilité
- **Interface entièrement traduite FR / EN** : libellés XAML via propriétés attachées `loc:Loc`, réappliqués à chaud au changement de langue ; messages de statut et de Defender localisés
- Revenir sur une section rafraîchit ses données (accueil, antivirus, historique) ; une action antivirus ou une menace temps réel rafraîchit aussi quarantaine, historique et accueil
- **Mode complément de Defender** (Options → Protection, désactivé par défaut) et **guide de premier lancement**
- **Score de sécurité : corrections en un clic** (pare-feu, UAC, partages, RTP, MAJ auto, analyse) avec confirmation et une seule invite UAC
- **Analyser en administrateur** : relance élevée de l’application depuis l’accueil
- Sélecteurs de fichiers / dossiers Win32 natifs (les sélecteurs WinRT échouaient en administrateur)
- `generate-brand-assets.py` écrit dans `assets/` et `installer/` (plus dans l’ancien dossier `optiCombat/`) ; titre de fenêtre, pied de page et page provisoire de la migration retirés
- **Exclusions Windows Defender opt-in** : plus appliquées par l’installateur ni au démarrage ; nouveau bouton *Options → Exclusions Windows Defender* (relance UAC si nécessaire)
- `prepare-release.ps1` : outils de poste de dev non versionnés (`unblock-dev-build`, `sign-dev-local`, `sync-installer-icon`) appelés seulement s’ils existent ; `-SkipFreshclam` autorise l’absence de base CVD (MAJ signatures au premier lancement)

### Fixed

- « Mise à jour » depuis l’accueil retombait sur l’onglet Analyse (sélection d’onglet écrasée par le gabarit du `TabView`)
- Tests EICAR : chemins des règles et binaires YARA de test corrigés (`runtime/`)
- Suppression définitive (quarantaine, fichier détecté) **sans confirmation** : confirmation désormais obligatoire, « Non » par défaut
- Liens « Corriger » à plusieurs cibles (`ms-settings:…|control.exe …`) : ouverture de la première cible disponible
- Toast / statut de menace temps réel : clé de traduction `Rtp_ThreatToastTitle` manquante
- **freshclam** : la directive `CVDCertsDirectory` (rejetée par ClamAV 1.4+, « Can't open/parse freshclam.conf ») n’est plus écrite ; les conf existants qui la contiennent sont régénérés ; certificats via `CVD_CERTS_DIR` (app et CI)

### Security

- Plafond de débit sur le pipe IPC (`scan_path` / `scan_buffer` : 120/min, 4 simultanés) contre le DoS local
- Vérification d’intégrité des paquets de règles YARA-Forge (ZIP, taille, SHA-256 GitHub) avant installation
- Validation des chemins d’analyse externes (`--scan`, CLI, IPC) : chemins de périphérique et caractères de contrôle refusés
- ACL restreinte (propriétaire, SYSTEM, Administrateurs) sur la quarantaine et sur `%LocalAppData%\optiCombat` quand les exclusions Defender sont ajoutées

### Documentation

- Guides réalignés sur l’état réel d’optiCOMBAT (shell WinUI 3) : `GUIDE_COMPLET` réécrit (sections et raccourcis, pipeline, persistance, CI, dette connue), index `docs/README`, migration, distribution, signature, RGPD, moteur Rust, qualification, branding
- Documentation mise à jour pour les thèmes, la traduction, les coordinateurs, la sécurité locale et les nouveaux tests

### CI / dépôt

- Workflows CodeQL (C#, Rust, Actions), Gitleaks, Dependency Review ; Dependabot (NuGet, Cargo, Actions)
- Couverture de tests mesurée avec plancher bloquant 40 % (cible 50 %) ; `cargo audit` ; publish win-x64 + SBOM CycloneDX sur `main`
- `.gitattributes` : fins de ligne normalisées (fin des fichiers « modifiés » fantômes CRLF/LF)
- `.editorconfig` : CA1711 désactivé pour les collections xUnit des tests
- `scripts/check-winui-theme-keys.ps1` en CI : mêmes clés dans les trois thèmes, pas de `{StaticResource}` sur une brosse de thème
- Scripts PowerShell modifiés enregistrés en UTF-8 avec BOM (compatibilité Windows PowerShell 5.1)

## [1.0.0] — 2026-06-26

Première release publique sous la marque **optiCOMBAT**.

### Added

- Application WPF .NET 8 : scans ClamAV (clamscan / clamd) + YARA en parallèle
- Cœur moteur Rust (`opticombat.dll`) avec repli managé si absent
- Protection temps réel user-mode, quarantaine AES-GCM, historique chiffré
- Exclusions utilisateur (DPAPI) et exclusions implicites RTP : scripts IDE (`ps-script-*.ps1` dans `%TEMP%`), dépôt de dev, fichiers signatures AppData (`ScanImplicitExclusions`)
- Interface FR/EN (621 clés), thèmes Donaby **Combat Aqua** (clair / sombre / contraste) — accent teal / cyan, fonds blanc et navy
- Accueil : posture /100, statistiques 30 j., recommandations, **cadran de scan circulaire** (anneau vert → bleu, emblème pulsant) et bouton **Analyser**
- Barre latérale : navigation mono-fenêtre, élément actif en pilule teal
- Scan antivirus : rapide, complète, fichier, dossier, clés USB/SD ; réputation VirusTotal (clé API Options) ; mode jeu
- Assets branding : emblème, logo horizontal, hero accueil fond transparent (`generate-brand-assets.py`)
- Installateur Inno bilingue `optiCombat_Setup_v1.0.0.exe`
- Scripts release : `prepare-release.ps1`, exclusions Defender, qualification détection
- **300** tests unitaires Release ; CI GitHub (C# + Rust)
- `RollForward=Major` (.NET Desktop Runtime) pour compatibilité avec les runtimes 8.0.x installés

### Notes

- Couche plateforme (service Windows, AMSI, minifiltre) incluse mais **non activée** par défaut
- Canal de mise à jour OTA non configuré (`UpdateService` en attente)

[1.0.0]: https://github.com/1donatien0/optiCOMBAT/releases/tag/v1.0.0
