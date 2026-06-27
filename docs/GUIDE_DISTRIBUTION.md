# Guide de distribution — optiCOMBAT

Ce guide couvre la mise en production d'optiCOMBAT chez des utilisateurs tiers : **signature de code**, **cohabitation avec d'autres antivirus** et **chaîne de publication**. Il complète le [README](../README.md) (§8 publication) et [SIGNATURE_PROCEDURE.md](SIGNATURE_PROCEDURE.md).

---

## 0. Stratégie de distribution par phases (petit éditeur → croissance)

Le pilote noyau est la partie la plus coûteuse à signer (certificat **EV** + compte **Partner Center**). Il n'est **pas nécessaire** pour distribuer optiCOMBAT : l'app fonctionne sans lui.

### Phase 1 — maintenant (sans pilote, sans budget signature)
- **Protection temps réel user-mode** via `FileSystemWatcher` — aucun pilote, aucune signature Microsoft requise. Mode par défaut (`UsePlatformProtectionService = false`, `PlatformProtectionFeatureGate.IsUserActivatable = false`).
- Le scan à la demande / planifié (ClamAV + YARA), la quarantaine et l'historique fonctionnent pleinement.
- **Publication self-contained** par défaut (`scripts\prepare-release.ps1 -SelfContained`) : pas de coût, pas de .NET à installer chez l'utilisateur.
- **Signature** : optionnelle (OV ~200–350 $/an). Pour un projet solo sans budget, diffusion non signée acceptable — prévoir FAQ SmartScreen et hash SHA-256 des binaires sur la release.
- Case « Protection système avancée » de l'installeur **visible mais grisée** ; option Options **grisée** avec mention « prévu dans 3 à 5 ans ».

### Phase 2 — plus tard (~3 ans, avec pilote)
- Obtenir un certificat **EV** + compte **Partner Center**, faire **signer le minifiltre** (voir `SIGNATURE_PROCEDURE.md`).
- Embarquer le `.sys` + `.cat` signés, activer le mode plateforme (service + AMSI noyau).
- Basculer alors `UsePlatformProtectionService` à `true` par défaut et cocher la tâche avancée de l'installeur.

> Conséquence concrète : pour les 3 prochaines années, suis uniquement les parties « user-mode » de ce guide ; ignore la §4 (pilote) et la procédure EV jusqu'à la phase 2.

---

## 1. Signature de code (obligatoire pour une diffusion sérieuse)

### 1.1 Exécutable & installeur — Authenticode

Sans signature, SmartScreen affiche « éditeur inconnu » et beaucoup de produits de sécurité bloquent l'installeur.

- **Certificat** : un certificat **Code Signing OV** suffit techniquement ; un **EV** (sur token matériel) supprime l'écran SmartScreen plus vite (réputation immédiate). Fournisseurs : DigiCert, Sectigo, GlobalSign.
- **Signer l'exe publié** (intégré au script `scripts/prepare-release.ps1` via `-Sign` ou `OPTICOMBAT_SIGN_THUMBPRINT`) :

  ```powershell
  signtool sign /n "Dona By" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 optiCombat.exe
  ```

- **Signer l'installeur Inno** : configurer un *Sign Tool* nommé `signtool` (Tools > Configure Sign Tools…) puis décommenter dans `installer/setup.iss` :

  ```
  SignTool=signtool $f
  SignedUninstaller=yes
  ```

### 1.2 Pilote minifiltre — signature noyau (non contournable)

Sur **Windows 10/11 x64**, un pilote non signé **ne se charge pas** (Driver Signature Enforcement). Ce n'est pas optionnel.

- Le pilote doit être signé via le **portail Microsoft Hardware Dev Center** (compte développeur matériel + certificat EV) :
  - soit **Attestation signing** (plus simple, pas de tests HLK) — suffisant pour un minifiltre,
  - soit **WHQL** (tests HLK complets) si certification complète souhaitée.
- Sans cela, `optiCombat.Minifilter.sys` est rejeté au chargement → pas de protection temps réel au niveau noyau. L'installeur avertit désormais l'utilisateur si le `.sys` est absent/non signé.

### 1.3 Fournisseur AMSI

`optiCombat.AmsiProvider.dll` (chargé en-process par les applications analysées) doit aussi être **signé** pour être accepté par AMSI, et enregistré sous `HKLM\SOFTWARE\Microsoft\AMSI\Providers` (déjà géré par le code, nécessite l'élévation).

---

## 2. Cohabitation avec d'autres antivirus

optiCOMBAT (hooks de processus, RTP, minifiltre, quarantaine) a le profil comportemental d'un logiciel qu'un autre AV peut considérer comme suspect.

- **Risque concret** : un **Kaspersky / Bitdefender / Avast** (très répandus en Europe) peut **mettre en quarantaine ou terminer** `optiCombat.exe` — symptôme « se lance quelques secondes puis disparaît ».
- **Mesures** :
  1. **Signer** tous les binaires (réduit fortement les faux positifs).
  2. Documenter pour l'utilisateur comment **ajouter une exclusion** dans son AV existant (dossier d'installation + `optiCombat.exe`, `optiCombat.Service.exe`).
  3. Tester optiCOMBAT sur des postes équipés de Kaspersky/Bitdefender/Defender **avant** diffusion.
  4. Côté Defender, le projet gère déjà l'ajout d'exclusions (`add-defender-exclusions.ps1`).
- **Avertissement** : faire tourner **deux moteurs temps réel** simultanément peut dégrader les performances et provoquer des conflits de verrous. Le recommander uniquement en complément (scan à la demande), pas comme second RTP permanent.

---

## 3. Dépendance au runtime .NET

Publication en **framework-dependent** : l'utilisateur doit avoir le **.NET 8 Desktop Runtime x64**. L'installeur le **vérifie déjà** (`IsDotNet8Installed`) et redirige vers la page de téléchargement si absent.

Pour une expérience « zéro dépendance » sur poste vierge, deux options :

- publier en **self-contained** : `scripts\prepare-release.ps1 -SelfContained` (installeur plus lourd, ~150 Mo) ;
- ou **bundler** le runtime dans l'installeur (téléchargement via Inno Download Plugin déjà présent sur la machine de build).

---

## 4. Chaîne de publication fiable

L'UI de publication de Visual Studio s'est révélée peu fiable ici. Utiliser le script :

```powershell
# Publication complète (publish + installateur)
.\scripts\prepare-release.ps1

# Publication + signature + installateur
.\scripts\prepare-release.ps1 -Sign
```

Le script : désactive le watchdog, ferme les instances qui verrouillent les fichiers, nettoie `publish\`, publie, signe (si certificat), puis compile l'installeur Inno.

---

## 5. Checklist avant release (phase 1 — sans budget signature)

- [ ] Code committé et build CI vert (tests + CodeQL + gitleaks).
- [ ] Publication **self-contained** par défaut (`scripts\prepare-release.ps1 -SelfContained`) — zéro prérequis .NET chez l'utilisateur.
- [ ] Installeur Inno compilé ; SHA-256 du setup publié sur la release GitHub / SourceForge.
- [ ] Section **Installation** : SmartScreen « éditeur inconnu » → Exécuter quand même ; FAQ exclusions antivirus.
- [ ] `docs/CONFORMITE_RGPD.md` à jour (VirusTotal = hash uniquement, opt-in clé API).
- [ ] Testé sur poste vierge + poste avec Defender (idéalement un AV tiers).
- [ ] Numéro de version cohérent (`Directory.Build.props`, Inno, README).
- [ ] couche plateforme **dormante** (`PlatformProtectionFeatureGate.IsUserActivatable = false`) — case installeur grisée.

### Phase 2 uniquement (quand pilote signé disponible)

- [ ] Pilote minifiltre **signé** (attestation/WHQL) et présent.
- [ ] `optiCombat.AmsiProvider.dll` **signé** et présent.
- [ ] `optiCombat.exe` et installeur **signés** Authenticode (OV ou EV).
- [ ] `PlatformProtectionFeatureGate.IsUserActivatable` passé à `true`.
