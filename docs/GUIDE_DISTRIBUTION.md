# Guide de distribution — optiCOMBAT

Publication d’optiCOMBAT chez des utilisateurs tiers : **signature**, **cohabitation antivirus** et **chaîne de build**.

---

## 1. Mode de protection livré (v1.0)

- **Temps réel user-mode** (`FileSystemWatcher` + surveillance des processus) — aucun pilote requis.
- Scans à la demande / planifiés (ClamAV + YARA, cœur Rust si `opticombat.dll` est livrée), quarantaine, historique.
- Couche plateforme (service, AMSI, minifiltre) **inactive** : l’installateur ne crée pas le service et les Options ne l’exposent pas.
- Publication **self-contained** dans tous les cas : `prepare-release.ps1` utilise le profil `FolderProfile-SelfContained` ; `-SelfContained` publie seulement vers `publish\win-x64` à la racine.

---

## 2. Signature de code

Sans signature Authenticode, SmartScreen affiche « éditeur inconnu ».

- **OV** suffit techniquement ; **EV** accélère la réputation SmartScreen.
- Signer l’exe publié : `scripts/prepare-release.ps1 -Sign` ou `OPTICOMBAT_SIGN_THUMBPRINT`.
- Signer l’installeur : *Sign Tool* dans Inno Setup — voir `installer/setup.iss.signing.example` et [SIGNATURE_PROCEDURE.md](SIGNATURE_PROCEDURE.md).

Le **pilote minifiltre** exige une signature Microsoft (Partner Center + certificat EV) ; il n’est pas requis pour la v1.0.

---

## 3. Cohabitation avec d'autres antivirus

Un second antivirus temps réel peut bloquer ou terminer `optiCombat.exe`.

- Signer les binaires en production.
- Documenter les exclusions (dossier d’installation + processus).
- Tester sur postes avec Defender et, si possible, un AV tiers.
- **Defender** : option **Laisser le temps réel à Windows Defender** (Options → Protection, proposée au premier lancement) : Defender surveille en continu, optiCOMBAT fait les analyses à la demande, planifiées et USB. Les exclusions Defender sont **opt-in** — *Options → Exclusions Windows Defender* ou `add-defender-exclusions.ps1` en administrateur — et ne sont jamais appliquées par l’installateur.
- Autres antivirus : `scripts/kaspersky-exclusions-guide.ps1`.

---

## 4. Runtime .NET

En **self-contained** (défaut), aucun runtime à installer. En **framework-dependent**, l’installateur vérifie .NET 8 Desktop x64 (`IsDotNet8Installed`).

---

## 5. Chaîne de publication

```powershell
.\scripts\prepare-release.ps1
.\scripts\prepare-release.ps1 -Sign   # avec certificat
```

Le script : arrêt des processus qui verrouillent les sorties, nettoyage, dépendances ClamAV / YARA (+ freshclam), assets, tests, publish, moteur Rust, vérification, signature optionnelle, compilation Inno. `-SkipFreshclam` produit un installateur sans base CVD (téléchargée au premier lancement).

---

## 6. Mise à jour d’une installation existante

Le setup Inno conserve le même `AppId` (`8E7178EF-E038-413D-BF79-FFB925BB2543`, propre à optiCOMBAT : ne jamais le réutiliser dans un autre produit, sinon Inno les traite comme une seule application). Lancer un `optiCombat_Setup_*.exe` plus récent :

- réutilise le dossier d’installation précédent ;
- ferme `optiCombat.exe` (y compris s’il est réduit dans la zone de notification) avant de copier les fichiers ;
- laisse `%LocalAppData%\optiCombat` intact (historique, quarantaine, préférences).

La désinstallation n’est utile que pour retirer le produit.

## 7. Checklist release

- [ ] `dotnet test` Release vert et CI verte (couverture ≥ 40 %, CodeQL, Gitleaks)
- [ ] `prepare-release.ps1` → `installer\output\optiCombat_Setup_v1.0.0.exe`
- [ ] SHA-256 du setup publié avec le binaire
- [ ] Test sur poste vierge : install, scan, RTP, quarantaine, FR/EN
- [ ] Test de mise à jour : relancer le setup par-dessus une installation existante, sans désinstaller, et vérifier que l’historique est toujours là
- [ ] Version cohérente (`Directory.Build.props`, Inno, README)
- [ ] `docs/CONFORMITE_RGPD.md` à jour (VirusTotal = hash, opt-in clé API)
