# Guide de distribution — optiCOMBAT

Publication d’optiCOMBAT chez des utilisateurs tiers : **signature**, **cohabitation antivirus** et **chaîne de build**.

---

## 1. Mode de protection livré (v1.0)

- **Temps réel user-mode** (`FileSystemWatcher`) — aucun pilote requis.
- Scans à la demande / planifiés (ClamAV + YARA), quarantaine, historique.
- Couche plateforme (service, AMSI, minifiltre) **inactive** dans l’installateur et les Options.
- Publication **self-contained** par défaut : `.\scripts\prepare-release.ps1 -SelfContained`.

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
- `add-defender-exclusions.ps1` gère Defender uniquement.

---

## 4. Runtime .NET

En **self-contained** (défaut), aucun runtime à installer. En **framework-dependent**, l’installateur vérifie .NET 8 Desktop x64 (`IsDotNet8Installed`).

---

## 5. Chaîne de publication

```powershell
.\scripts\prepare-release.ps1
.\scripts\prepare-release.ps1 -Sign   # avec certificat
```

Le script : arrêt des instances, nettoyage `publish\`, publish, signature optionnelle, compilation Inno.

---

## 6. Checklist release

- [ ] `dotnet test` Release — **300** tests OK
- [ ] `prepare-release.ps1` → `installer\output\optiCombat_Setup_v1.0.0.exe`
- [ ] SHA-256 du setup publié avec le binaire
- [ ] Test sur poste vierge : install, scan, RTP, quarantaine, FR/EN
- [ ] Version cohérente (`Directory.Build.props`, Inno, README)
- [ ] `docs/CONFORMITE_RGPD.md` à jour (VirusTotal = hash, opt-in clé API)
