# Procédure de signature de code — optiCOMBAT

Guide pratique pour signer optiCOMBAT. Un antivirus complet a **quatre** artefacts à signer, dont un (le pilote noyau) qui passe obligatoirement par Microsoft.

> **Quand utiliser ce document ?**
> - **Phase 1 (maintenant, sans pilote)** : seule la **§3** te concerne, et de façon **optionnelle** — un certificat **OV** pour `optiCombat.exe` + l'installeur. Pas besoin d'EV, ni de Partner Center, ni de signer le pilote (la couche plateforme est dormante). Tu peux même diffuser non signé en bêta.
> - **Phase 2 (~3 ans, activation de la couche plateforme)** : tout le reste (EV en **§2.1**, pilote en **§4**) devient nécessaire.
>
> Vérifié en juin 2026. Les prix et portails évoluent — recouper avec les liens en bas.

---

## 1. Ce qu'il faut signer

| Artefact | Type | Chaîne de signature |
|---|---|---|
| `optiCombat.exe` | Exécutable WinUI 3 (shell principal) | Authenticode (ton certificat) |
| Installeur `optiCombat_Setup_*.exe` | Inno Setup | Authenticode (ton certificat) |
| `optiCombat.AmsiProvider.dll` | DLL user-mode (AMSI) | Authenticode (ton certificat) |
| `optiCombat.Minifilter.sys` | **Pilote noyau** | **Microsoft** (via Partner Center) après signature EV |

Les trois premiers se signent toi-même avec `signtool`. Le pilote **doit** être soumis à Microsoft.

---

## 2. Prérequis (à obtenir une fois)

### 2.1 Certificat de signature de code **EV**

- **Pourquoi EV (et pas OV) ?** Parce que Microsoft **exige un certificat EV** pour soumettre un pilote à la signature d'attestation. Comme tu dois signer le pilote, prends directement de l'EV : il couvre aussi l'exe et l'installeur.
- **Stockage matériel obligatoire** : depuis juin 2023 (CA/B Forum), la clé privée d'un certificat de signature doit vivre sur un **token matériel** (FIPS 140-2 niveau 2 / Common Criteria EAL4+) ou un **HSM cloud**. Tu ne peux pas l'exporter en `.pfx`.
- **Fournisseurs / prix indicatifs (revendeurs, /an)** : Sectigo/Comodo ~280–330 $, DigiCert ~500–560 $. Le token USB + envoi est inclus (~130 $).
- **Validité** : depuis le 24 février 2026, durée max **459 jours** pour les certificats publics de signature.
- ⚠️ **À savoir (changement 2024)** : depuis mars 2024, l'EV **ne donne plus** de contournement SmartScreen instantané. EV et OV construisent désormais leur réputation SmartScreen de la même façon (volume de téléchargements). L'EV reste néanmoins **indispensable pour le pilote**.

### 2.2 Compte Microsoft **Partner Center — Hardware**

- Crée un compte sur le **Partner Center for Windows Hardware** (anciennement Hardware Dev Center).
- **Associe ton certificat EV** au compte (l'enregistrement initial du compte se fait via une signature EV). Sans EV rattaché, tu ne peux pas soumettre de pilote.

---

## 3. Signer les binaires user-mode (exe, DLL, installeur)

Token EV branché, depuis un terminal développeur (où `signtool.exe` est dans le PATH — fourni par le Windows SDK).

```powershell
# Horodatage OBLIGATOIRE (sinon la signature expire avec le certificat)
$ts = "http://timestamp.digicert.com"   # ou celui de ton émetteur

# Exe + DLL AMSI (after publish)
signtool sign /fd SHA256 /tr $ts /td SHA256 /a `
  "optiCombat\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\optiCombat.exe"

signtool sign /fd SHA256 /tr $ts /td SHA256 /a `
  "native\optiCombat.AmsiProvider\x64\Release\optiCombat.AmsiProvider.dll"
```

- `/a` sélectionne automatiquement le bon certificat ; sinon `/n "Nom du sujet"` ou `/sha1 <empreinte>`.
- Avec certains tokens/HSM cloud, il faut passer par le KSP du fournisseur (option `/csp`/`/kc` ou outil maison — suis la doc de ton émetteur).
- **L'installeur** se signe automatiquement si tu configures Inno (voir §5), ou manuellement après compilation :
  ```powershell
  signtool sign /fd SHA256 /tr $ts /td SHA256 /a "installer\output\optiCombat_Setup_v1.0.0.exe"
  ```

**Ordre important** : signe `optiCombat.exe` et la DLL **avant** de compiler l'installeur, pour que l'installeur embarque des binaires déjà signés. Puis signe l'installeur lui-même.

---

## 4. Signer le pilote noyau (procédure Microsoft)

Le `.sys` ne se charge pas sur Windows 10/11 x64 sans signature Microsoft. Voie recommandée : **Attestation Signing** (pas de tests HLK, plus rapide que WHQL).

1. **Compiler** le pilote en Release x64 (`optiCombat.Minifilter.sys`).
2. **Créer un `.cab`** contenant : le `.sys`, le `.inf`, et le fichier de symboles `.pdb`.
   - Via `MakeCab` + un fichier `.ddf`, ou l'outil de packaging du WDK.
3. **Signer le `.cab` avec ton certificat EV** :
   ```powershell
   signtool sign /fd SHA256 /tr $ts /td SHA256 /a optiCombat.Minifilter.cab
   ```
4. **Soumettre** sur le Partner Center hardware : nouveau « Driver submission » → **attestation signing** → téléverser le `.cab` signé (renseigner nom du produit / infos matériel demandées).
5. **Microsoft re-signe** : il ajoute une signature embarquée SHA-2 Microsoft et génère un **catalogue (`.cat`) signé** par un certificat Microsoft SHA-2.
6. **Télécharger** le paquet signé → tu distribues le **`.sys` re-signé + le `.cat`**.
   - L'installeur doit installer le `.cat` à côté du `.sys` (ou installer le pilote via son `.inf` qui référence le catalogue).

> Limites de l'attestation : Windows 10 Desktop et ultérieur. Pour une certification complète / autres éditions, passer par WHQL (tests HLK).

---

## 5. Automatiser dans la build

### Inno Setup (installeur)
Dans `installer/setup.iss`, le scaffolding est déjà prêt. Configure un *Sign Tool* nommé `signtool` (IDE Inno → Tools → Configure Sign Tools…) :
```
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a $f
```
puis décommente dans `[Setup]` :
```
SignTool=signtool $f
SignedUninstaller=yes
```

### Script de publication
`scripts/prepare-release.ps1` signe l'exe et compile l'installateur si tu passes `-Sign` ou définis `OPTICOMBAT_SIGN_THUMBPRINT` :
```powershell
.\scripts\prepare-release.ps1 -Sign
```

---

## 6. Vérifier les signatures

```powershell
# User-mode
signtool verify /v /pa "optiCombat.exe"
signtool verify /v /pa "installer\output\optiCombat_Setup_v1.0.0.exe"

# Pilote (catalogue)
signtool verify /v /kp /c optiCombat.Minifilter.cat optiCombat.Minifilter.sys
```
Un horodatage valide doit apparaître ; sans lui, tout casse à l'expiration du certificat.

---

## 7. Ordre récapitulatif d'une release signée

1. `dotnet publish` (ou `scripts\prepare-release.ps1`).
2. Signer `optiCombat.exe` + `optiCombat.AmsiProvider.dll` (EV).
3. Faire signer le pilote par Microsoft (Partner Center) → récupérer `.sys` + `.cat`.
4. Placer pilote+catalogue signés à l'emplacement attendu par l'installeur.
5. Compiler l'installeur Inno (signature auto si configurée).
6. Signer l'installeur si non auto.
7. `signtool verify` sur tout.
8. Tester l'install sur poste vierge **et** sur poste avec Kaspersky/Defender.

---

## Sources
- [Attestation Sign Windows Drivers — Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation)
- [Driver Code Signing Requirements — Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs)
- [Partner Center for Windows Hardware — Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/)
- [Code signing options for Windows app developers — Microsoft Learn](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
- [EV Code Signing Certificates — SSL.com](https://www.ssl.com/products/software-integrity/code-signing/ev/)
- [EV Code Signing : nouvelles exigences matérielles — e-verse](https://e-verse.com/learn/ev-code-signing-certificates-hardware-requirements/)
