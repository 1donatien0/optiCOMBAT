# Signature EV et pilote — optiCOMBAT

## Prérequis distribution

| Composant | Certificat | Notes |
|-----------|------------|-------|
| `optiCombat.exe` | Authenticode EV | SmartScreen |
| `optiCombat.Service.exe` | Authenticode EV | Service Windows |
| `opticombat.dll` | Authenticode EV | Cœur Rust |
| `optiCombat.AmsiProvider.dll` | Authenticode EV | AMSI provider |
| `optiCombat.Minifilter.sys` | Attestation Microsoft | WHQL / Hardware Dev Center |

## Workflow Authenticode (exe + dll)

1. Obtenir un certificat **EV Code Signing** (DigiCert, Sectigo, etc.).
2. Stocker le thumbprint : `$env:OPTICOMBAT_SIGN_THUMBPRINT = "..."`.
3. Publier : `dotnet publish optiCombat/optiCombat.csproj -c Release -r win-x64`.
4. Signer : `.\scripts\sign-release.ps1`.

## Pilote minifilter

1. Soumettre le driver sur [Partner Center](https://partner.microsoft.com/dashboard/hardware).
2. Attestation signing pour tests internes.
3. WHQL pour distribution large.

Sans driver signé, le minifilter reste un stub — RTP user-mode + service-host restent fonctionnels.

## Inno Setup

Ajouter dans `setup.iss` après compilation :

```
SignTool=signtool sign /sha1 $p /tr http://timestamp.digicert.com /td sha256 /fd sha256 $f
SignedUninstaller=yes
```

## Vérification

```powershell
Get-AuthenticodeSignature .\optiCombat.exe
Get-AuthenticodeSignature .\opticombat.dll
signtool verify /pa /v optiCombat.exe
.\scripts\verify-signatures.ps1 -PublishDir .\optiCombat\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64 -Strict
```

## Développement local — SmartScreen bloque opticombat.dll

Windows Security affiche *« Part of this app has been blocked »* si `opticombat.dll` (ou l'exe) n'est **pas signé** Authenticode.

**Correctif dev (immédiat)** :

```powershell
# 1) Créer un certificat de signature dev (une fois)
.\scripts\sign-dev-local.ps1 -CreateCert

# 2) Rebuild + déployer + signer
dotnet build optiCombat.sln -c Release
.\scripts\build-engine.ps1 -SignDev

# 3) Si le blocage persiste (admin, une fois sur cette machine)
certutil -addstore TrustedPublisher <thumbprint affiché>
```

**Correctif production** : certificat **EV Code Signing** + `OPTICOMBAT_SIGN_THUMBPRINT` + `.\scripts\sign-release.ps1` (signe aussi `opticombat.dll`).

> Smart App Control (Windows 11) peut bloquer des binaires non réputés même en dev. Désactiver SAC dans *Sécurité Windows → Contrôle intelligent des applications* uniquement pour le poste de développement, ou utiliser la signature ci-dessus.

## Chaîne release complète

```powershell
# Sans certificat (publish + installateur)
.\scripts\prepare-release.ps1

# Avec certificat EV
$env:OPTICOMBAT_SIGN_THUMBPRINT = "..."
.\scripts\prepare-release.ps1 -Sign
```
