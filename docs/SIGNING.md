# Signature — optiCOMBAT

## Composants à signer (production)

| Composant | Certificat |
|-----------|------------|
| `optiCombat.exe` | Authenticode |
| `optiCombat.Service.exe` | Authenticode |
| `opticombat.dll` | Authenticode |
| `optiCombat.AmsiProvider.dll` | Authenticode |
| `optiCombat.Minifilter.sys` | Attestation Microsoft (couche plateforme inactive en v1.0) |

## Workflow

1. Certificat **Code Signing** (OV ou EV) — thumbprint dans `$env:OPTICOMBAT_SIGN_THUMBPRINT`.
2. Publish : `dotnet publish optiCombat.WinUI/optiCombat.WinUI.csproj -c Release -r win-x64 --self-contained true`.
3. Signer : `.\scripts\sign-release.ps1` ou `.\scripts\prepare-release.ps1 -Sign`.

Détails pilote et Partner Center : [SIGNATURE_PROCEDURE.md](SIGNATURE_PROCEDURE.md).

## Vérification

```powershell
.\scripts\verify-signatures.ps1 -PublishDir .\optiCombat.WinUI\bin\Release\net8.0-windows10.0.19041.0\publish\win-x64 -Strict
```

## Développement local

Binaires non signés : exclusions Defender pour le dossier de build, ou certificat local via `signtool` (ne jamais committer de `.pfx`).
