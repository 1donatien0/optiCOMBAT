<#
.SYNOPSIS
    Prépare l'environnement dev avant tests : exclusions Defender, Unblock MOTW, signature locale des DLL.
.DESCRIPTION
    Les échecs 0x800711C7 (Application Control) viennent souvent de Smart App Control / Defender
    sur des binaires non signés — pas seulement du scan temps réel. Les exclusions de chemins
    (Add-MpPreference) ne suffisent pas toujours ; signer les DLL ou désactiver SAC en dev aide.
#>
[CmdletBinding()]
param(
    [switch] $SkipDefender,
    [switch] $SkipSign
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot

if (-not $SkipDefender) {
    Write-Host "`n=== Exclusions Defender (dev) ===" -ForegroundColor Cyan
    & (Join-Path $root 'scripts\add-defender-exclusions.ps1') -InstallDir $root -DevWorkspace
    if ($LASTEXITCODE -gt 1) {
        Write-Warning @'
Exclusions Defender incomplètes (admin ou protection contre falsification).
Relancer en administrateur :
  .\scripts\add-defender-exclusions.ps1 -DevWorkspace
'@
    }
}

Write-Host "`n=== Unblock bin/obj (MOTW) ===" -ForegroundColor Cyan
& (Join-Path $root 'scripts\unblock-dev-build.ps1')

if (-not $SkipSign) {
    Write-Host "`n=== Signature dev (DLL tests) ===" -ForegroundColor Cyan
    & (Join-Path $root 'scripts\sign-dev-local.ps1')
    if ($LASTEXITCODE -ne 0) {
        Write-Warning @'
Signature dev absente — Smart App Control peut bloquer optiCombat.Platform.dll (0x800711C7).
  .\scripts\sign-dev-local.ps1 -CreateCert
  .\scripts\sign-dev-local.ps1
Optionnel (admin, une fois) :
  certutil -addstore TrustedPublisher <thumbprint>
'@
    }
}

Write-Host "`nPret pour : dotnet test optiCombat.Tests\optiCombat.Tests.csproj -c Release --no-build" -ForegroundColor Green
Write-Host @"

Si les tests echouent encore avec 0x800711C7 (Application Control / Smart App Control) :
  1. Build puis relancer ce script (signe les DLL fraiches).
  2. Une fois en admin, faire confiance au certificat dev :
       certutil -addstore TrustedPublisher <thumbprint affiche par sign-dev-local -CreateCert>
  3. Ou desactiver Smart App Control : Securite Windows > Controle d'applications > desactiver (dev uniquement).
"@ -ForegroundColor Yellow
