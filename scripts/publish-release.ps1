<#
.SYNOPSIS
    Publication Release fiable d'optiCombat + compilation de l'installeur Inno.

.DESCRIPTION
    Contourne l'UI de publication de Visual Studio (peu fiable) en utilisant
    directement `dotnet publish`. Gère les causes classiques d'échec :
      - arrête la tâche planifiée optiCombat_Watchdog (qui relance l'exe),
      - termine tout optiCombat.exe / optiCombat.Service.exe en cours (verrous de fichiers),
      - nettoie le dossier publish périmé,
      - publie en Release win-x64 (framework-dependent),
      - (optionnel) signe l'exe si un certificat est fourni,
      - compile l'installeur Inno (ISCC) si disponible.

.PARAMETER Configuration
    Configuration de build (défaut: Release).

.PARAMETER Runtime
    RID cible (défaut: win-x64).

.PARAMETER SelfContained
    Publier en self-contained (inclut le runtime .NET). Activé par défaut (zéro prérequis .NET).

.PARAMETER FrameworkDependent
    Publier sans le runtime embarqué (installeur plus léger ; .NET 8 Desktop requis chez l'utilisateur).

.PARAMETER SignToolPath / CertSubject
    Si fournis, signe optiCombat.exe avec signtool (certificat du magasin par sujet).

.PARAMETER SkipInstaller
    Ne pas compiler l'installeur Inno.

.EXAMPLE
    pwsh -File scripts\publish-release.ps1
    pwsh -File scripts\publish-release.ps1 -FrameworkDependent
    pwsh -File scripts\publish-release.ps1 -CertSubject "Dona By"
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$Runtime = 'win-x64',
    [switch]$SelfContained,
    [switch]$FrameworkDependent,
    [string]$SignToolPath,
    [string]$CertSubject,
    [switch]$SkipInstaller
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $repo 'optiCombat\optiCombat.csproj'
$tfm  = 'net8.0-windows10.0.17763.0'
$publishDir = Join-Path $repo "optiCombat\bin\$Configuration\$tfm\publish\$Runtime"

function Write-Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }

# 1) Neutraliser le watchdog qui relance optiCombat pendant le build
Write-Step 'Arrêt du watchdog anti-sabotage'
schtasks.exe /Change /TN 'optiCombat_Watchdog' /DISABLE 2>$null | Out-Null
schtasks.exe /End    /TN 'optiCombat_Watchdog' 2>$null | Out-Null

# 2) Terminer les instances qui verrouillent les binaires
Write-Step 'Fermeture des instances optiCombat'
foreach ($p in 'optiCombat','optiCombat.Service') {
    Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 500

# 3) Nettoyer le dossier publish périmé
Write-Step 'Nettoyage du dossier publish'
if (Test-Path $publishDir) { Remove-Item -Recurse -Force $publishDir }

# 4) Publier (self-contained par défaut — pas de coût, zéro prérequis .NET chez l'utilisateur)
$publishSelfContained = if ($FrameworkDependent) { $false } elseif ($SelfContained) { $true } else { $true }
Write-Step "dotnet publish ($Configuration / $Runtime / self-contained=$publishSelfContained)"
$sc = if ($publishSelfContained) { 'true' } else { 'false' }
dotnet publish $proj -c $Configuration -r $Runtime --self-contained $sc -p:CleanPublishArtifactsBeforePublish=true
if ($LASTEXITCODE -ne 0) { throw "dotnet publish a échoué (code $LASTEXITCODE)." }

$exe = Join-Path $publishDir 'optiCombat.exe'
if (-not (Test-Path $exe)) { throw "optiCombat.exe introuvable après publish : $exe" }
Write-Host "Publié : $exe" -ForegroundColor Green

# 5) Signature Authenticode (certificat EV via thumbprint ou sujet)
if ($env:OPTICOMBAT_SIGN_THUMBPRINT) {
    Write-Step 'Signature EV (OPTICOMBAT_SIGN_THUMBPRINT)'
    & (Join-Path $repo 'scripts\sign-release.ps1') -PublishDir $publishDir
    if ($LASTEXITCODE -ne 0) { throw "sign-release.ps1 a échoué." }
    & (Join-Path $repo 'scripts\verify-signatures.ps1') -PublishDir $publishDir -Strict
}
elseif ($CertSubject) {
    Write-Step 'Signature Authenticode de optiCombat.exe'
    $st = if ($SignToolPath) { $SignToolPath } else { 'signtool.exe' }
    & $st sign /n $CertSubject /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $exe
    if ($LASTEXITCODE -ne 0) { throw "signtool a échoué (code $LASTEXITCODE)." }
}
else {
    Write-Warning "Pas de signature (paramètre -CertSubject non fourni). SmartScreen affichera « éditeur inconnu »."
}

# 6) Compiler l'installeur Inno
if (-not $SkipInstaller) {
    Write-Step 'Compilation de l''installeur Inno'
    $buildSetup = Join-Path $repo 'installer\build-release-setup.ps1'
    if (-not (Test-Path -LiteralPath $buildSetup)) { throw "Introuvable : $buildSetup" }
    & $buildSetup -SkipPublish -AllowMissingSignatures
    if ($LASTEXITCODE -ne 0) { throw "build-release-setup a échoué (code $LASTEXITCODE)." }
}

# 7) Réactiver le watchdog
Write-Step 'Réactivation du watchdog'
schtasks.exe /Change /TN 'optiCombat_Watchdog' /ENABLE 2>$null | Out-Null

Write-Host "`nTerminé." -ForegroundColor Green
