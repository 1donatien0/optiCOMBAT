# Restaure les fichiers supprimés par un AV (Kaspersky, etc.) :
# logos, binaires de build, dépendances runtime. Les sources du dépôt ne sont pas modifiées.
#
# Usage (depuis la racine du dépôt) :
#   .\scripts\restore-after-av.ps1
#   .\scripts\restore-after-av.ps1 -Configuration Release

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Debug'
)

$ErrorActionPreference = 'Stop'
$root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { 'D:\Projets\optiCombat' }
Set-Location $root

Write-Host '==> Regeneration des assets de marque...' -ForegroundColor Cyan
python (Join-Path $root 'scripts\generate-brand-assets.py')
if ($LASTEXITCODE -ne 0) { throw 'generate-brand-assets.py a echoue.' }

Write-Host "==> Build solution ($Configuration)..." -ForegroundColor Cyan
dotnet build (Join-Path $root 'optiCombat.sln') -c $Configuration
if ($LASTEXITCODE -ne 0) { throw 'Build echoue.' }

$outDir = Get-ChildItem (Join-Path $root "optiCombat\bin\$Configuration") -Directory -Filter 'net8.0*' |
    Sort-Object Name -Descending |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $outDir) { throw "Dossier de sortie introuvable pour $Configuration." }

Write-Host "==> Sortie : $outDir" -ForegroundColor Green
$check = @(
    'optiCombat.exe', 'optiCombat.dll', 'optiCombat.ico', 'optiCombat_hero.png',
    'optiCombat_shield.png', 'clamav\x64\clamscan.exe', 'yara\yara64.exe'
)
$missing = @()
foreach ($f in $check) {
    if (-not (Test-Path (Join-Path $outDir $f))) { $missing += $f }
}

if ($missing.Count -gt 0) {
    Write-Warning ('Manquants apres build : ' + ($missing -join ', '))
    Write-Warning 'Verifiez la quarantaine Kaspersky et relancez apres exclusions.'
}
else {
    Write-Host 'Tous les fichiers cles sont presents.' -ForegroundColor Green
}

if (Get-Command cargo -ErrorAction SilentlyContinue) {
    Write-Host '==> Deploiement opticombat.dll (Rust)...' -ForegroundColor Cyan
    & (Join-Path $root 'scripts\build-engine.ps1') -Unblock
}
else {
    Write-Host 'cargo absent — opticombat.dll non redeployee (repli ClamAV OK).' -ForegroundColor DarkYellow
}

Write-Host ''
Write-Host 'Lancer :' -ForegroundColor Cyan
Write-Host "  $outDir\optiCombat.exe"
Write-Host ''
Write-Host 'Ajoutez des exclusions Kaspersky : .\scripts\kaspersky-exclusions-guide.ps1' -ForegroundColor DarkYellow
