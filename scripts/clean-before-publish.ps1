# Vide les sorties Release avant publication / Inno Setup.
# Supprime TOUS les dossiers publish (win-x64 ET racine publish\) pour qu'Inno
# ne reprenne jamais un optiCombat.exe residuel (setup.iss fallback publish\*).
# Usage (racine du depot) :
#   .\scripts\clean-before-publish.ps1 -IncludeObj
#   .\scripts\clean-before-publish.ps1 -IncludeObj -IncludeInstallerOutput

[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string] $Configuration = 'Release',
    [switch] $IncludeObj,
    [switch] $IncludeInstallerOutput,
    [switch] $IncludeCiPublish
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tfm = 'net8.0-windows10.0.17763.0'
$binDir = Join-Path $root "optiCombat.WinUI\bin\$Configuration\$tfm"
$objDir = Join-Path $root "optiCombat\obj\$Configuration\$tfm"
$legacyVsBinDir = Join-Path $root "optiCombat.WinUI\bin\$Configuration\net8.0"
$legacyVsObjDir = Join-Path $root "optiCombat\obj\$Configuration\net8.0"
$ridOutputDir = Join-Path $binDir 'win-x64'
$publishRoot = Join-Path $binDir 'publish'
$publishWinX64 = Join-Path $publishRoot 'win-x64'
$legacyPublishWinX64 = Join-Path $legacyVsBinDir 'publish\win-x64'
$legacyPublishRoot = Join-Path $legacyVsBinDir 'publish'
$ciPublishRoot = Join-Path $root 'publish'
$testsBin = Join-Path $root 'optiCombat.Tests\bin'
$testsObj = Join-Path $root 'optiCombat.Tests\obj'
$installerOut = Join-Path $root 'installer\output'
$platformLegacyBin = Join-Path $root "optiCombat.Platform\bin\$Configuration\net8.0"
$platformObjPublish = Join-Path $root 'optiCombat.Platform\obj\publish'
$opticombatObjPublish = Join-Path $root 'optiCombat\obj\publish'

function Remove-PathIfExists([string] $path, [string] $label) {
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    Write-Host "  - $label" -ForegroundColor DarkGray
    Write-Host "    $path"
    try {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
    }
    catch {
        Stop-ProcessesLockingPublish $binDir
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
    }
    return $true
}

function Remove-OpticombatExecutables([string] $searchRoot) {
    if (-not (Test-Path -LiteralPath $searchRoot)) { return 0 }
    $exes = Get-ChildItem -LiteralPath $searchRoot -Recurse -Filter 'optiCombat.exe' -File -ErrorAction SilentlyContinue
    $count = 0
    foreach ($exe in $exes) {
        Write-Host "  - optiCombat.exe" -ForegroundColor DarkGray
        Write-Host "    $($exe.FullName)"
        Remove-Item -LiteralPath $exe.FullName -Force -ErrorAction Stop
        $count++
    }
    return $count
}

function Stop-ProcessesLockingPublish([string] $binRoot) {
    $names = @('optiCombat', 'yara64', 'clamscan', 'freshclam', 'clamd')
  foreach ($name in $names) {
    Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
      Write-Host "  - Arret $name (PID $($_.Id))" -ForegroundColor Yellow
      Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
  }
  if (Test-Path -LiteralPath $binRoot) {
    Get-Process -ErrorAction SilentlyContinue | Where-Object {
      $_.Path -and $_.Path.StartsWith($binRoot, [System.StringComparison]::OrdinalIgnoreCase)
    } | ForEach-Object {
      Write-Host "  - Arret $($_.ProcessName) (PID $($_.Id))" -ForegroundColor Yellow
      Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
  }
  Start-Sleep -Seconds 1
}

Write-Host "Nettoyage avant publication ($Configuration)..." -ForegroundColor Cyan
Stop-ProcessesLockingPublish $binDir

$removed = 0

# Ancienne cible Visual Studio erronee (bin\Release\net8.0\publish\...)
if (Remove-PathIfExists $legacyPublishWinX64 'publish\win-x64 (ancien profil VS net8.0)') { $removed++ }
if (Remove-PathIfExists $legacyPublishRoot 'publish\ (ancien profil VS net8.0)') { $removed++ }
if (Remove-PathIfExists $legacyVsBinDir "Dossier bin\$Configuration\net8.0 (profil VS obsolete)") { $removed++ }
if (Remove-PathIfExists $legacyVsObjDir "Dossier obj\$Configuration\net8.0 (profil VS obsolete)") { $removed++ }

# Publish residuel (prioritaire - evite le fallback Inno setup.iss publish\*.exe)
if (Remove-PathIfExists $publishWinX64 'publish\win-x64 (Inno / FolderProfile)') { $removed++ }
if (Remove-PathIfExists $publishRoot 'publish\ (racine, exe plat obsolete)') { $removed++ }
if (Remove-PathIfExists $ridOutputDir 'win-x64 intermediaire (hors publish\)') { $removed++ }

# Publish residuels projets satellites / obj
if (Remove-PathIfExists (Join-Path $platformLegacyBin 'publish') 'optiCombat.Platform publish (net8.0 obsolete)') { $removed++ }
if (Remove-PathIfExists $platformLegacyBin 'optiCombat.Platform bin\net8.0 (obsolete)') { $removed++ }
if (Remove-PathIfExists $platformObjPublish 'optiCombat.Platform\obj\publish') { $removed++ }
if (Remove-PathIfExists $opticombatObjPublish 'optiCombat\obj\publish') { $removed++ }

if ($IncludeCiPublish) {
    if (Remove-PathIfExists $ciPublishRoot 'publish\ a la racine du depot (CI)') { $removed++ }
}

if (Remove-PathIfExists $binDir "Dossier bin complet ($Configuration)") { $removed++ }

if ($Configuration -eq 'Release') {
    if (Remove-PathIfExists $testsBin 'optiCombat.Tests\bin') { $removed++ }
    if (Remove-PathIfExists $testsObj 'optiCombat.Tests\obj') { $removed++ }
}

# Securite : exe residuels hors bin (publish partiel, ancien RID, etc.)
$extraDirs = @(
    (Join-Path $root "optiCombat.WinUI\bin\$Configuration"),
    (Join-Path $root 'optiCombat\bin')
)
foreach ($dir in $extraDirs) {
    if (Test-Path -LiteralPath $dir) {
        $removed += Remove-OpticombatExecutables $dir
    }
}

if ($IncludeObj) {
    if (Remove-PathIfExists $objDir "Dossier obj ($Configuration)") { $removed++ }
}

if ($IncludeInstallerOutput) {
    if (Test-Path -LiteralPath $installerOut) {
        Get-ChildItem -LiteralPath $installerOut -Filter '*.exe' -File -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "  - installateur" -ForegroundColor DarkGray
            Write-Host "    $($_.FullName)"
            Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
            $removed++
        }
    }
}

Write-Host ""
Write-Host ""
Write-Host "Nettoyage termine ($removed operation(s))." -ForegroundColor Green
Write-Host "Ordre obligatoire avant Inno (sans publish frais = installateur obsolete) :" -ForegroundColor Yellow
Write-Host "  1. .\scripts\clean-before-publish.ps1 -IncludeObj [-IncludeInstallerOutput]"
Write-Host "  2. dotnet publish .\optiCombat.WinUI\optiCombat.WinUI.csproj -c Release -p:PublishProfile=FolderProfile-SelfContained"
Write-Host "  3. .\scripts\verify-runtime-deps.ps1"
Write-Host "  4. .\installer\build-release-setup.ps1 -SkipPublish   # ou ISCC avec AppPublishSource win-x64"
Write-Host ""
Write-Host "Tout-en-un : .\scripts\prepare-release.ps1  ou  .\installer\build-release-setup.ps1"
