<#
.SYNOPSIS
    Vérifie que tous les binaires et fichiers critiques sont présents dans le dossier
    de publication avant de créer l'installateur Inno Setup.

.PARAMETER PublishDir
    Chemin du dossier de publication (ex. publish\win-x64).

.EXAMPLE
    pwsh -File scripts\verify-runtime-deps.ps1 -PublishDir publish\win-x64
#>

param (
    [string] $PublishDir,
    [switch] $AllowMissingSignatures
)

if ([string]::IsNullOrWhiteSpace($PublishDir)) {
    $repo = Split-Path -Parent $PSScriptRoot
    $PublishDir = Join-Path $repo 'optiCombat\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64'
    if (-not (Test-Path (Join-Path $PublishDir 'optiCombat.exe'))) {
        $PublishDir = Join-Path $repo 'publish\win-x64'
    }
}
$PublishDir = (Resolve-Path -LiteralPath $PublishDir).Path

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$sourceRoot = Join-Path $repo 'optiCombat'
$failed = @()
$warned = @()

function Resolve-SourceOrPublishPath([string]$RelPath) {
    $inPublish = Join-Path $PublishDir $RelPath
    if (Test-Path -LiteralPath $inPublish) { return $inPublish }
    $inSource = Join-Path $sourceRoot $RelPath
    if (Test-Path -LiteralPath $inSource) { return $inSource }
    return $null
}

function Check {
    param(
        [string]$RelPath,
        [string]$Description,
        [switch]$Optional
    )
    $resolved = Resolve-SourceOrPublishPath $RelPath
    if ($null -eq $resolved) {
        if ($Optional) {
            Write-Host "  SKIP      $RelPath  ($Description, optionnel)" -ForegroundColor Yellow
            $script:warned += $RelPath
        } else {
            Write-Host "  MANQUANT  $RelPath  ($Description)" -ForegroundColor Red
            $script:failed += $RelPath
        }
    } else {
        $label = if ($resolved.StartsWith($PublishDir, [StringComparison]::OrdinalIgnoreCase)) { $RelPath } else { "$RelPath (source projet)" }
        Write-Host "  OK        $label" -ForegroundColor Green
    }
}

Write-Host "`n=== verify-runtime-deps.ps1 - $PublishDir ===`n" -ForegroundColor Cyan

Write-Host "[ Executable ]"
Check "optiCombat.exe" "Executable principal"

Write-Host "`n[ ClamAV x64 ]"
Check "clamav\x64\clamscan.exe"  "Scanner ClamAV"
Check "clamav\x64\freshclam.exe" "Mise a jour signatures"
Check "clamav\x64\clamd.exe"     "Daemon ClamAV"
$clambc = Join-Path $PublishDir "clamav\x64\clambc.exe"
if (Test-Path $clambc) {
    Write-Host "  OK        clamav\x64\clambc.exe" -ForegroundColor Green
} else {
    Write-Host "  SKIP      clamav\x64\clambc.exe (optionnel)" -ForegroundColor Yellow
}
Check "clamav\certs\clamav.crt"  "Certificat CA Cisco-Talos"

Write-Host "`n[ Signatures ClamAV ]"
$dbPublish = Join-Path $PublishDir "clamav\database"
$dbSource = Join-Path $sourceRoot "clamav\database"
$sigFiles = @()
foreach ($db in @($dbPublish, $dbSource)) {
    if (Test-Path -LiteralPath $db) {
        $sigFiles += Get-ChildItem -Path $db -Filter "*.cvd" -ErrorAction SilentlyContinue
        if ($sigFiles.Count -eq 0) {
            $sigFiles += Get-ChildItem -Path $db -Filter "*.cld" -ErrorAction SilentlyContinue
        }
    }
}
$sigFiles = $sigFiles | Select-Object -Unique FullName
if ($sigFiles.Count -eq 0) {
    if ($AllowMissingSignatures) {
        Write-Host "  SKIP      clamav\database (AllowMissingSignatures, MAJ au 1er lancement)" -ForegroundColor Yellow
    } else {
        Write-Host "  MANQUANT  clamav\database\*.cvd / *.cld  (fetch-runtime-deps.ps1 -RunFreshclam)" -ForegroundColor Red
        $failed += "clamav\database\*.cvd"
    }
} else {
    foreach ($f in $sigFiles) {
        Write-Host "  OK        $($f.FullName.Replace($repo + '\', ''))" -ForegroundColor Green
    }
}

Write-Host "`n[ YARA ]"
Check "yara\yara64.exe" "YARA engine x64"
$yara32 = Join-Path $PublishDir "yara\yara32.exe"
if (Test-Path $yara32) {
    Write-Host "  OK        yara\yara32.exe" -ForegroundColor Green
} else {
    Write-Host "  SKIP      yara\yara32.exe (optionnel si processus x64 uniquement)" -ForegroundColor Yellow
}

$yaraRules = Get-ChildItem -Path (Join-Path $PublishDir "rules") -Filter "*.yar" -Recurse -ErrorAction SilentlyContinue
if ($yaraRules.Count -eq 0) {
    $yaraRules = Get-ChildItem -Path (Join-Path $sourceRoot "rules") -Filter "*.yar" -Recurse -ErrorAction SilentlyContinue
}
if ($yaraRules.Count -eq 0) {
    Write-Host "  MANQUANT  rules\*.yar  (regles YARA)" -ForegroundColor Red
    $failed += "rules\*.yar"
} else {
    Write-Host "  OK        rules\ - $($yaraRules.Count) regle(s) .yar" -ForegroundColor Green
}

Write-Host "`n[ Ressources ]"
Check "optiCombat.ico" "Icone application" -Optional
Check "optiCombat_hero.png" "Image hero bouclier" -Optional

Write-Host ""
if ($failed.Count -eq 0) {
    Write-Host "=== Toutes les dependances sont presentes. Publication OK. ===" -ForegroundColor Green
    exit 0
} else {
    Write-Host "=== ECHEC : $($failed.Count) dependance(s) manquante(s) ===" -ForegroundColor Red
    foreach ($f in $failed) { Write-Host "  - $f" -ForegroundColor Red }
    exit 1
}
