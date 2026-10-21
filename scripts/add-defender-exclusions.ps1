# Ajoute optiCombat aux exclusions Windows Defender (chemins + processus).
# Relance en administrateur si nécessaire.
# Usage :
#   .\scripts\add-defender-exclusions.ps1
#   .\scripts\add-defender-exclusions.ps1 -InstallDir "C:\Program Files\optiCombat"

[CmdletBinding()]
param(
    [string] $InstallDir,
    [switch] $DevWorkspace,
    [switch] $NoElevate
)

$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $NoElevate -and -not (Test-IsAdmin)) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-NoElevate')
    if ($InstallDir) { $argList += @('-InstallDir', $InstallDir) }
    if ($DevWorkspace) { $argList += '-DevWorkspace' }
    Write-Host 'Elevation UAC requise pour les exclusions Defender...' -ForegroundColor Yellow
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList -Wait
    exit $LASTEXITCODE
}

function Test-DefenderActive {
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        return $s.AMServiceEnabled
    }
    catch {
        return $false
    }
}

function Ensure-ExclusionPath([string[]] $Existing, [string] $Path, [ref] $Denied) {
    if (-not (Test-Path -LiteralPath $Path)) {
        $parent = Split-Path -Parent $Path
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $norm = (Resolve-Path -LiteralPath $Path).Path
    foreach ($e in $Existing) {
        if ($e.Equals($norm, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    try {
        Add-MpPreference -ExclusionPath $norm -ErrorAction Stop
        return $true
    }
    catch {
        $Denied.Value = $true
        Write-Warning "Chemin refuse : $norm — $($_.Exception.Message)"
        return $false
    }
}

function Ensure-ExclusionProcess([string[]] $Existing, [string] $Name, [ref] $Denied) {
    foreach ($e in $Existing) {
        if ($e.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    try {
        Add-MpPreference -ExclusionProcess $Name -ErrorAction Stop
        return $true
    }
    catch {
        $Denied.Value = $true
        Write-Warning "Processus refuse : $Name — $($_.Exception.Message)"
        return $false
    }
}

if (-not (Test-DefenderActive)) {
    Write-Warning 'Windows Defender inactif ou indisponible — exclusions ignorees.'
    exit 2
}

if (-not (Test-IsAdmin)) {
    Write-Warning 'Droits administrateur requis pour Add-MpPreference. Relancez sans -NoElevate ou en admin.'
    exit 3
}

$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path ${env:ProgramFiles} 'optiCombat'
    if (-not (Test-Path -LiteralPath $InstallDir)) {
        $InstallDir = $root
    }
}

$paths = @(
    $InstallDir
    (Join-Path $env:LOCALAPPDATA 'optiCombat')
)
if ($DevWorkspace) {
    $paths += $root
    foreach ($sub in @('optiCombat', 'optiCombat.Tests', 'optiCombat.Service', 'optiCombat.Platform', 'engine')) {
        $paths += Join-Path $root $sub
    }
}
$paths = $paths | ForEach-Object {
    try { (Resolve-Path -LiteralPath $_ -ErrorAction SilentlyContinue).Path } catch { $_ }
} | Where-Object { $_ } | Select-Object -Unique

# Exclusions de processus par CHEMIN COMPLET uniquement : une exclusion par nom seul
# (« optiCombat.exe ») couvre tout exécutable de ce nom, n'importe où sur le disque.
$processes = @()
if ($InstallDir) {
    foreach ($rel in @('optiCombat.exe', 'optiCombat.Service.exe', 'clamav\x64\clamscan.exe',
                       'clamav\x64\freshclam.exe', 'clamav\x64\clamd.exe', 'yara\yara64.exe')) {
        $full = Join-Path $InstallDir $rel
        if (Test-Path -LiteralPath $full) { $processes += (Resolve-Path -LiteralPath $full).Path }
    }
}
if ($DevWorkspace) {
    # Volontairement aucune exclusion dotnet.exe / MSBuild.exe / testhost.exe : elles
    # désactiveraient l'analyse de TOUT code .NET exécuté sur le poste. Les chemins du
    # dépôt (ci-dessus) suffisent pour les faux positifs de build.
    Write-Warning 'DevWorkspace : exclusions de chemins du dépôt uniquement (aucun processus générique).'
}

$pref = Get-MpPreference
$pathExisting = @($pref.ExclusionPath)
$procExisting = @($pref.ExclusionProcess)
$added = 0
$denied = $false

foreach ($p in $paths) {
    if (Ensure-ExclusionPath $pathExisting $p ([ref]$denied)) {
        Write-Host "  + chemin $p" -ForegroundColor Green
        if (Test-Path -LiteralPath $p) {
            $pathExisting += (Resolve-Path -LiteralPath $p).Path
        }
        $added++
    }
}

foreach ($proc in $processes) {
    if (Ensure-ExclusionProcess $procExisting $proc ([ref]$denied)) {
        Write-Host "  + processus $proc" -ForegroundColor Green
        $procExisting += $proc
        $added++
    }
}

if ($added -eq 0 -and -not $denied) {
    Write-Host 'Exclusions Defender deja en place.' -ForegroundColor Cyan
    exit 0
}

if ($denied) {
    Write-Host 'Certaines exclusions n''ont pas pu etre ajoutees (droits admin ou protection contre la falsification).' -ForegroundColor Yellow
    exit 4
}

Write-Host "Exclusions Defender ajoutees : $added" -ForegroundColor Green
exit 0
