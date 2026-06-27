<#
.SYNOPSIS
    Build optiCombat Rust cdylib and deploy opticombat.dll to .NET output folders.

.DESCRIPTION
    1. cargo build -p opticombat-ffi --release
    2. Copy opticombat.dll next to every optiCombat.exe under optiCombat\bin\

    Requires Rust stable (https://rustup.rs). Run from repository root.
#>
[CmdletBinding()]
param(
    [string[]]$ExtraOutputDirs = @(),
    [switch]$SignDev,
    [switch]$Unblock
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "Building optiCombat cdylib (release)..." -ForegroundColor Cyan
cargo build --manifest-path engine\Cargo.toml -p opticombat-ffi --release
if ($LASTEXITCODE -ne 0) { throw "Rust build failed." }

$dll = Join-Path $root "engine\target\release\opticombat.dll"
if (-not (Test-Path $dll)) { throw "Missing DLL: $dll" }

$targets = @()
$targets += Get-ChildItem -Path (Join-Path $root "optiCombat\bin") -Directory -Recurse -ErrorAction SilentlyContinue |
            Where-Object { Test-Path (Join-Path $_.FullName "optiCombat.exe") } |
            Select-Object -ExpandProperty FullName
$targets += $ExtraOutputDirs

if ($targets.Count -eq 0) {
    Write-Warning "No optiCombat.exe found. Build the .NET app first, then rerun this script."
}

$sizeMb = [math]::Round((Get-Item $dll).Length / 1MB, 2)
foreach ($t in ($targets | Select-Object -Unique)) {
    Copy-Item $dll -Destination $t -Force
    if ($Unblock) {
        Unblock-File -LiteralPath (Join-Path $t 'opticombat.dll') -ErrorAction SilentlyContinue
    }
    Write-Host ('Deployed opticombat.dll (' + $sizeMb + ' MB) to ' + $t) -ForegroundColor Green
}

if ($SignDev -or $env:OPTICOMBAT_DEV_SIGN -eq '1') {
    Write-Host 'Signing deployed binaries (dev cert)...' -ForegroundColor Cyan
    & (Join-Path $root 'scripts\sign-dev-local.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'sign-dev-local.ps1 failed.' }
}

Write-Host "Done. Restart optiCombat.exe to activate the Rust engine." -ForegroundColor Green
