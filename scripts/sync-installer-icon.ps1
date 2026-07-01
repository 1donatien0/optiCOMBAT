# Copie optiCombat.ico vers installer\ (source unique pour Inno Setup).
# Usage : .\scripts\sync-installer-icon.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root 'optiCombat\optiCombat.ico'
$dst = Join-Path $root 'installer\optiCombat.ico'

if (-not (Test-Path -LiteralPath $src)) {
    throw "Icone introuvable : $src (lancez generate-brand-assets.py)"
}

Copy-Item -LiteralPath $src -Destination $dst -Force
$item = Get-Item -LiteralPath $dst
Write-Host "Icone installateur synchronisee :" -ForegroundColor Green
Write-Host "  $dst ($($item.Length) octets, $($item.LastWriteTime.ToString('u')))"
exit 0
