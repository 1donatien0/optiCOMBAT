# Supprime les installateurs .exe existants avant compilation Inno.
# Usage : .\scripts\clear-installer-output.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $root 'installer\output'

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$removed = 0
Get-ChildItem -LiteralPath $outDir -Filter '*.exe' -File -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "  Suppression : $($_.Name)" -ForegroundColor DarkGray
    Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
    $removed++
}

Write-Host "Sortie installateur prete ($removed fichier(s) supprime(s)) : $outDir" -ForegroundColor Green
exit 0
