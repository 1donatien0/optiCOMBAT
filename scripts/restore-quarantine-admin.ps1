# Restaure une entrée quarantaine vers son chemin d'origine (y compris System32).
# Nécessite une console PowerShell « Exécuter en tant qu'administrateur ».
# Usage: .\scripts\restore-quarantine-admin.ps1 <quarantineId>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $QuarantineId
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $root 'tools\AdminRestoreQuarantine\AdminRestoreQuarantine.csproj'

if (-not (Test-Path -LiteralPath $proj)) { throw "Introuvable: $proj" }

Write-Host "Restauration admin (id=$QuarantineId)..." -ForegroundColor Cyan
dotnet run --project $proj -c Release -- $QuarantineId
if ($LASTEXITCODE -ne 0) { throw "Restauration échouée (code $LASTEXITCODE)." }
Write-Host "Terminé." -ForegroundColor Green
