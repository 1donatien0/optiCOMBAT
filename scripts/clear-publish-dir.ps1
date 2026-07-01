# Vide entierement un dossier publish avant dotnet publish (evite fichiers residuels).
# Usage :
#   .\scripts\clear-publish-dir.ps1
#   .\scripts\clear-publish-dir.ps1 -PublishDir D:\chemin\publish\win-x64

[CmdletBinding()]
param(
    [string] $PublishDir
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tfm = 'net8.0-windows10.0.17763.0'

if ([string]::IsNullOrWhiteSpace($PublishDir)) {
    $PublishDir = Join-Path $root "optiCombat\bin\Release\$tfm\publish\win-x64"
} elseif (-not [System.IO.Path]::IsPathRooted($PublishDir)) {
    $PublishDir = Join-Path $root $PublishDir
}

$names = @('optiCombat', 'yara64', 'clamscan', 'freshclam', 'clamd')
foreach ($name in $names) {
    Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "  Arret $name (PID $($_.Id))" -ForegroundColor Yellow
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}

if (Test-Path -LiteralPath $PublishDir) {
    Write-Host "Suppression du dossier publish :" -ForegroundColor Cyan
    Write-Host "  $PublishDir" -ForegroundColor DarkGray
    Remove-Item -LiteralPath $PublishDir -Recurse -Force -ErrorAction Stop
}

New-Item -ItemType Directory -Path $PublishDir -Force | Out-Null
Write-Host "Dossier publish vide pret : $PublishDir" -ForegroundColor Green
exit 0
