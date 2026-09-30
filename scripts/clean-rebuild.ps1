<#
.SYNOPSIS
    Nettoyage complet bin/obj/.vs avant publication ou après changement majeur de structure,
    puis rebuild. Corrige le crash 0xE0434352 au démarrage (ressources XAML
    compilées sous l'ancien nom d'assembly).

.NOTES
    Fermer Visual Studio avant d'exécuter. N'efface PAS runtime\clamav\.
#>
[CmdletBinding()]
param([string]$Configuration = "Debug")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "==> Nettoyage des artefacts de build (bin/obj/.vs)..." -ForegroundColor Cyan
Remove-Item -Recurse -Force ".vs" -ErrorAction SilentlyContinue

$projects = @(
    "optiCombat",
    "optiCombat.Platform",
    "optiCombat.Service",
    "optiCombat.Tests",
    "tools\AdminRestoreQuarantine"
)
foreach ($p in $projects) {
    foreach ($d in @("bin", "obj")) {
        $path = Join-Path $root (Join-Path $p $d)
        if (Test-Path $path) {
            Remove-Item -Recurse -Force $path
            Write-Host "    supprimé: $p\$d"
        }
    }
}

# Sécurité : on n'a PAS touché runtime\clamav (binaires ClamAV).
if (-not (Test-Path "runtime\clamav\x64\clamscan.exe")) {
    Write-Warning "clamscan.exe introuvable — vérifier runtime\clamav\ !"
}

Write-Host "==> Restore + Build ($Configuration)..." -ForegroundColor Cyan
dotnet restore optiCombat.sln
dotnet build optiCombat.sln -c $Configuration --no-restore
if ($LASTEXITCODE -ne 0) { throw "Build en échec — voir les erreurs ci-dessus." }

Write-Host "==> OK. Lancer : optiCombat\bin\$Configuration\net8.0-windows*\optiCombat.exe" -ForegroundColor Green
