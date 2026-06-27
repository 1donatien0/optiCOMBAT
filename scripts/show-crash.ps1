<#
.SYNOPSIS
    Affiche la dernière exception de démarrage d'optiCombat (à coller dans le chat).
.DESCRIPTION
    Cherche, dans l'ordre :
      1. %LOCALAPPDATA%\optiCombat\Logs\startup-crash.log  (capteur ModuleInitializer)
      2. le .log le plus récent du même dossier            (filet AppLogger)
      3. les évènements « .NET Runtime » de l'Observateur d'évènements
.NOTES
    Lancer APRÈS avoir reproduit le crash (optiCombat.exe).
#>
$ErrorActionPreference = "SilentlyContinue"
$dir = Join-Path $env:LOCALAPPDATA "optiCombat\Logs"

Write-Host "=== 1) startup-crash.log (capteur de tout premier niveau) ===" -ForegroundColor Cyan
$crash = Join-Path $dir "startup-crash.log"
if (Test-Path $crash) { Get-Content $crash -Tail 100 }
else { Write-Host "  (absent — capteur non déclenché ou pas encore recompilé)" -ForegroundColor Yellow }

Write-Host "`n=== 2) Dernier log AppLogger ===" -ForegroundColor Cyan
$last = Get-ChildItem $dir -Filter *.log | Where-Object { $_.Name -ne "startup-crash.log" } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($last) { Write-Host "  ($($last.Name))"; Get-Content $last.FullName -Tail 100 }
else { Write-Host "  (aucun autre log)" -ForegroundColor Yellow }

Write-Host "`n=== 3) Évènements .NET Runtime / Application Error (optiCombat) ===" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = '.NET Runtime' } -MaxEvents 8 |
    Where-Object { $_.Message -match 'optiCombat' } |
    Select-Object -First 2 |
    ForEach-Object { Write-Host $_.TimeCreated -ForegroundColor DarkGray; Write-Host $_.Message; Write-Host "----" }

Write-Host "`n>> Copie tout ce qui précède et colle-le dans le chat." -ForegroundColor Green
