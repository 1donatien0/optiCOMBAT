# Affiche les chemins/processus à exclure dans Kaspersky (ou autre AV tiers)
# quand optiCombat est tué au démarrage (« processus liquidé »).
#
# Kaspersky ne permet pas d'automatiser les exclusions via PowerShell public ;
# copiez la liste ci-dessous dans :
#   Paramètres → Protection → Gestion des exclusions → Ajouter

[CmdletBinding()]
param(
    [string] $DevRoot
)

if ([string]::IsNullOrWhiteSpace($DevRoot)) {
    $DevRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { 'D:\Projets\optiCombat' }
}

$paths = @(
    $DevRoot
    (Join-Path $env:LOCALAPPDATA 'optiCombat')
    (Join-Path ${env:ProgramFiles} 'optiCombat')
) | ForEach-Object {
    try {
        if (Test-Path -LiteralPath $_) { (Resolve-Path -LiteralPath $_).Path }
        else { $_ }
    }
    catch { $_ }
} | Select-Object -Unique

$processes = @(
    'optiCombat.exe'
    'optiCombat.Service.exe'
    'opticombat.dll'
    'clamscan.exe'
    'freshclam.exe'
    'clamd.exe'
    'yara64.exe'
)

Write-Host ''
Write-Host '=== Exclusions Kaspersky (optiCombat) ===' -ForegroundColor Cyan
Write-Host ''
Write-Host 'Dossiers a exclure :' -ForegroundColor Yellow
foreach ($p in $paths) { Write-Host "  - $p" }

Write-Host ''
Write-Host 'Fichiers / applications (exclusion par objet) :' -ForegroundColor Yellow
foreach ($proc in $processes) { Write-Host "  - $proc" }

Write-Host ''
Write-Host 'Etapes Kaspersky :' -ForegroundColor Green
Write-Host '  1. Ouvrir Kaspersky → Parametres (engrenage)'
Write-Host '  2. Protection → Gestion des exclusions → Ajouter'
Write-Host '  3. Ajouter les dossiers ci-dessus (developpement : surtout le depot Git)'
Write-Host '  4. Ajouter optiCombat.exe et opticombat.dll (moteur natif)'
Write-Host '  5. Quarantaine → restaurer optiCombat si deja bloque'
Write-Host ''
Write-Host 'Dev : supprimez opticombat.dll si c''est une copie de optiCombat.dll,' -ForegroundColor DarkYellow
Write-Host '      puis scripts\build-engine.ps1 + scripts\sign-dev-local.ps1 -SignDev' -ForegroundColor DarkYellow
Write-Host ''
