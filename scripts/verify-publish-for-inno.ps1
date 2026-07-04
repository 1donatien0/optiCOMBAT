# Verifie que optiCombat.exe est la ou Inno Setup (setup.iss) le cherche.
# Usage : .\scripts\verify-publish-for-inno.ps1

[CmdletBinding()]
param(
    [switch] $FailOnMissing
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tfm = 'net8.0-windows10.0.19041.0'

$candidates = @(
    @{ Label = 'Release publish win-x64 (attendu)'; Path = "optiCombat.WinUI\bin\Release\$tfm\publish\win-x64\optiCombat.exe" },
    @{ Label = 'Release publish plat'; Path = "optiCombat.WinUI\bin\Release\$tfm\publish\optiCombat.exe" },
    @{ Label = 'Release win-x64 intermediaire (build, pas publish)'; Path = "optiCombat.WinUI\bin\Release\$tfm\win-x64\optiCombat.exe" },
    @{ Label = 'Debug publish win-x64 (mauvaise config pour Inno)'; Path = "optiCombat.WinUI\bin\Debug\$tfm\publish\win-x64\optiCombat.exe" },
    @{ Label = 'Ancien VS net8.0 publish win-x64'; Path = 'optiCombat.WinUI\bin\Release\net8.0\publish\win-x64\optiCombat.exe' },
    @{ Label = 'CI publish racine'; Path = 'publish\win-x64\optiCombat.exe' }
)

Write-Host "`n=== verify-publish-for-inno ===`n" -ForegroundColor Cyan
$found = @()
foreach ($c in $candidates) {
    $full = Join-Path $root $c.Path
    if (Test-Path -LiteralPath $full) {
        $item = Get-Item -LiteralPath $full
        Write-Host "[OK] $($c.Label)" -ForegroundColor Green
        Write-Host "     $($item.FullName)  ($([math]::Round($item.Length/1KB)) Ko, $($item.LastWriteTime))`n"
        $found += $item
    }
    else {
        Write-Host "[--] $($c.Label)" -ForegroundColor DarkGray
        Write-Host "     $full`n"
    }
}

if ($found.Count -eq 0) {
    Write-Host "Aucun optiCombat.exe trouve. Inno echouera." -ForegroundColor Red
    Write-Host @"

Publiez en Release avec le bon profil :
  dotnet publish .\optiCombat.WinUI\optiCombat.WinUI.csproj -c Release -p:PublishProfile=FolderProfile-SelfContained

VS : clic droit optiCombat > Publier > FolderProfile-SelfContained (Configuration = Release).

Attention : un nettoyage (clean-before-publish) efface publish\ — republiez ensuite.
"@ -ForegroundColor Yellow
    if ($FailOnMissing) { exit 1 }
    exit 0
}

$preferred = $found | Where-Object {
    $_.FullName -like "*\bin\Release\$tfm\publish\win-x64\optiCombat.exe"
} | Select-Object -First 1

if ($preferred) {
    Write-Host "Inno utilisera : $($preferred.FullName)" -ForegroundColor Green
}
else {
    Write-Host "optiCombat.exe present mais PAS au chemin attendu par setup.iss (Release\...\publish\win-x64\)." -ForegroundColor Yellow
    Write-Host "Republiez avec FolderProfile-SelfContained en Release, ou compilez Inno via build-release-setup.ps1 -PublishDir ..." -ForegroundColor Yellow
    if ($FailOnMissing) { exit 2 }
}
