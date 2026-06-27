<#
.SYNOPSIS
    A executer UNE FOIS en PowerShell administrateur — confiance certificat dev + exclusions Defender.
.EXAMPLE
    Clic droit PowerShell > Executer en tant qu'administrateur :
    cd D:\Projets\optiCombat
    .\scripts\setup-dev-trust-admin.ps1
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string] $CertThumbprint = 'C308F985E35051B8A062CE3D07C93459D8B103BF'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

Write-Host "`n=== TrustedPublisher (certificat dev optiCOMBAT) ===" -ForegroundColor Cyan
certutil -addstore TrustedPublisher $CertThumbprint

Write-Host "`n=== Exclusions Defender (depot dev) ===" -ForegroundColor Cyan
& (Join-Path $root 'scripts\add-defender-exclusions.ps1') -InstallDir $root -DevWorkspace -NoElevate

Write-Host "`n=== OK ===" -ForegroundColor Green
Write-Host "Puis dans une console normale :"
Write-Host "  cd $root"
Write-Host "  .\scripts\ensure-dev-trust.ps1 -SkipDefender"
Write-Host "  dotnet build optiCombat.Tests\optiCombat.Tests.csproj -c Release"
Write-Host "  .\scripts\sign-dev-local.ps1"
Write-Host "  dotnet test optiCombat.Tests\optiCombat.Tests.csproj -c Release --no-build"
