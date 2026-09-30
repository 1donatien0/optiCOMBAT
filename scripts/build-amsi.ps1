<#
.SYNOPSIS
    Compile optiCombat.AmsiProvider.dll (Release x64) via MSBuild / Visual Studio.

.PARAMETER Configuration
    MSBuild configuration (défaut : Release).

.PARAMETER Platform
    Plateforme MSBuild (défaut : x64).
#>
[CmdletBinding()]
param(
    [string] $Configuration = 'Release',
    [string] $Platform = 'x64'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$vcxproj = Join-Path $repo 'native\optiCombat.AmsiProvider\optiCombat.AmsiProvider.vcxproj'

if (-not (Test-Path -LiteralPath $vcxproj)) {
    throw "Projet introuvable : $vcxproj"
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    Write-Warning "vswhere absent — build AMSI ignoré (environnement sans Visual Studio)."
    exit 0
}

$msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) {
    Write-Warning "MSBuild introuvable — build AMSI ignoré."
    exit 0
}

Write-Host "Build AMSI : $vcxproj ($Configuration|$Platform)" -ForegroundColor Cyan
& $msbuild $vcxproj /p:Configuration=$Configuration /p:Platform=$Platform /m /v:minimal

$dll = Join-Path $repo "native\optiCombat.AmsiProvider\$Platform\$Configuration\optiCombat.AmsiProvider.dll"
if (-not (Test-Path -LiteralPath $dll)) {
    throw "DLL AMSI absente après build : $dll"
}

Write-Host "AMSI OK : $dll" -ForegroundColor Green
