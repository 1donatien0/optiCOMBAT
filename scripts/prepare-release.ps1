<#
.SYNOPSIS
    Chaîne complète de publication v1.0 (dépôt -> installateur testé).

.EXAMPLE
    .\scripts\prepare-release.ps1
    .\scripts\prepare-release.ps1 -SkipFreshclam
    .\scripts\prepare-release.ps1 -SkipInstaller -RunFreshclam
#>
[CmdletBinding()]
param(
    [switch] $SkipTests,
    [switch] $SkipFetch,
    [switch] $SkipFreshclam,
    [switch] $SkipInstaller,
    [switch] $SkipClean,
    [switch] $SkipEngine,
    [switch] $SelfContained,
    [switch] $IncludeInstallerOutput,
    [switch] $Sign
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$tfm = 'net8.0-windows10.0.19041.0'
$pubDir = if ($SelfContained) {
    Join-Path $root 'publish\win-x64'
} else {
    Join-Path $root "optiCombat.WinUI\bin\Release\$tfm\publish\win-x64"
}

function Invoke-Step([string] $label, [scriptblock] $action) {
    Write-Host "`n=== $label ===" -ForegroundColor Cyan
    & $action
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
        throw "$label a échoué (code $LASTEXITCODE)."
    }
}

if (-not $SkipClean) {
    Invoke-Step 'Nettoyage' {
        $cleanArgs = @{ IncludeObj = $true; IncludeCiPublish = $true }
        if ($IncludeInstallerOutput) { $cleanArgs['IncludeInstallerOutput'] = $true }
        & (Join-Path $root 'scripts\clean-before-publish.ps1') @cleanArgs
    }
}

if (-not $SkipFetch) {
    $fetchArgs = @()
    if (-not $SkipFreshclam) { $fetchArgs += '-RunFreshclam' }
    Invoke-Step 'Dependances ClamAV + YARA' {
        & (Join-Path $root 'scripts\fetch-runtime-deps.ps1') @fetchArgs
    }
}

Invoke-Step 'Assets branding (Combat Aqua)' {
    python (Join-Path $root 'scripts\generate-brand-assets.py')
    if ($LASTEXITCODE -ne 0) { throw 'generate-brand-assets.py a echoue.' }
}

Invoke-Step 'Vider dossier publish (avant publish)' {
    & (Join-Path $root 'scripts\clear-publish-dir.ps1') -PublishDir $pubDir
}

if (-not $SkipTests) {
    Write-Host "`n=== Exclusions Defender (dev) ===" -ForegroundColor Cyan
    & (Join-Path $root 'scripts\add-defender-exclusions.ps1') -InstallDir $root -DevWorkspace
    if ($LASTEXITCODE -gt 1) {
        Write-Warning 'Exclusions Defender incomplètes — admin : .\scripts\add-defender-exclusions.ps1 -DevWorkspace'
    }

    Invoke-Step 'Tests Release' {
        dotnet build (Join-Path $root 'optiCombat.Tests\optiCombat.Tests.csproj') -c Release
        & (Join-Path $root 'scripts\unblock-dev-build.ps1')
        & (Join-Path $root 'scripts\sign-dev-local.ps1')
        if ($LASTEXITCODE -ne 0) {
            Write-Warning 'Signature dev absente — Smart App Control peut bloquer les tests (0x800711C7). Voir scripts\ensure-dev-trust.ps1'
        }
        dotnet test (Join-Path $root 'optiCombat.Tests\optiCombat.Tests.csproj') -c Release --no-build
    }
}

Invoke-Step 'dotnet publish' {
    $csproj = Join-Path $root 'optiCombat.WinUI\optiCombat.WinUI.csproj'
    $svc = Join-Path $root 'optiCombat.Service\optiCombat.Service.csproj'
    if ($SelfContained) {
        dotnet publish $csproj -c Release -r win-x64 --self-contained true `
            -p:PublishSingleFile=false -o $pubDir
        dotnet publish $svc -c Release -r win-x64 --self-contained true `
            -p:PublishSingleFile=false -o $pubDir
    } else {
        dotnet publish $csproj -c Release /p:PublishProfile=FolderProfile-SelfContained
        dotnet publish $svc -c Release -r win-x64 --self-contained false `
            -o (Join-Path $root "optiCombat.Service\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64")
        Copy-Item (Join-Path $root "optiCombat.Service\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\optiCombat.Service.exe") `
            (Join-Path $pubDir 'optiCombat.Service.exe') -ErrorAction SilentlyContinue
    }
}

if (-not $SkipEngine) {
    Invoke-Step 'Moteur Rust (opticombat.dll)' {
        & (Join-Path $root 'scripts\build-engine.ps1') -ExtraOutputDirs @($pubDir)
    }
}

Invoke-Step 'Verification publish' {
    & (Join-Path $root 'scripts\verify-runtime-deps.ps1') -PublishDir $pubDir
}

if ($Sign -or $env:OPTICOMBAT_SIGN_THUMBPRINT) {
    Invoke-Step 'Signature EV' {
        & (Join-Path $root 'scripts\sign-release.ps1') -PublishDir $pubDir
        & (Join-Path $root 'scripts\verify-signatures.ps1') -PublishDir $pubDir -Strict
    }
}

if (-not $SkipInstaller) {
    Invoke-Step 'Vider sortie installateur (avant Inno)' {
        & (Join-Path $root 'scripts\clear-installer-output.ps1')
    }
    Invoke-Step 'Icone installateur (Combat Aqua)' {
        & (Join-Path $root 'scripts\sync-installer-icon.ps1')
    }
    Invoke-Step 'Installateur Inno' {
        $build = Join-Path $root 'installer\build-release-setup.ps1'
        if ($SelfContained) {
            & $build -SkipPublish -PublishDir $pubDir
        } else {
            & $build -SkipPublish
        }
    }
}

Write-Host "`n=== Publication v1 prete ===" -ForegroundColor Green
Write-Host "  Publish : $pubDir"
Write-Host "  Setup   : installer\output\optiCombat_Setup_v1.0.0.exe"
