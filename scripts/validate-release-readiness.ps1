<#
.SYNOPSIS
    Validation automatisee avant release (tests Release + dependances publish optionnelles).

.DESCRIPTION
    Equivalent partiel de la checklist README section 8.
    Ne remplace pas le test installateur sur VM propre.

.PARAMETER WithPublishCheck
    Lance verify-runtime-deps.ps1 si le dossier publish win-x64 existe.

.EXAMPLE
    .\scripts\validate-release-readiness.ps1
    .\scripts\validate-release-readiness.ps1 -WithPublishCheck
#>

param(
    [switch] $WithPublishCheck
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

Write-Host ""
Write-Host "=== optiCombat validate-release-readiness ===" -ForegroundColor Cyan
Write-Host ""

Push-Location $repo
try {
    Write-Host "[ Tests Release ]" -ForegroundColor Cyan
    dotnet test optiCombat.Tests\optiCombat.Tests.csproj -c Release
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    if ($WithPublishCheck) {
        Write-Host ""
        Write-Host "[ Publish runtime deps ]" -ForegroundColor Cyan
        $pub = Join-Path $repo 'optiCombat\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64'
        if (-not (Test-Path (Join-Path $pub 'optiCombat.exe'))) {
            $pub = Join-Path $repo 'publish\win-x64'
        }
        if (Test-Path (Join-Path $pub 'optiCombat.exe')) {
            & "$PSScriptRoot\verify-runtime-deps.ps1" -PublishDir $pub
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        }
        else {
            Write-Warning "Dossier publish absent - lancer dotnet publish ou .\scripts\prepare-release.ps1"
        }
    }

    Write-Host ""
    Write-Host "OK - validate-release-readiness termine" -ForegroundColor Green
}
finally {
    Pop-Location
}
