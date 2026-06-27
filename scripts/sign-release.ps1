# Sign release binaries (requires EV code signing certificate)
[CmdletBinding()]
param(
    [string]$PublishDir = (Join-Path $PSScriptRoot "..\optiCombat\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64"),
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$CertThumbprint = $env:OPTICOMBAT_SIGN_THUMBPRINT
)

$ErrorActionPreference = "Stop"

if (-not $CertThumbprint) {
    Write-Host @"
No signing certificate configured.

Set OPTICOMBAT_SIGN_THUMBPRINT to your EV certificate thumbprint, then re-run.

Components to sign for distribution:
  - optiCombat.exe
  - optiCombat.Service.exe
  - opticombat.dll
  - optiCombat.AmsiProvider.dll
  - optiCombat.Minifilter.sys (requires Microsoft attestation)

See docs/SIGNING.md for the full EV + driver signing workflow.
"@
    exit 0
}

$signtool = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Get-Item -ErrorAction SilentlyContinue | Select-Object -Last 1
if (-not $signtool) { throw "signtool.exe not found. Install Windows SDK." }

$files = @(
    "optiCombat.exe",
    "optiCombat.Service.exe",
    "opticombat.dll",
    "optiCombat.AmsiProvider.dll"
)

foreach ($name in $files) {
    $path = Join-Path $PublishDir $name
    if (-not (Test-Path $path)) {
        Write-Warning "Skip missing: $path"
        continue
    }
    Write-Host "Signing $name..." -ForegroundColor Cyan
    & $signtool sign /sha1 $CertThumbprint /tr $TimestampUrl /td sha256 /fd sha256 $path
    if ($LASTEXITCODE -ne 0) { throw "Signing failed: $name" }
}

Write-Host "Signing complete." -ForegroundColor Green
