# Verify Authenticode signatures on published binaries
[CmdletBinding()]
param(
    [string]$PublishDir = (Join-Path $PSScriptRoot "..\optiCombat\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64"),
    [switch]$Strict
)

$ErrorActionPreference = "Stop"
$files = @(
    "optiCombat.exe",
    "optiCombat.Service.exe",
    "opticombat.dll",
    "optiCombat.AmsiProvider.dll"
)

$missing = @()
$unsigned = @()
$valid = @()

foreach ($name in $files) {
    $path = Join-Path $PublishDir $name
    if (-not (Test-Path $path)) {
        $missing += $name
        continue
    }
    $sig = Get-AuthenticodeSignature -FilePath $path
    if ($sig.Status -eq "Valid") {
        $valid += "$name ($($sig.SignerCertificate.Subject))"
    } else {
        $unsigned += "$name ($($sig.Status))"
    }
}

Write-Host "`n=== Signature verification ===" -ForegroundColor Cyan
Write-Host "PublishDir: $PublishDir"
if ($valid.Count) {
    Write-Host "`nValid:" -ForegroundColor Green
    $valid | ForEach-Object { Write-Host "  $_" }
}
if ($unsigned.Count) {
    Write-Host "`nUnsigned or invalid:" -ForegroundColor Yellow
    $unsigned | ForEach-Object { Write-Host "  $_" }
}
if ($missing.Count) {
    Write-Host "`nMissing:" -ForegroundColor DarkGray
    $missing | ForEach-Object { Write-Host "  $_" }
}

if ($Strict -and ($unsigned.Count -gt 0 -or $missing.Count -gt 0)) {
    exit 1
}
exit 0
