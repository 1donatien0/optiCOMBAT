# Sign optiCombat binaries for local dev (SmartScreen / SAC — unsigned opticombat.dll).
#
# Production: use EV cert via scripts/sign-release.ps1 + OPTICOMBAT_SIGN_THUMBPRINT
# Dev: this script creates a self-signed cert (once) and signs exe + opticombat.dll
#
# Usage:
#   .\scripts\sign-dev-local.ps1 -CreateCert          # first time only
#   .\scripts\sign-dev-local.ps1
#   .\scripts\build-engine.ps1 -SignDev
[CmdletBinding()]
param(
    [switch]$CreateCert,
    [string]$Configuration = 'Release',
    [string]$CertSubject = 'CN=optiCombat Dev, O=Dona By',
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tfm = 'net8.0-windows10.0.17763.0'

function Get-SignTool {
    $st = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Get-Item -ErrorAction SilentlyContinue | Select-Object -Last 1
    if (-not $st) { throw 'signtool.exe not found. Install Windows SDK.' }
    return $st.FullName
}

function Get-DevCert {
    param([string]$Subject)
    Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $Subject } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1
}

function Find-BinDirs {
    $dirs = @()
    $base = Join-Path $root "optiCombat\bin\$Configuration\$tfm"
    if (Test-Path (Join-Path $base 'optiCombat.exe')) { $dirs += $base }
    if (Test-Path $base) {
        Get-ChildItem -Path $base -Directory -Recurse -ErrorAction SilentlyContinue |
            Where-Object { Test-Path (Join-Path $_.FullName 'optiCombat.exe') } |
            ForEach-Object { $dirs += $_.FullName }
    }
    $pub = Join-Path $base 'publish\win-x64'
    if (Test-Path (Join-Path $pub 'optiCombat.exe')) { $dirs += $pub }
    return $dirs | Select-Object -Unique
}

if ($CreateCert) {
    $existing = Get-DevCert -Subject $CertSubject
    if ($existing) {
        Write-Host "Dev cert already exists: $($existing.Subject) ($($existing.Thumbprint))" -ForegroundColor Yellow
    } else {
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $CertSubject `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -HashAlgorithm SHA256 `
            -KeyExportPolicy Exportable `
            -NotAfter (Get-Date).AddYears(3)
        Write-Host "Created dev code-signing cert:" -ForegroundColor Green
        Write-Host "  Subject     : $($cert.Subject)"
        Write-Host "  Thumbprint  : $($cert.Thumbprint)"
        Write-Host ""
        Write-Host "Optional (admin, reduces SmartScreen prompts on this PC):" -ForegroundColor Cyan
        Write-Host "  certutil -addstore TrustedPublisher $($cert.Thumbprint)"
    }
}

$cert = Get-DevCert -Subject $CertSubject
if (-not $cert) {
    Write-Host @"
No dev signing certificate found.

Run once:
  .\scripts\sign-dev-local.ps1 -CreateCert
  .\scripts\sign-dev-local.ps1

Or set OPTICOMBAT_SIGN_THUMBPRINT to your EV cert and use .\scripts\sign-release.ps1
"@
    exit 1
}

$signtool = Get-SignTool
$thumb = $cert.Thumbprint
$names = @('optiCombat.exe', 'optiCombat.Service.exe', 'opticombat.dll', 'optiCombat.AmsiProvider.dll', 'optiCombat.dll', 'optiCombat.Platform.dll')
$dirs = Find-BinDirs
Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -in $names -and $_.FullName -match '\\bin\\(Release|Debug)\\'
    } |
    ForEach-Object {
        $parent = $_.DirectoryName
        if ($dirs -notcontains $parent) { $dirs += $parent }
    }
$dirs = $dirs | Select-Object -Unique

if ($dirs.Count -eq 0) {
    Write-Warning "No Release output found. Build first: dotnet build optiCombat.sln -c Release"
    exit 1
}

$signed = 0
foreach ($dir in $dirs) {
    foreach ($name in $names) {
        $path = Join-Path $dir $name
        if (-not (Test-Path $path)) { continue }
        Write-Host "Signing $path ..." -ForegroundColor Cyan
        & $signtool sign /sha1 $thumb /tr $TimestampUrl /td sha256 /fd sha256 $path
        if ($LASTEXITCODE -ne 0) { throw "signtool failed: $path" }
        $signed++
    }
}

Write-Host ""
Write-Host "Signed $signed file(s) with dev cert ($thumb)." -ForegroundColor Green
Write-Host "Restart optiCombat.exe. If Windows Security still blocks, run as admin:" -ForegroundColor Yellow
Write-Host "  certutil -addstore TrustedPublisher $thumb"
