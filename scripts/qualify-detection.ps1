# Qualification detection panel — optiCombat
# Builds oc-qualify, generates safe fixtures, runs manifest, enforces thresholds.
[CmdletBinding()]
param(
    [string]$Manifest = (Join-Path $PSScriptRoot "..\qualification\manifest.json"),
    [string]$ReportDir = (Join-Path $PSScriptRoot "..\qualification\reports"),
    [double]$MinMaliciousRate = 1.0,
    [double]$MaxFprRate = 0.0
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$genDir = Join-Path $root "qualification\generated"
New-Item -ItemType Directory -Force -Path $genDir, $ReportDir | Out-Null

# EICAR (standard test file — safe in isolation)
$eicarPath = Join-Path $genDir "eicar.com"
$eicarPayload = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path $eicarPath -Value $eicarPayload -NoNewline -Encoding ascii

# Synthetic behavioral profile (API strings only — not executable malware)
$behaviorPath = Join-Path $genDir "behavior-dropper.ps1"
@'
# Synthetic qualification fixture — behavioral indicators only (no real payload).
# Simulates download -> write -> persist -> execute chain for sandbox scoring.
$noise = "benign padding"
URLDownloadToFile
WinHttp
WriteFile
RegCreateKey
Software\Microsoft\Windows\CurrentVersion\Run
ShellExecute
cmd.exe
CreateService
powershell
winmgmts:
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
'@ | Set-Content -Path $behaviorPath -Encoding ascii

Write-Host "Building oc-qualify..." -ForegroundColor Cyan
cargo build --manifest-path engine\Cargo.toml -p qualify --release
if ($LASTEXITCODE -ne 0) { throw "Rust build failed" }

$qualify = Join-Path $root "engine\target\release\oc-qualify.exe"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$report = Join-Path $ReportDir "qualify-$stamp.json"

Write-Host "Running qualification panel (detection >= $MinMaliciousRate, FPR <= $MaxFprRate)..." -ForegroundColor Cyan
& $qualify --manifest $Manifest --report $report `
    --min-malicious-rate $MinMaliciousRate `
    --max-fpr-rate $MaxFprRate
$code = $LASTEXITCODE

Write-Host "Report: $report" -ForegroundColor Green
if ($code -ne 0) {
    Write-Host "Qualification FAILED (exit $code)" -ForegroundColor Red
    exit $code
}
Write-Host "Qualification PASSED" -ForegroundColor Green
