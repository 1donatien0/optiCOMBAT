<#
  _sign-all.ps1 - Signe TOUS les binaires optiCombat avec le certificat dev.
  Genere par assistant. Usage : via _sign-all.cmd (double-clic Explorateur).
  Journalise dans ..\sign-all.log
#>
[CmdletBinding()]
param(
    [string]$CertSubject  = 'CN=optiCombat Dev, O=Dona By',
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$log = Join-Path $root 'sign-all.log'
"=== optiCOMBAT sign-all $(Get-Date -Format s) ===" | Out-File -FilePath $log -Encoding utf8

function Log([string]$m) { $m | Tee-Object -FilePath $log -Append | Out-Null }

# --- signtool ---
$signtool = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
    Get-Item -ErrorAction SilentlyContinue | Select-Object -Last 1
if (-not $signtool) { Log "ERREUR: signtool.exe introuvable (installer le SDK Windows)."; exit 1 }
Log ("signtool  : " + $signtool.FullName)

# --- certificat dev ---
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $CertSubject } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { Log "ERREUR: certificat dev introuvable ($CertSubject)."; exit 1 }
$thumb = $cert.Thumbprint
Log ("certificat: " + $thumb + "  (" + $CertSubject + ")")

# --- liberer les verrous (app en cours) ---
foreach ($n in 'optiCombat', 'optiCombat.Service', 'clamd') {
    Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 1

# --- fichiers "maison" a signer ---
$names = @(
    'optiCombat.exe', 'optiCombat.Service.exe',
    'opticombat.dll', 'optiCombat.dll', 'optiCombat.Platform.dll',
    'optiCombat.AmsiProvider.dll', 'optiCombat.Minifilter.sys'
)
$searchRoots = @(
    'optiCombat\bin', 'optiCombat.Service\bin', 'optiCombat.Platform\bin',
    'native', 'engine\target', 'artifacts', 'installer\Output', 'installer'
) | ForEach-Object { Join-Path $root $_ } | Where-Object { Test-Path -LiteralPath $_ }

$files = New-Object System.Collections.Generic.List[string]
foreach ($r in $searchRoots) {
    foreach ($n in $names) {
        Get-ChildItem -LiteralPath $r -Recurse -Filter $n -File -ErrorAction SilentlyContinue |
            ForEach-Object { [void]$files.Add($_.FullName) }
    }
    Get-ChildItem -LiteralPath $r -Recurse -Filter '*Setup*.exe' -File -ErrorAction SilentlyContinue |
        ForEach-Object { [void]$files.Add($_.FullName) }
}
$files = $files | Sort-Object -Unique

Log ""
Log ("Fichiers trouves: " + $files.Count)
Log "--- Signature ---"
$signed = 0; $failed = 0
foreach ($f in $files) {
    $out = & $signtool sign /sha1 $thumb /fd sha256 /tr $TimestampUrl /td sha256 $f 2>&1
    if ($LASTEXITCODE -eq 0) { $signed++; Log ("OK    " + $f) }
    else { $failed++; Log ("ECHEC " + $f + "  ::  " + (($out | Select-Object -Last 1))) }
}
Log ""
Log ("Bilan: signes=$signed  echecs=$failed  total=$($files.Count)")

# --- verification ---
Log ""
Log "--- Verification Authenticode ---"
foreach ($f in $files) {
    if (Test-Path -LiteralPath $f) {
        $s = Get-AuthenticodeSignature -LiteralPath $f
        Log ("{0,-12} {1}" -f $s.Status, $f)
    }
}
Log "=== FIN ==="
