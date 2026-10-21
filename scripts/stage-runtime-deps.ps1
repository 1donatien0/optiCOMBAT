<#
.SYNOPSIS
    Copie clamav / yara / rules / certificats du projet vers un dossier de publication.

.PARAMETER PublishDir
    Cible (ex. publish\win-x64 ou bin\...\publish\win-x64).

.PARAMETER SourceRoot
    Racine optiCombat (défaut : optiCombat\ sous le dépôt).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PublishDir,
    [string] $SourceRoot
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = if ($SourceRoot) { $SourceRoot } else { Join-Path $repo 'optiCombat' }
$pub = (Resolve-Path -LiteralPath $PublishDir).Path

function Copy-Tree([string] $rel) {
    $from = Join-Path $src $rel
    if (-not (Test-Path $from)) {
        Write-Warning "Source absente : $from"
        return
    }
    $to = Join-Path $pub $rel
    New-Item -ItemType Directory -Force -Path (Split-Path $to -Parent) | Out-Null
    Copy-Item -LiteralPath $from -Destination $to -Recurse -Force
    Write-Host "  Copie $rel" -ForegroundColor DarkGray
}

Write-Host "stage-runtime-deps -> $pub" -ForegroundColor Cyan
Copy-Tree 'clamav\x64'
Copy-Tree 'clamav\x86'
Copy-Tree 'clamav\database'
Copy-Tree 'clamav\certs'
# freshclam / libclamav sur Windows attend aussi des certs a cote des binaires x64
$srcX64Certs = Join-Path $src 'clamav\x64\certs'
$pubX64Certs = Join-Path $pub 'clamav\x64\certs'
if (Test-Path -LiteralPath $srcX64Certs) {
    New-Item -ItemType Directory -Force -Path $pubX64Certs | Out-Null
    Copy-Item -LiteralPath (Join-Path $srcX64Certs '*') -Destination $pubX64Certs -Recurse -Force
    Write-Host "  Copie clamav\x64\certs" -ForegroundColor DarkGray
}
Copy-Tree 'yara'
Copy-Tree 'rules'
