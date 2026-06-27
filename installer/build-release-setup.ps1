# Publie optiCombat (Release, win-x64) puis compile l'installateur Inno.
# Usage (depuis la racine du depot) : .\installer\build-release-setup.ps1
# Uniquement Inno (publish deja fait) : .\installer\build-release-setup.ps1 -SkipPublish
# CI : .\installer\build-release-setup.ps1 -SkipPublish -PublishDir publish\win-x64

[CmdletBinding()]
param(
    [switch] $SkipPublish,
    [string] $PublishDir,
    [switch] $AllowMissingSignatures,
    [switch] $SkipVerify
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$csproj = Join-Path $root 'optiCombat\optiCombat.csproj'
$iss = Join-Path $PSScriptRoot 'setup.iss'
$defaultPublishDir = Join-Path $root 'optiCombat\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64'
$publishCandidates = @(
    $defaultPublishDir,
    (Join-Path $root 'publish\win-x64')
)
$cleanScript = Join-Path $root 'scripts\clean-before-publish.ps1'
$verifyScript = Join-Path $root 'scripts\verify-runtime-deps.ps1'

if (-not (Test-Path -LiteralPath $csproj)) { throw "Introuvable : $csproj" }
if (-not (Test-Path -LiteralPath $iss)) { throw "Introuvable : $iss" }

function Resolve-PublishRoot([string] $dir) {
    $p = if ([System.IO.Path]::IsPathRooted($dir)) { $dir } else { Join-Path $root $dir }
    if (-not (Test-Path -LiteralPath $p)) {
        throw "Dossier publish introuvable : $p"
    }
    return (Resolve-Path -LiteralPath $p).Path.TrimEnd('\', '/')
}

$targetPublishDir = if (-not [string]::IsNullOrWhiteSpace($PublishDir)) {
    Resolve-PublishRoot $PublishDir
} else {
    $found = $publishCandidates | Where-Object { Test-Path (Join-Path $_ 'optiCombat.exe') } | Select-Object -First 1
    if ($found) { (Resolve-Path -LiteralPath $found).Path.TrimEnd('\', '/') }
    else { $defaultPublishDir }
}

$publishExe = Join-Path $targetPublishDir 'optiCombat.exe'
$staleFlatPublish = Join-Path (Split-Path $targetPublishDir -Parent) 'optiCombat.exe'

if (-not $SkipPublish) {
    if (-not (Test-Path -LiteralPath $cleanScript)) { throw "Introuvable : $cleanScript" }
    & $cleanScript -Configuration Release -IncludeObj -IncludeCiPublish
    if ($LASTEXITCODE -ne 0) { throw "clean-before-publish a echoue (code $LASTEXITCODE)." }
    Write-Host 'dotnet publish (Release, FolderProfile-SelfContained -> publish\win-x64)...' -ForegroundColor Cyan
    dotnet publish $csproj -c Release /p:PublishProfile=FolderProfile-SelfContained
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish a echoue (code $LASTEXITCODE)." }
    $targetPublishDir = Resolve-PublishRoot $defaultPublishDir
    $publishExe = Join-Path $targetPublishDir 'optiCombat.exe'
} else {
    if ((Test-Path -LiteralPath $staleFlatPublish) -and -not (Test-Path -LiteralPath $publishExe)) {
        throw @"
Publication win-x64 absente mais ancien publish\optiCombat.exe detecte ($staleFlatPublish).
Relancez d'abord :
  .\scripts\clean-before-publish.ps1 -IncludeObj -IncludeCiPublish
  dotnet publish $csproj -c Release /p:PublishProfile=FolderProfile-SelfContained
"@
    }
}

if (-not (Test-Path -LiteralPath $publishExe)) {
    throw "Publication introuvable : $publishExe (faites dotnet publish avant Inno)."
}

$srcClamScan = Join-Path $root 'optiCombat\clamav\x64\clamscan.exe'
if (-not (Test-Path -LiteralPath $srcClamScan)) {
    $fetchScript = Join-Path $root 'scripts\fetch-runtime-deps.ps1'
    if (Test-Path -LiteralPath $fetchScript) {
        Write-Host 'Dependances ClamAV/YARA absentes — fetch-runtime-deps...' -ForegroundColor Cyan
        & $fetchScript
        if ($LASTEXITCODE -ne 0) { throw "fetch-runtime-deps a echoue (code $LASTEXITCODE)." }
    }
}

if (-not $SkipVerify -and (Test-Path -LiteralPath $verifyScript)) {
    Write-Host 'verify-runtime-deps...' -ForegroundColor Cyan
    $verifyArgs = @{ PublishDir = $targetPublishDir }
    if ($AllowMissingSignatures) { $verifyArgs['AllowMissingSignatures'] = $true }
    & $verifyScript @verifyArgs
    if ($LASTEXITCODE -ne 0) { throw "verify-runtime-deps a echoue (code $LASTEXITCODE)." }
}

$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $iscc) { throw 'ISCC.exe introuvable. Installez Inno Setup 6.' }

$outDir = Join-Path $PSScriptRoot 'output'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$propsPath = Join-Path $root 'Directory.Build.props'
[xml]$propsXml = Get-Content -LiteralPath $propsPath
$appVersion = ($propsXml.Project.PropertyGroup.Version | Select-Object -First 1).'#text'
if ([string]::IsNullOrWhiteSpace($appVersion)) { $appVersion = '1.0.0' }
$parts = $appVersion.Split('.')
$appRelease = if ($parts.Length -ge 2) { "v$($parts[0]).$($parts[1])" } else { "v$appVersion" }

Write-Host "Inno Setup : $iscc (AppVersion=$appVersion, AppRelease=$appRelease)" -ForegroundColor Cyan
$installerDir = $PSScriptRoot
$publishUri = (Resolve-Path -LiteralPath $targetPublishDir).Path
$installerUri = (Resolve-Path -LiteralPath $installerDir).Path
$relative = [System.Uri]::UnescapeDataString(
    (New-Object System.Uri($installerUri + '\')).MakeRelativeUri((New-Object System.Uri($publishUri + '\'))).ToString()
).Replace('/', '\')
$publishGlob = $relative.TrimEnd('\') + '\*'
$isccArgs = @(
    "/DAppVersion=$appVersion",
    "/DAppRelease=$appRelease",
    "/DAppPublishSource=$publishGlob"
)
Write-Host "Publish source (force) : $publishGlob" -ForegroundColor DarkGray
Write-Host "  optiCombat.exe : $((Get-Item -LiteralPath $publishExe).LastWriteTime.ToString('u'))" -ForegroundColor DarkGray
& $iscc @isccArgs $iss
if ($LASTEXITCODE -ne 0) { throw "ISCC a echoue (code $LASTEXITCODE)." }

if (Test-Path $outDir) {
    Write-Host 'Sortie :' -ForegroundColor Green
    Get-ChildItem $outDir -Filter '*.exe' | Sort-Object LastWriteTime -Descending | Select-Object -First 3 | Format-Table Name, Length, LastWriteTime -AutoSize
}
