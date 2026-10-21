<#
.SYNOPSIS
    Vérifie que les thèmes WinUI (Combat.Light / Combat.Dark / Combat.HighContrast) déclarent
    exactement le même jeu de clés, avec le même type d'élément, et que les brosses de thème
    ne sont jamais référencées en {StaticResource} dans les vues.

.DESCRIPTION
    Une clé absente d'un thème retombe silencieusement sur la valeur d'un autre thème
    (ex. une couleur claire en mode contraste renforcé). Une brosse de thème référencée en
    StaticResource ne suit pas les changements de thème. Code de sortie 1 en cas d'écart.

.EXAMPLE
    pwsh -File scripts/check-winui-theme-keys.ps1
#>
[CmdletBinding()]
param(
    [string] $WinUiDir = (Join-Path $PSScriptRoot '..\optiCombat.WinUI')
)

$ErrorActionPreference = 'Stop'
$themesDir = Join-Path $WinUiDir 'Themes'
$files = @('Combat.Light.xaml', 'Combat.Dark.xaml', 'Combat.HighContrast.xaml')
$xNs = 'http://schemas.microsoft.com/winfx/2006/xaml'

$maps = @{}
foreach ($f in $files) {
    $path = Join-Path $themesDir $f
    if (-not (Test-Path -LiteralPath $path)) { throw "Thème introuvable : $path" }
    [xml]$doc = Get-Content -LiteralPath $path -Raw -Encoding UTF8
    $map = @{}
    foreach ($node in $doc.DocumentElement.ChildNodes) {
        if ($node.NodeType -ne 'Element') { continue }
        $key = $node.GetAttribute('Key', $xNs)
        if ($key) { $map[$key] = $node.LocalName }
    }
    $maps[$f] = $map
}

$failed = $false
$reference = $maps[$files[0]]
foreach ($f in $files[1..($files.Count - 1)]) {
    $other = $maps[$f]
    foreach ($k in $reference.Keys) {
        if (-not $other.ContainsKey($k)) { Write-Host "MANQUANT  $f : $k" -ForegroundColor Red; $failed = $true }
        elseif ($other[$k] -ne $reference[$k]) { Write-Host "TYPE      $f : $k ($($other[$k]) au lieu de $($reference[$k]))" -ForegroundColor Red; $failed = $true }
    }
    foreach ($k in $other.Keys) {
        if (-not $reference.ContainsKey($k)) { Write-Host "EN TROP   $f : $k (absent de $($files[0]))" -ForegroundColor Red; $failed = $true }
    }
}

$themeKeys = @($reference.Keys)
Get-ChildItem -LiteralPath $WinUiDir -Recurse -Filter *.xaml |
    Where-Object { $_.FullName -notmatch '\\(bin|obj|Themes)\\' } |
    ForEach-Object {
        $content = Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8
        foreach ($k in $themeKeys) {
            if ($content -match "\{StaticResource\s+$([regex]::Escape($k))\}") {
                Write-Host "STATIC    $($_.Name) : {StaticResource $k} -> utiliser {ThemeResource $k}" -ForegroundColor Red
                $failed = $true
            }
        }
    }

if ($failed) {
    Write-Host "`nThèmes WinUI incohérents." -ForegroundColor Red
    exit 1
}

Write-Host ("Thèmes WinUI cohérents : {0} clés x {1} thèmes." -f $reference.Count, $files.Count) -ForegroundColor Green
exit 0
