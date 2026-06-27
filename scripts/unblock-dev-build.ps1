<#
.SYNOPSIS
    Retire le marqueur Zone.Identifier (MOTW) des binaires bin/obj — évite les blocages Defender / Smart App Control en dev.
#>
[CmdletBinding()]
param(
    [string] $Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'SilentlyContinue'
$count = 0
foreach ($dirName in @('bin', 'obj')) {
    Get-ChildItem -Path $Root -Recurse -Directory -Filter $dirName | ForEach-Object {
        Get-ChildItem -LiteralPath $_.FullName -Recurse -File -Include *.dll, *.exe | ForEach-Object {
            Unblock-File -LiteralPath $_.FullName -ErrorAction SilentlyContinue
            $count++
        }
    }
}
Write-Host "Unblock dev build : $count fichier(s) traites sous $Root"
