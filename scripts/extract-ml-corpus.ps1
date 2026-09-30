# Extract ML feature vectors from PE samples into corpus/labeled.jsonl
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SamplesDir,
    [Parameter(Mandatory = $true)]
    [ValidateSet("Benign", "Ransomware", "Rat", "Dropper")]
    [string]$Class,
    [string]$Output = (Join-Path $PSScriptRoot "..\engine\crates\ml-train\corpus\labeled.jsonl"),
    [switch]$Append
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path $SamplesDir)) { throw "SamplesDir not found: $SamplesDir" }

cargo build --manifest-path engine\Cargo.toml -p ml-train --release
if ($LASTEXITCODE -ne 0) { throw "ml-train build failed" }

$mlTrain = Join-Path $root "engine\target\release\ml-train.exe"
$lines = @()

# Batch extract via --extract-dir when the folder has only PE files at top level.
$fileCount = (Get-ChildItem -Path $SamplesDir -File -Recurse | Measure-Object).Count
if ($fileCount -gt 0) {
    $batchOut = Join-Path $env:TEMP ("ml-corpus-{0}.jsonl" -f [Guid]::NewGuid().ToString("N"))
    & $mlTrain --extract-dir $SamplesDir $Class *> $batchOut
    if ($LASTEXITCODE -eq 0 -and (Test-Path $batchOut)) {
        $lines = Get-Content $batchOut | Where-Object { $_.Trim().Length -gt 0 }
        Remove-Item $batchOut -Force -ErrorAction SilentlyContinue
    }
}

if ($lines.Count -eq 0) {
    Get-ChildItem -Path $SamplesDir -File -Recurse | ForEach-Object {
        $line = & $mlTrain --extract $_.FullName $Class 2>$null
        if ($LASTEXITCODE -eq 0 -and $line) {
            $lines += $line
            Write-Host ("Extracted: " + $_.Name) -ForegroundColor DarkGray
        }
    }
}

if ($lines.Count -eq 0) {
    Write-Warning "No features extracted."
    exit 1
}

if ($Append) {
    Add-Content -Path $Output -Value ($lines -join [Environment]::NewLine)
} else {
    Set-Content -Path $Output -Value ($lines -join [Environment]::NewLine)
}
Write-Host ("Wrote {0} samples to {1}" -f $lines.Count, $Output) -ForegroundColor Green
