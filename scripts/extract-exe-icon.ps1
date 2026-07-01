param([Parameter(Mandatory)][string] $ExePath, [string] $OutPng)
Add-Type -AssemblyName System.Drawing
$icon = [System.Drawing.Icon]::ExtractAssociatedIcon($ExePath)
$bmp = $icon.ToBitmap()
if (-not $OutPng) { $OutPng = [IO.Path]::ChangeExtension($ExePath, '.icon.png') }
$bmp.Save($OutPng, [System.Drawing.Imaging.ImageFormat]::Png)
Write-Host "Icon ${bmp.Width}x${bmp.Height} -> $OutPng"
