# Vide le cache d'icones Windows (Explorateur affiche parfois une vieille icone).
# Relancez l'Explorateur apres execution. Admin non requis.

Write-Host "Rafraichissement du cache d'icones Windows..." -ForegroundColor Cyan
$ie4u = Join-Path $env:SystemRoot 'System32\ie4uinit.exe'
if (Test-Path -LiteralPath $ie4u) {
    & $ie4u -ClearIconCache
    Write-Host "  ie4uinit -ClearIconCache OK" -ForegroundColor DarkGray
}

Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Process explorer
Write-Host "Explorateur relance. Rouvrez le dossier de l'installateur." -ForegroundColor Green
