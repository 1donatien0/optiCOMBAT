<#
.SYNOPSIS
  Test de fumée UI : lance optiCombat.exe et mesure le délai avant l'apparition du contenu de l'accueil
  (UI Automation). Sert à détecter un écran blanc / démarrage anormalement long.
#>
param([Parameter(Mandatory)][string]$Exe, [int]$TimeoutSeconds = 120)

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$ae = [System.Windows.Automation.AutomationElement]
$TS = [System.Windows.Automation.TreeScope]
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process $Exe -PassThru
$win = $null
while (-not $win -and $sw.Elapsed.TotalSeconds -lt 60) {
    Start-Sleep -Milliseconds 300
    $win = $ae::RootElement.FindFirst($TS::Children,
        (New-Object System.Windows.Automation.PropertyCondition($ae::ProcessIdProperty, $p.Id)))
}
"window after {0:N1}s" -f $sw.Elapsed.TotalSeconds
$found = $false
$all = @()
while (-not $found -and $sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
    Start-Sleep -Milliseconds 500
    $all = $win.FindAll($TS::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    foreach ($e in $all) {
        if ($e.Current.Name -like "*Mise à jour*" -or $e.Current.Name -like "*Update*") {
            $found = $true
            "home content '$($e.Current.Name)' after {0:N1}s" -f $sw.Elapsed.TotalSeconds
            break
        }
    }
}
if (-not $found) { "home content never appeared (elements=$($all.Count))" }
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
