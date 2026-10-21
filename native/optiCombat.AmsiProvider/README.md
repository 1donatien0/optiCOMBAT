# optiCOMBAT AMSI Provider

Provider AMSI natif (C++, build `scripts/build-amsi.ps1`, staging `scripts/stage-amsi.ps1`) qui délègue l’analyse
de contenu scripté à `optiCombat.exe --service-host` via le pipe `\\.\pipe\optiCombat_Protection`
(débit plafonné par `IpcScanRateLimiter`).

**Inactif en v1.0** : la couche plateforme n’est pas activable (`PlatformProtectionFeatureGate.IsUserActivatable = false`).
