@echo off
REM Signe TOUS les binaires optiCombat avec le certificat dev (voir _sign-all.ps1)
cd /d "%~dp0.."
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\_sign-all.ps1"
