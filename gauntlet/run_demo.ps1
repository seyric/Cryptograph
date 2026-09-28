# CANARY TRAP Master Demonstration PowerShell Script
# Executes the full 8-phase SIH26237 demo

$ErrorActionPreference = "Stop"

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "                STARTING CANARY TRAP 8-PHASE LIVE DEMO                  " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

$env:PYTHONPATH = "."
python gauntlet/demo.py

Write-Host "`n[+] Master Demonstration Run Completed." -ForegroundColor Green
Write-Host "[*] You can view the Recipient Viewer at: http://localhost:5001/" -ForegroundColor Yellow
Write-Host "[*] You can view the Audit Console at:    http://localhost:8001/console" -ForegroundColor Yellow
