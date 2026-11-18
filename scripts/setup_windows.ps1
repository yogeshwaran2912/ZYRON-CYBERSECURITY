# ZYRON Cybersecurity Framework - Windows 11 Setup Script
# Run from PowerShell in project root

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  ZYRON CYBERSECURITY FRAMEWORK - WINDOWS SETUP" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Check Python installation
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[!] Python 3.10+ is required but was not found in PATH." -ForegroundColor Red
    Write-Host "    Please install Python from https://www.python.org/" -ForegroundColor Yellow
    exit 1
}

$pyVer = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Write-Host "[+] Found Python version $pyVer" -ForegroundColor Green

# Create Virtual Environment if not exists
if (-not (Test-Path ".venv")) {
    Write-Host "[*] Creating isolated virtual environment in .venv..." -ForegroundColor Yellow
    python -m venv .venv
}

Write-Host "[*] Activating virtual environment..." -ForegroundColor Yellow
& .\.venv\Scripts\Activate.ps1

Write-Host "[*] Upgrading pip and installing dependencies..." -ForegroundColor Yellow
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

Write-Host "[*] Running automated test suite..." -ForegroundColor Yellow
python -m pytest tests

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  ZYRON SETUP COMPLETE! Run with: .\scripts\run_windows.ps1" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
