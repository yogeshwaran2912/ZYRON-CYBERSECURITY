#!/usr/bin/env bash
# ZYRON Cybersecurity Framework - Kali Linux Setup Script
# Run from bash in project root

set -e

echo -e "\033[1;36m==========================================================\033[0m"
echo -e "\033[1;36m  ZYRON CYBERSECURITY FRAMEWORK - KALI LINUX SETUP\033[0m"
echo -e "\033[1;36m==========================================================\033[0m"

# Ensure Python 3 and venv are installed
if ! command -v python3 &> /dev/null; then
    echo -e "\033[1;31m[!] python3 could not be found. Please run: sudo apt install python3 python3-venv python3-pip\033[0m"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "\033[1;32m[+] Found Python version $PY_VER\033[0m"

# Avoid installing globally into Kali's system Python (PEP 668 compliance)
if [ ! -d ".venv" ]; then
    echo -e "\033[1;33m[*] Creating isolated virtual environment in .venv...\033[0m"
    python3 -m venv .venv
fi

echo -e "\033[1;33m[*] Activating virtual environment...\033[0m"
source .venv/bin/activate

echo -e "\033[1;33m[*] Installing dependencies in isolated venv...\033[0m"
pip install --upgrade pip
pip install -r requirements.txt

echo -e "\033[1;33m[*] Executing test suite...\033[0m"
python -m pytest tests

echo -e "\033[1;32m==========================================================\033[0m"
echo -e "\033[1;32m  ZYRON KALI SETUP COMPLETE!\033[0m"
echo -e "\033[1;32m  Run: source .venv/bin/activate && python main.py\033[0m"
echo -e "\033[1;32m==========================================================\033[0m"
