# ZYRON Installation & Setup Guide

## Requirements
- **OS:** Windows 11 (AMD Ryzen / Intel) or Kali Linux (VMware / Bare Metal)
- **RAM:** 8 GB RAM (Optimized; consumes < 150 MB RAM in execution)
- **Python:** Python 3.10, 3.11, or 3.12
- **Network:** Local only (No mandatory cloud accounts or external database servers)

---

## Windows 11 Installation

1. Open PowerShell inside the project root:
   ```powershell
   cd ZYRON-CYBERSECURITY
   ```
2. Run the automated setup script:
   ```powershell
   .\scripts\setup_windows.ps1
   ```
3. Launch the terminal framework:
   ```powershell
   .\scripts\run_windows.ps1
   ```

---

## Kali Linux Installation

1. Open bash terminal inside the project root:
   ```bash
   cd ZYRON-CYBERSECURITY
   chmod +x scripts/setup_kali.sh
   ./scripts/setup_kali.sh
   ```
2. Activate environment and launch:
   ```bash
   source .venv/bin/activate
   python main.py
   ```

---

## Verification
Run the unit test suite to verify all database, scope, validation, reporting, and module operations:
```bash
python -m pytest tests -v
```
All 25 tests should pass with green status.
