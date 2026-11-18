# ZYRON Cybersecurity Framework - Windows 11 Run Script
# Executes the framework in local terminal

$ErrorActionPreference = "Stop"

# Use venv python if available, otherwise fallback to system python
if (Test-Path ".venv\Scripts\python.exe") {
    & .\.venv\Scripts\python.exe main.py
} elseif (Test-Path "..\.venv\Scripts\python.exe") {
    & ..\.venv\Scripts\python.exe main.py
} else {
    python main.py
}
