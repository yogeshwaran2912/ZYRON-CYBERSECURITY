# ZYRON – Cybersecurity Research & Automation Framework

```
  ███████╗██╗   ██╗██████╗  ██████╗ ███╗   ██╗
  ╚══███╔╝╚██╗ ██╔╝██╔══██╗██╔═══██╗████╗  ██║
    ███╔╝  ╚████╔╝ ██████╔╝██║   ██║██╔██╗ ██║
   ███╔╝    ╚██╔╝  ██╔══██╗██║   ██║██║╚██╗██║
  ███████╗   ██║   ██║  ██║╚██████╔╝██║ ╚████║
  ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
```

**Version:** 0.1.0  
**Status:** Milestone 1 Foundation Complete  
**Platform Compatibility:** Windows 11 & Kali Linux (AMD Ryzen 3 7320U / 8 GB RAM Optimized)  

---

## 1. Overview

**ZYRON** is a modular, lightweight Python cybersecurity research and automation framework engineered to support four major security domains:

1. **Bug Bounty Research:** Program tracking, target scope verification, asset inventory, DNS resolution, HTTP security header analysis, vulnerability verification tracking, and disclosure reporting.
2. **Red Team Operations:** Engagement authorizations, Active Directory lab assessment, Cyber Kill Chain attack-path tracking, MITRE ATT&CK detection testing, and operator activity logging.
3. **Penetration Testing:** Network host inventory, port and daemon service tracking, web assessment surface documentation, CVSS v3 vulnerability management, and remediation retesting.
4. **Cybersecurity Automation:** Safe reviewed Python task execution, result parsing (JSON/CSV), duplicate finding suppression, lightweight non-daemon job scheduling, and multi-step security workflows.

---

## 2. Core Architectural Pillars

- **Modular Monolith:** 4 independent domain modules backed by shared foundational core services (`database`, `scope_manager`, `validators`, `evidence_manager`, `report_engine`, `security_manager`, `logger`).
- **Default Policy DENY:** Mandatory scope manager blocks any target asset not explicitly authorized in the engagement scope before network operations can execute.
- **Dry-Run by Default:** Protects production environments from accidental active actions.
- **Evidence Integrity:** SHA-256 cryptographic hashing of all evidence files to ensure tamper-proof forensic validity.
- **Zero Heavyweight Daemons:** Optimized for 8 GB RAM systems without requiring Docker, background daemon services, or cloud infrastructure.
- **SQLite Normalized Schema:** 11 normalized relational tables with enforced foreign keys, WAL mode, and parameterized queries.

---

## 3. Quick Start

### Windows 11
```powershell
cd ZYRON-CYBERSECURITY
.\scripts\setup_windows.ps1
.\scripts\run_windows.ps1
```

### Kali Linux
```bash
cd ZYRON-CYBERSECURITY
chmod +x scripts/setup_kali.sh
./scripts/setup_kali.sh
source .venv/bin/activate
python main.py
```

### Running Automated Tests
```bash
python -m pytest tests -v
```

---

## 4. Directory Structure

```
ZYRON-CYBERSECURITY/
├── main.py                  # Main terminal interface & domain router
├── requirements.txt         # Core dependencies
├── pyproject.toml           # Package configuration & pytest settings
├── README.md                # Framework overview
├── .gitignore               # Excludes secrets, evidence, db, and caches
├── .env.example             # Template for local environment variables
├── config/
│   ├── settings.yaml        # Application configuration & security policies
│   └── logging.yaml         # Logging & audit trail configuration
├── core/
│   ├── database.py          # SQLite layer with 11 normalized tables
│   ├── scope_manager.py     # Central Default-DENY scope authorization engine
│   ├── validators.py        # IPs, CIDRs, domains, URLs, ports, severities
│   ├── logger.py            # Application and security audit logging
│   ├── evidence_manager.py  # SHA-256 cryptographic evidence tracking
│   ├── report_engine.py     # Markdown, HTML, and JSON report generator
│   ├── security_manager.py  # Dry-run and authorization controls
│   └── exceptions.py        # Custom structured exceptions
├── modules/
│   ├── bug_bounty/          # Program & recon domain
│   ├── red_team/            # Engagement, AD lab & ATT&CK domain
│   ├── penetration_testing/ # Network, service & web pentest domain
│   └── automation/          # Task runner, scheduler & workflows
├── database/                # Local SQLite storage (gitignored)
├── evidence/                # Local evidence storage (gitignored)
├── reports/                 # Compiled reports (gitignored)
├── documentation/           # Technical guides & AI context export
├── tests/                   # 25 automated pytest tests
├── scripts/                 # Setup and run scripts for Windows & Kali
└── .github/workflows/       # GitHub Actions CI matrix workflow
```

---

## 5. Security & Legal Disclaimer

ZYRON is designed strictly for **authorized educational research, lab simulation, defensive testing, and legal security assessments**. Users must obtain explicit written authorization before conducting active tests on any target network or application.
