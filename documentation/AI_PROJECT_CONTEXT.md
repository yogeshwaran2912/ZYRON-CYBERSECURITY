# AI Collaboration Context – ZYRON Framework

> **Instructions for ChatGPT / Claude:**  
> This file contains the complete system architecture, operational constraints, and coding standards for the ZYRON Cybersecurity Research & Automation Framework. Use this context when answering questions, reviewing code, or proposing new features.

---

## 1. Project Identity
- **Project Name:** ZYRON – Cybersecurity Research & Automation Framework
- **Current Version:** 0.1.0
- **Primary Audience:** Cybersecurity student, ethical hacker, penetration tester, and security automation engineer.
- **Hardware Profile:** AMD Ryzen 3 7320U, 8 GB RAM, Windows 11 host with Kali Linux running in VMware.
- **Design Constraint:** Lightweight, modular monolithic architecture. No mandatory Docker, heavy background daemons, or paid cloud APIs.

---

## 2. Architectural Structure
```
ZYRON-CYBERSECURITY/
├── main.py                  # Terminal interactive menu & entry point
├── config/                  # settings.yaml and logging.yaml
├── core/
│   ├── database.py          # SQLite layer (11 normalized tables, WAL, foreign keys)
│   ├── scope_manager.py     # Default-DENY authorization engine
│   ├── validators.py        # Strict input validation (IP, CIDR, domain, URL, port)
│   ├── logger.py            # Application & security audit logging
│   ├── evidence_manager.py  # SHA-256 evidence hashing & local storage
│   ├── report_engine.py     # Markdown, HTML, JSON report generation
│   ├── security_manager.py  # Dry-run toggles & active test confirmation
│   └── exceptions.py        # Structured error hierarchy
├── modules/
│   ├── bug_bounty/          # Program & recon domain
│   ├── red_team/            # Engagements, AD lab, ATT&CK detection domain
│   ├── penetration_testing/ # Network, service & web pentest domain
│   └── automation/          # Task runner, result parsers, workflows
├── database/                # zyron.db (gitignored)
├── evidence/                # Local evidence storage (gitignored)
├── reports/                 # Output reports (gitignored)
├── tests/                   # Pytest test suite (25 tests passing)
└── scripts/                 # Windows & Kali execution scripts
```

---

## 3. Mandatory Security & Coding Guidelines
1. **Scope Verification:** Every network operation must verify target authorization through `ScopeManager.verify_scope_or_raise()`.
2. **Default Policy DENY:** If an asset is not explicitly registered in the project's authorized scope, reject it immediately.
3. **No Weaponized Code:** Do not generate real malware, worms, ransomware, credential wipers, or unauthorized exploitation scripts.
4. **Parameterized SQL:** Never concatenate user input into SQL queries. Always use SQLite parameterized queries (`?`).
5. **Standard Library Preference:** Minimize external dependencies. Keep the framework fast and lightweight for 8 GB RAM machines.
6. **Cross-Platform:** Always use `pathlib.Path` for filesystem operations. Do not use hardcoded Windows backslashes.
