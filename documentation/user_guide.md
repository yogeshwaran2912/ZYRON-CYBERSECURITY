# ZYRON User Guide

## 1. Navigating the Terminal Interface
Upon launching `python main.py`, the main menu displays the 10 available domains and services:

```text
  [1]  Bug Bounty Research
  [2]  Red Team Operations
  [3]  Penetration Testing
  [4]  Security Automation
  [5]  Project Management
  [6]  Vulnerability Findings (Global)
  [7]  Evidence Management (Integrity Hashes)
  [8]  Reports & Documentation
  [9]  System Information
  [10] Settings
  [0]  Exit
```

Enter the numeric option and press Enter.

---

## 2. Typical Workflows

### A. Bug Bounty Target Setup & Recon
1. Go to `[1] Bug Bounty Research` -> `[1] View & Add Target Scope`.
2. Register an authorized domain (e.g. `example.com`).
3. Optionally add an excluded subdomain (e.g. `out-of-scope.example.com` with `is_excluded = True`).
4. Run `[3] Scope-Enforced DNS Reconnaissance` to resolve IPs. Discovered assets are automatically added to the inventory.
5. Run `[4] Run HTTP Security Header Analysis` to check for missing HSTS, CSP, and X-Frame-Options.
6. Record suspected or validated vulnerabilities in `[5] Record New Vulnerability Finding`.

### B. Red Team Lab Simulation
1. Go to `[2] Red Team Operations` -> `[1] Engagement Management` to create ROE and approval records.
2. Register lab Domain Controllers in `[2] Active Directory Security Lab Inventory`.
3. Document simulated kill chain steps in `[3] Attack Path Documentation`.
4. Log SIEM and EDR detection test results in `[4] Detection & Telemetry Testing`.

### C. Penetration Testing Assessment
1. Go to `[3] Penetration Testing` -> `[1] Pre-Engagement & Scope Verification`.
2. Register target subnets (e.g. `10.0.0.0/24`) and hosts.
3. Track open ports and service versions in `[3] Service & Port Inventory`.
4. Record findings with CVSS scores and retest notes in `[5]` and `[6]`.
5. Generate an executive report in HTML or Markdown using `[7]`.

### D. Automation Hub
1. Go to `[4] Security Automation` -> `[1] Predefined Task Runner`.
2. Execute the database optimization routine or system health check.
3. Run `[2] Workflow: Evidence Cryptographic Integrity Verification` to ensure no evidence files have been altered.
