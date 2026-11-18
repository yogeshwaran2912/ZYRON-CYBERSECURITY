# Module 02: Red Team Operations & Lab Simulation

## Purpose
Manages authorized lab simulations, Active Directory security analysis, MITRE ATT&CK technique mapping, and defensive detection testing.

## Operational Boundaries & Ethics
ZYRON Red Team module is strictly for **controlled lab simulation and authorized security validation**:
- No automated credential harvesting.
- No autonomous lateral movement.
- No destructive payloads or ransomware mechanisms.
- All operations require explicit engagement authorization codes.

## Features

### 1. Engagement Management
- Tracks engagement code, client organization, start/end windows, and rules of engagement.

### 2. Active Directory Security Lab
- Documents Domain Controllers, forests, and domains.
- Catalogs security misconfigurations (Kerberoasting, AS-REP roasting, Unconstrained Delegation).
- Supports parsing BloodHound / SharpHound export JSON metadata.

### 3. Cyber Kill Chain Attack Paths
- Methodological tracking:
  1. Reconnaissance
  2. Enumeration
  3. Initial Access Assessment
  4. Privilege Escalation Assessment
  5. Lateral Movement Assessment
  6. Persistence Assessment
  7. Detection Validation
  8. Reporting

### 4. Detection & Telemetry Testing
- Compares expected telemetry (e.g. Sysmon Event 1, Security Log 4624) against actual defensive outcomes (`detected`, `alerted`, `blocked`, `missed`).
- Recommends actionable defensive detection engineering rules.

### 5. Operator Activity Logger
- Real-time logging of operator, action, source, destination, tool, and timestamp for deconfliction with blue teams.
