# ZYRON Framework Architecture

## 1. Architectural Style: Modular Monolith

ZYRON uses a Modular Monolithic pattern. All four domains (`bug_bounty`, `red_team`, `penetration_testing`, `automation`) are distinct modules with high cohesion and loose coupling. They interact through the `core` layer rather than calling each other's private internals directly.

```
+-----------------------------------------------------------------------------------+
|                              ZYRON TERMINAL CLI (main.py)                        |
+-----------------------------------------------------------------------------------+
        |                          |                        |                  |
        v                          v                        v                  v
+-----------------+      +-----------------+      +-------------------+   +------------+
| Bug Bounty      |      | Red Team        |      | Penetration Test  |   | Automation |
| Research        |      | Operations      |      | Engineering       |   | Hub        |
+-----------------+      +-----------------+      +-------------------+   +------------+
        \                          |                        |                  /
         \                         |                        |                 /
          +------------------------+------------------------+----------------+
                                   |
                                   v
             +---------------------------------------------+
             |             CORE SERVICES LAYER             |
             +---------------------------------------------+
             | - DatabaseManager (SQLite normalized DDL)   |
             | - ScopeManager (Default-DENY Enforcement)   |
             | - Input Validators (IP, CIDR, Domain, Port) |
             | - EvidenceManager (SHA-256 Hashing)         |
             | - ReportEngine (Markdown, HTML, JSON)       |
             | - SecurityManager (Dry-Run Controller)      |
             | - Logging & Audit Trails                    |
             +---------------------------------------------+
```

## 2. Central Database Model

SQLite is used with WAL (Write-Ahead Logging) and enforced foreign keys. The 11 relational tables are:
1. `users_or_operators`: System users and authorized operators.
2. `projects`: High-level operational workspaces categorized by domain.
3. `programs`: Bug bounty program metadata, organization, rules.
4. `engagements`: Red team & pentest formal authorizations and testing windows.
5. `scopes`: Authorized target rules (IPs, CIDRs, domains, URLs) and explicit exclusions.
6. `assets`: Discovered domains, subdomains, IPs, listening ports, and web applications.
7. `findings`: Documented vulnerabilities with severity ratings, CVSS scores, and validation status.
8. `evidence`: Forensic artifacts, raw HTTP logs, screenshots, and SHA-256 fingerprints.
9. `tasks`: Predefined Python automation routines, attack steps, and detection checks.
10. `audit_logs`: Immutable security audit logs recording every action, actor, target, and outcome.
11. `reports`: Compiled reports cataloged with output paths and executive summaries.

## 3. Scope Enforcement

Every network action queries `ScopeManager.verify_scope_or_raise(project_id, target)`:
- Rule 1: Checks for explicit EXCLUSION entries. If matched, access is blocked immediately.
- Rule 2: Checks for authorized INCLUSIONS (exact domain/subdomain, IP, or CIDR network range).
- Rule 3: If no rule matches, default policy **DENY** blocks the operation.
