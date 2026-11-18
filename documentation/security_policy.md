# ZYRON Security Policy & Ethics Standard

## 1. Ethical Hacking Mandate
ZYRON is designed solely for **authorized security testing, defense validation, academic cybersecurity research, and ethical red-team lab simulations**.

### Explicit Prohibitions:
1. **No Real-World Unauthorized Target Scanning:** Testing targets without written authorization is illegal and violates the ZYRON code of ethics.
2. **No Autonomous Compromise or Weaponization:** ZYRON will never contain autonomous malware, ransomware, credential wipers, or destructive exploit payloads.
3. **No Uncontrolled Lateral Movement:** All lateral movement assessments must be conducted inside isolated, pre-authorized lab virtual machines.

---

## 2. Default Policy DENY
All network operations enforce strict authorization checks:
- Targets must be explicitly registered under an authorized project scope rule.
- If a target is outside the approved scope, or matches an explicit exclusion rule, execution is blocked immediately and logged in `audit_logs`.

---

## 3. Data Confidentiality & Storage
- Local assessment records and SQLite database files (`database/zyron.db`) must **never** be committed to public GitHub repositories.
- Evidence files (`evidence/*`) and generated security reports (`reports/*`) are excluded via `.gitignore`.
- Evidence integrity is verified via SHA-256 cryptographic fingerprints.
