"""
ZYRON - Red Team Operations Module Entry Point
Terminal workflow for engagements, AD security labs, attack path planning, and detection tests.
"""

from __future__ import annotations

from core.database import DatabaseManager, get_db
from core.logger import get_logger
from core.report_engine import ReportEngine
from core.scope_manager import ScopeManager
from modules.red_team.activity_logger import ActivityLogger
from modules.red_team.ad_inventory import ActiveDirectoryInventory
from modules.red_team.attack_path_documentation import AttackPathTracker
from modules.red_team.detection_tests import DetectionTester
from modules.red_team.engagement import EngagementManager

logger = get_logger("red_team.cli")


class RedTeamModule:
    """Main controller for the Red Team Operations domain in ZYRON."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()
        self.scope_manager = ScopeManager(self.db)
        self.engagement_mgr = EngagementManager(self.db)
        self.ad_inventory = ActiveDirectoryInventory(self.db)
        self.attack_tracker = AttackPathTracker(self.db)
        self.detection_tester = DetectionTester(self.db)
        self.activity_logger = ActivityLogger(self.db)
        self.report_engine = ReportEngine(self.db)

    def get_or_create_default_project(self) -> int:
        """Fetch or initialize the baseline Red Team project ID."""
        projects = self.db.get_projects(module_type="red_team")
        if projects:
            return projects[0]["id"]
        return self.db.create_project(
            name="Authorized Red Team Lab",
            module_type="red_team",
            description="Controlled lab engagement workspace"
        )

    def run_menu(self) -> None:
        """Display the Red Team Operations interactive menu."""
        project_id = self.get_or_create_default_project()

        while True:
            print("\n" + "=" * 65)
            print("  ZYRON :: RED TEAM OPERATIONS WORKSPACE")
            print(f"  Active Project ID: #{project_id}")
            print("=" * 65)
            print("  [1] Engagement Management (ROE, Dates, Approvals)")
            print("  [2] Active Directory Security Lab Inventory")
            print("  [3] Attack Path Documentation (Cyber Kill Chain)")
            print("  [4] Detection & Telemetry Testing (MITRE ATT&CK)")
            print("  [5] Operator Activity Logger (Deconfliction)")
            print("  [6] Generate Red Team Engagement Report")
            print("  [0] Return to Main Menu")
            print("-" * 65)

            choice = input("Select an option [0-6]: ").strip()

            if choice == "0":
                break
            elif choice == "1":
                self._handle_engagements(project_id)
            elif choice == "2":
                self._handle_ad_inventory(project_id)
            elif choice == "3":
                self._handle_attack_paths(project_id)
            elif choice == "4":
                self._handle_detection_tests(project_id)
            elif choice == "5":
                self._handle_activity_logging(project_id)
            elif choice == "6":
                self._handle_generate_report(project_id)
            else:
                print("\n[!] Invalid selection. Please enter a number between 0 and 6.")

    def _handle_engagements(self, project_id: int) -> None:
        print("\n--- ENGAGEMENT MANAGEMENT ---")
        engs = self.engagement_mgr.list_engagements(project_id)
        if engs:
            for e in engs:
                print(f"  - [{e['engagement_code']}] Org: {e['organization']} | Status: {e['status']} | ROE: {e['rules_of_engagement'][:50]}...")
        else:
            print("  No formal engagements registered yet.")

        create_new = input("\nCreate new engagement? (y/N): ").strip().lower()
        if create_new == "y":
            code = input("Engagement Code (e.g., RT-2026-01): ").strip()
            org = input("Organization: ").strip()
            auth = input("Authorization Details (e.g. SOW #104 signed by CISO): ").strip()
            roe = input("Rules of Engagement summary: ").strip()
            objs = input("Testing Objectives: ").strip()
            try:
                self.engagement_mgr.create_engagement(
                    project_id=project_id,
                    engagement_code=code,
                    organization=org,
                    authorization_details=auth,
                    rules_of_engagement=roe,
                    testing_objectives=objs
                )
                print("[+] Engagement registered successfully.")
            except Exception as e:
                print(f"[-] Error: {e}")

    def _handle_ad_inventory(self, project_id: int) -> None:
        print("\n--- ACTIVE DIRECTORY SECURITY LAB ---")
        print("  [1] Record Domain Controller")
        print("  [2] Record AD Misconfiguration (Kerberoasting, Delegation, etc.)")
        sub = input("Select action [1-2]: ").strip()
        if sub == "1":
            host = input("DC Hostname (e.g. DC01): ").strip()
            ip = input("DC IP Address: ").strip()
            dom = input("Domain FQDN (e.g. corp.local): ").strip()
            os_ver = input("OS Version [Windows Server 2022]: ").strip() or "Windows Server 2022"
            self.ad_inventory.record_domain_controller(project_id, host, ip, dom, os_ver)
            print("[+] Domain Controller recorded.")
        elif sub == "2":
            title = input("Misconfiguration Title: ").strip()
            cat = input("Category (e.g. Kerberos / ACL): ").strip()
            obj = input("Affected AD Object: ").strip()
            mitre = input("MITRE Technique ID (e.g. T1558.003): ").strip()
            desc = input("Description: ").strip()
            remed = input("Defensive Recommendation: ").strip()
            self.ad_inventory.record_ad_misconfiguration(project_id, title, cat, obj, mitre, desc, remed)
            print("[+] AD Misconfiguration finding recorded.")

    def _handle_attack_paths(self, project_id: int) -> None:
        print("\n--- ATTACK PATH DOCUMENTATION ---")
        steps = self.attack_tracker.list_attack_steps(project_id)
        if steps:
            for s in steps:
                print(f"  - [{s['status'].upper()}] {s['task_name']} | Recorded: {s['created_at']}")
        else:
            print("  No attack steps recorded yet.")

        add_step = input("\nDocument a simulated attack step? (y/N): ").strip().lower()
        if add_step == "y":
            phase = input("Kill Chain Phase (e.g. Privilege Escalation): ").strip()
            name = input("Step Name (e.g. SeImpersonatePrivilege Token Abuse): ").strip()
            tech = input("MITRE Technique ID (e.g. T1134.001): ").strip()
            tgt = input("Target Host: ").strip()
            succ = input("Was the simulation successful? (y/N): ").strip().lower() == "y"
            obs = input("Observations: ").strip()
            ind = input("Defensive Indicators Left: ").strip()
            self.attack_tracker.record_attack_step(project_id, phase, name, tech, tgt, succ, obs, ind)
            print("[+] Attack step recorded.")

    def _handle_detection_tests(self, project_id: int) -> None:
        print("\n--- DETECTION & TELEMETRY TESTING ---")
        tests = self.detection_tester.list_detection_tests(project_id)
        if tests:
            for t in tests:
                details = t.get("details", {})
                print(f"  - [{details.get('actual_outcome', '').upper()}] {t['task_name']} | Source: {details.get('detection_source')}")
        else:
            print("  No detection tests recorded yet.")

        add_test = input("\nRecord a detection test? (y/N): ").strip().lower()
        if add_test == "y":
            name = input("Technique Name: ").strip()
            tech_id = input("MITRE Technique ID: ").strip()
            sim = input("Simulation Details: ").strip()
            expected = input("Expected Telemetry (e.g. Event ID 4624/Sysmon Event 1): ").strip()
            outcome = input("Actual Outcome (detected/alerted/blocked/missed): ").strip().lower()
            source = input("Detection Source (e.g. Microsoft Defender for Endpoint / Splunk): ").strip()
            remed = input("Remediation / Detection Rule Guidance: ").strip()
            self.detection_tester.record_detection_test(project_id, name, tech_id, sim, expected, outcome, source, remed)
            print("[+] Detection test result recorded.")

    def _handle_activity_logging(self, project_id: int) -> None:
        print("\n--- OPERATOR ACTIVITY LOGGER ---")
        acts = self.activity_logger.list_activities(project_id)
        if acts:
            for a in acts:
                d = a.get("details", {})
                print(f"  - [{d.get('timestamp')}] {d.get('operator')}: {d.get('action')} on {d.get('target_host')} via {d.get('tool_name')}")
        else:
            print("  No activities logged yet.")

        log_new = input("\nLog an operator action? (y/N): ").strip().lower()
        if log_new == "y":
            op = input("Operator handle [analyst]: ").strip() or "analyst"
            act = input("Action (e.g. LDAP Query for SPNs): ").strip()
            src = input("Source Host: ").strip()
            tgt = input("Target Host: ").strip()
            tool = input("Tool Used: ").strip()
            notes = input("Notes: ").strip()
            self.activity_logger.log_activity(project_id, op, act, src, tgt, tool, notes)
            print("[+] Activity logged.")

    def _handle_generate_report(self, project_id: int) -> None:
        print("\n--- GENERATE RED TEAM REPORT ---")
        engs = self.engagement_mgr.list_engagements(project_id)
        org = engs[0]["organization"] if engs else "Lab Environment"
        title = "Red Team Security Assessment & Detection Validation Report"
        summary = input("Executive Summary: ").strip() or "Authorized red team simulation conducted to evaluate security detection boundaries."
        fmt = input("Format (markdown/html/json) [markdown]: ").strip() or "markdown"

        findings = self.db.get_projects() # findings list
        with self.db.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM findings WHERE project_id = ?", (project_id,))
            f_list = [dict(r) for r in cursor.fetchall()]

        path = self.report_engine.generate_report(
            project_id=project_id,
            title=title,
            organization=org,
            module_name="Red Team Operations",
            executive_summary=summary,
            findings=f_list,
            report_format=fmt
        )
        print(f"[+] Report generated at:\n    {path}")
