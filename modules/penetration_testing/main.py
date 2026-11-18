"""
ZYRON - Penetration Testing Module Entry Point
Terminal workflow for network inventory, service tracking, web assessment, findings, and reporting.
"""

from __future__ import annotations

from core.database import DatabaseManager, get_db
from core.exceptions import ValidationError
from core.logger import get_logger
from core.scope_manager import ScopeManager
from modules.penetration_testing.findings import PenetrationTestFindings
from modules.penetration_testing.network_inventory import NetworkInventory
from modules.penetration_testing.report import PenetrationTestReporter
from modules.penetration_testing.service_inventory import ServiceInventory
from modules.penetration_testing.web_assessment import WebAssessmentTracker

logger = get_logger("pentest.cli")


class PenetrationTestingModule:
    """Main controller for the Penetration Testing domain in ZYRON."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()
        self.scope_manager = ScopeManager(self.db)
        self.network_inv = NetworkInventory(self.db)
        self.service_inv = ServiceInventory(self.db)
        self.web_tracker = WebAssessmentTracker(self.db)
        self.findings_mgr = PenetrationTestFindings(self.db)
        self.reporter = PenetrationTestReporter(self.db)

    def get_or_create_default_project(self) -> int:
        """Fetch or initialize the baseline Penetration Testing project ID."""
        projects = self.db.get_projects(module_type="penetration_testing")
        if projects:
            return projects[0]["id"]
        return self.db.create_project(
            name="Internal Penetration Test Workspace",
            module_type="penetration_testing",
            description="Active penetration testing assessment workspace"
        )

    def run_menu(self) -> None:
        """Display the Penetration Testing interactive menu."""
        project_id = self.get_or_create_default_project()

        while True:
            print("\n" + "=" * 65)
            print("  ZYRON :: PENETRATION TESTING WORKSPACE")
            print(f"  Active Project ID: #{project_id}")
            print("=" * 65)
            print("  [1] Pre-Engagement & Scope Verification")
            print("  [2] Network Host Inventory (Authorized Hosts & Subnets)")
            print("  [3] Service & Port Inventory (Ports, Versions, Banners)")
            print("  [4] Web Application Assessment Surface")
            print("  [5] Record New Vulnerability Finding (CVSS Rating)")
            print("  [6] List Findings & Record Remediation Retest")
            print("  [7] Generate Formal Penetration Test Report")
            print("  [0] Return to Main Menu")
            print("-" * 65)

            choice = input("Select an option [0-7]: ").strip()

            if choice == "0":
                break
            elif choice == "1":
                self._handle_scope(project_id)
            elif choice == "2":
                self._handle_network_inventory(project_id)
            elif choice == "3":
                self._handle_service_inventory(project_id)
            elif choice == "4":
                self._handle_web_assessment(project_id)
            elif choice == "5":
                self._handle_add_finding(project_id)
            elif choice == "6":
                self._handle_list_and_retest(project_id)
            elif choice == "7":
                self._handle_generate_report(project_id)
            else:
                print("\n[!] Invalid selection. Please enter a number between 0 and 7.")

    def _handle_scope(self, project_id: int) -> None:
        print("\n--- PRE-ENGAGEMENT SCOPE ---")
        scopes = self.scope_manager.list_scopes(project_id)
        if scopes:
            for s in scopes:
                pol = "EXCLUDED" if s["is_excluded"] else "AUTHORIZED"
                print(f"  - [{pol}] {s['target_type'].upper()}: {s['target_value']} | {s.get('description') or ''}")
        else:
            print("  No targets authorized yet. (Default Policy: DENY ALL)")

        add_tgt = input("\nAdd authorized/excluded network target? (y/N): ").strip().lower()
        if add_tgt == "y":
            val = input("Target (IP, CIDR, domain): ").strip()
            ttype = input("Target type (ip/cidr/domain/url) [ip]: ").strip() or "ip"
            ex = input("Is this target EXCLUDED? (y/N): ").strip().lower() == "y"
            desc = input("Scope notes: ").strip()
            try:
                self.scope_manager.add_scope_target(project_id, ttype, val, is_excluded=ex, description=desc)
                print("[+] Target registered in scope.")
            except Exception as e:
                print(f"[-] Error: {e}")

    def _handle_network_inventory(self, project_id: int) -> None:
        print("\n--- NETWORK HOST INVENTORY ---")
        hosts = self.network_inv.list_network_hosts(project_id)
        if hosts:
            for h in hosts:
                m = h.get("metadata", {})
                print(f"  - {h['asset_value']} | Hostname: {m.get('hostname', 'N/A')} | OS: {m.get('os_fingerprint', 'Unknown')}")
        else:
            print("  No hosts registered in network inventory.")

        add_h = input("\nRegister a host? (y/N): ").strip().lower()
        if add_h == "y":
            ip = input("Host IP Address: ").strip()
            hostname = input("Hostname: ").strip()
            os_fp = input("OS Fingerprint (e.g. Linux Ubuntu 22.04 / Windows Server): ").strip()
            seg = input("Segment [internal]: ").strip() or "internal"
            try:
                self.network_inv.add_network_host(project_id, ip, hostname, os_fp, seg)
                print("[+] Host registered.")
            except Exception as e:
                print(f"[-] Error: {e}")

    def _handle_service_inventory(self, project_id: int) -> None:
        print("\n--- SERVICE & PORT INVENTORY ---")
        services = self.service_inv.list_services(project_id)
        if services:
            for s in services:
                m = s.get("metadata", {})
                print(f"  - {s['asset_value']} | Service: {m.get('service_name')} | Version: {m.get('version')} | Banner: {m.get('banner')[:30]}")
        else:
            print("  No services recorded yet.")

        add_s = input("\nRecord an identified service? (y/N): ").strip().lower()
        if add_s == "y":
            ip = input("Host IP: ").strip()
            port = input("Port number: ").strip()
            proto = input("Protocol (tcp/udp) [tcp]: ").strip() or "tcp"
            svc = input("Service Name (e.g. ssh, http, smb): ").strip()
            ver = input("Version string: ").strip()
            ban = input("Banner text: ").strip()
            try:
                self.service_inv.record_service(project_id, ip, port, proto, svc, ver, ban)
                print("[+] Service recorded.")
            except Exception as e:
                print(f"[-] Error: {e}")

    def _handle_web_assessment(self, project_id: int) -> None:
        print("\n--- WEB ASSESSMENT SURFACE ---")
        url = input("Enter Web Application Target URL to record: ").strip()
        if url:
            app_name = input("Application Name: ").strip()
            tech = input("Tech Stack / Frameworks: ").strip()
            try:
                self.web_tracker.record_web_target(project_id, url, app_name, tech)
                print("[+] Web application registered.")
            except Exception as e:
                print(f"[-] Error: {e}")

    def _handle_add_finding(self, project_id: int) -> None:
        print("\n--- RECORD PENTEST FINDING ---")
        title = input("Finding Title: ").strip()
        if not title:
            return
        sev = input("Severity (informational/low/medium/high/critical) [medium]: ").strip() or "medium"
        cvss_in = input("CVSS v3 Score (0.0 - 10.0) [leave blank if unassigned]: ").strip()
        cvss = float(cvss_in) if cvss_in else None
        asset = input("Affected Asset (IP / Hostname / URL): ").strip()
        desc = input("Technical Description: ").strip()
        impact = input("Vulnerability Impact: ").strip()
        repro = input("Reproduction Steps: ").strip()
        remed = input("Remediation Recommendation: ").strip()
        ref = input("References (CVE, CWE, OWASP): ").strip()

        try:
            fid = self.findings_mgr.add_finding(
                project_id, title, sev, asset, desc, impact, repro, remed, cvss, ref
            )
            print(f"[+] Pentest finding #{fid} recorded.")
        except Exception as e:
            print(f"[-] Error: {e}")

    def _handle_list_and_retest(self, project_id: int) -> None:
        print("\n--- FINDINGS & RETESTING ---")
        findings = self.findings_mgr.list_findings(project_id)
        if not findings:
            print("  No findings recorded.")
            return

        for f in findings:
            print(f"  - [#{f['id']}] [{f['severity'].upper()}] {f['title']} | Asset: {f['affected_asset']} | Status: {f['validation_status']}")

        retest = input("\nRecord a retest validation? (y/N): ").strip().lower()
        if retest == "y":
            try:
                fid = int(input("Finding ID to retest: ").strip())
                resolved = input("Is the issue resolved/fixed? (y/N): ").strip().lower() == "y"
                notes = input("Retest verification notes: ").strip()
                self.findings_mgr.record_retest(fid, resolved, notes)
                print(f"[+] Retest recorded. Finding #{fid} status updated.")
            except Exception as e:
                print(f"[-] Retest update error: {e}")

    def _handle_generate_report(self, project_id: int) -> None:
        print("\n--- GENERATE PENETRATION TEST REPORT ---")
        client = input("Client Name [Internal Assessment]: ").strip() or "Internal Assessment"
        atype = input("Assessment Type (Network / Web / Full Scope) [Full Scope]: ").strip() or "Full Scope"
        summary = input("Executive Summary: ").strip() or "Formal penetration testing assessment conducted under authorized rules of engagement."
        fmt = input("Report format (markdown/html/json) [markdown]: ").strip() or "markdown"

        try:
            path = self.reporter.generate_report(project_id, client, atype, summary, fmt)
            print(f"[+] Report generated successfully at:\n    {path}")
        except Exception as e:
            print(f"[-] Report generation failed: {e}")
