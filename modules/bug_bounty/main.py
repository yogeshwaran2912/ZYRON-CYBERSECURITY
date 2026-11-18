"""
ZYRON - Bug Bounty Research Module Entry Point
Terminal workflow for program management, recon, vulnerability tracking, and reporting.
"""

from __future__ import annotations

import sys
from typing import Any

from core.database import DatabaseManager, get_db
from core.exceptions import ScopeViolationError, ValidationError, ZyronException
from core.logger import get_logger
from core.scope_manager import ScopeManager
from modules.bug_bounty.asset_inventory import AssetInventory
from modules.bug_bounty.dns_recon import DNSRecon
from modules.bug_bounty.http_analyzer import HTTPAnalyzer
from modules.bug_bounty.report import BugBountyReporter
from modules.bug_bounty.vulnerability_tracker import VulnerabilityTracker

logger = get_logger("bug_bounty.cli")


class BugBountyModule:
    """Main controller for the Bug Bounty Research domain in ZYRON."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()
        self.scope_manager = ScopeManager(self.db)
        self.inventory = AssetInventory(self.db)
        self.dns_recon = DNSRecon(self.db, self.scope_manager, self.inventory)
        self.http_analyzer = HTTPAnalyzer(self.db, self.scope_manager)
        self.vuln_tracker = VulnerabilityTracker(self.db)
        self.reporter = BugBountyReporter(self.db)

    def get_or_create_default_project(self) -> int:
        """Fetch or initialize the baseline bug bounty project ID."""
        projects = self.db.get_projects(module_type="bug_bounty")
        if projects:
            return projects[0]["id"]
        return self.db.create_project(
            name="Default Bug Bounty Workspace",
            module_type="bug_bounty",
            description="Active bug bounty research workspace"
        )

    def run_menu(self) -> None:
        """Display the Bug Bounty Research interactive terminal menu."""
        project_id = self.get_or_create_default_project()

        while True:
            print("\n" + "=" * 65)
            print("  ZYRON :: BUG BOUNTY RESEARCH WORKSPACE")
            print(f"  Active Project ID: #{project_id}")
            print("=" * 65)
            print("  [1] View & Add Target Scope (Authorized / Excluded)")
            print("  [2] Asset Inventory (View / Register Assets)")
            print("  [3] Run Scope-Enforced DNS Reconnaissance")
            print("  [4] Run HTTP Security Header Analysis")
            print("  [5] Record New Vulnerability Finding")
            print("  [6] List & Review Vulnerability Findings")
            print("  [7] Generate Bug Bounty Assessment Report")
            print("  [0] Return to Main Menu")
            print("-" * 65)

            choice = input("Select an option [0-7]: ").strip()

            if choice == "0":
                break
            elif choice == "1":
                self._handle_scope_management(project_id)
            elif choice == "2":
                self._handle_asset_inventory(project_id)
            elif choice == "3":
                self._handle_dns_recon(project_id)
            elif choice == "4":
                self._handle_http_analysis(project_id)
            elif choice == "5":
                self._handle_record_finding(project_id)
            elif choice == "6":
                self._handle_list_findings(project_id)
            elif choice == "7":
                self._handle_generate_report(project_id)
            else:
                print("\n[!] Invalid selection. Please enter a number between 0 and 7.")

    def _handle_scope_management(self, project_id: int) -> None:
        print("\n--- SCOPE CONFIGURATION ---")
        scopes = self.scope_manager.list_scopes(project_id)
        if scopes:
            print(f"Current Rules ({len(scopes)}):")
            for s in scopes:
                policy = "EXCLUDED" if s["is_excluded"] else "AUTHORIZED"
                print(f"  - [{policy}] {s['target_type'].upper()}: {s['target_value']} ({s.get('description') or 'No notes'})")
        else:
            print("  No scope rules registered yet. (Default Policy: DENY ALL)")

        add_new = input("\nAdd new target rule? (y/N): ").strip().lower()
        if add_new == "y":
            target = input("Target value (e.g., example.com, 192.168.1.1): ").strip()
            ttype = input("Target type (domain/ip/cidr/url) [domain]: ").strip() or "domain"
            is_ex = input("Is this target EXCLUDED from testing? (y/N): ").strip().lower() == "y"
            desc = input("Rule description / notes: ").strip()
            try:
                self.scope_manager.add_scope_target(
                    project_id=project_id,
                    target_type=ttype,
                    target_value=target,
                    is_excluded=is_ex,
                    description=desc
                )
                print("[+] Scope rule registered successfully.")
            except (ValidationError, ScopeViolationError) as e:
                print(f"[-] Validation error: {e}")

    def _handle_asset_inventory(self, project_id: int) -> None:
        print("\n--- ASSET INVENTORY ---")
        assets = self.inventory.list_assets(project_id)
        if assets:
            print(f"Recorded Assets ({len(assets)}):")
            for a in assets:
                print(f"  - [{a['asset_type'].upper()}] {a['asset_value']} | Category: {a['category']} | Status: {a['status']}")
        else:
            print("  No assets recorded yet.")

        add_new = input("\nRegister a new asset manually? (y/N): ").strip().lower()
        if add_new == "y":
            val = input("Asset value: ").strip()
            atype = input("Asset type (domain/subdomain/ip/url) [domain]: ").strip() or "domain"
            cat = input("Category [target_domain]: ").strip() or "target_domain"
            try:
                self.inventory.add_asset(project_id, atype, val, category=cat)
                print("[+] Asset recorded successfully.")
            except ValidationError as e:
                print(f"[-] Validation error: {e}")

    def _handle_dns_recon(self, project_id: int) -> None:
        print("\n--- SCOPE-ENFORCED DNS RECONNAISSANCE ---")
        domain = input("Enter target domain to resolve: ").strip()
        try:
            result = self.dns_recon.resolve_domain(project_id, domain)
            if result.get("status") == "resolved":
                print(f"[+] Domain {domain} resolved successfully:")
                print(f"    Discovered IPs: {', '.join(result.get('ips', []))}")
                if result.get("cnames"):
                    print(f"    CNAMEs: {', '.join(result.get('cnames', []))}")
            else:
                print(f"[-] Resolution status: {result.get('status')} - Error: {result.get('error')}")
        except ScopeViolationError as e:
            print(f"\n[BLOCKED BY SCOPE POLICY] {e}")
        except ValidationError as e:
            print(f"[-] Input error: {e}")

    def _handle_http_analysis(self, project_id: int) -> None:
        print("\n--- HTTP SECURITY HEADER ANALYZER ---")
        url = input("Enter target URL (e.g., https://example.com): ").strip()
        try:
            res = self.http_analyzer.analyze_headers(project_id, url)
            if res.get("status") == "analyzed":
                print(f"\n[+] Analysis for {url}:")
                print(f"    HTTP Status: {res.get('http_status')}")
                print(f"    Security Score: {res.get('security_score_percent')}%")
                print(f"    Present Security Headers ({len(res.get('present_security_headers', {}))}):")
                for k in res.get("present_security_headers", {}):
                    print(f"      + {k}")
                print(f"    Missing Recommended Headers ({len(res.get('missing_security_headers', []))}):")
                for m in res.get("missing_security_headers", []):
                    print(f"      - {m['header']} ({m['purpose']})")
                if res.get("information_disclosure_headers"):
                    print("    Information Disclosure Headers Detected:")
                    for k, v in res.get("information_disclosure_headers", {}).items():
                        print(f"      ! {k}: {v}")
            else:
                print(f"[-] HTTP Analysis failed: {res.get('error')}")
        except ScopeViolationError as e:
            print(f"\n[BLOCKED BY SCOPE POLICY] {e}")
        except ValidationError as e:
            print(f"[-] Input error: {e}")

    def _handle_record_finding(self, project_id: int) -> None:
        print("\n--- RECORD VULNERABILITY FINDING ---")
        title = input("Finding Title: ").strip()
        if not title:
            print("[-] Title cannot be empty.")
            return

        sev = input("Severity (informational/low/medium/high/critical) [medium]: ").strip() or "medium"
        v_status = input("Validation Status (potential/suspected/validated/false_positive/fixed) [potential]: ").strip() or "potential"
        asset = input("Affected Asset: ").strip()
        desc = input("Description: ").strip()
        repro = input("Reproduction Steps: ").strip()
        impact = input("Business Impact: ").strip()
        remed = input("Remediation Guidance: ").strip()

        try:
            fid = self.vuln_tracker.record_finding(
                project_id=project_id,
                title=title,
                severity=sev,
                affected_asset=asset,
                description=desc,
                reproduction_steps=repro,
                impact=impact,
                remediation=remed,
                validation_status=v_status
            )
            print(f"[+] Finding #{fid} registered successfully.")
        except ValidationError as e:
            print(f"[-] Validation error: {e}")

    def _handle_list_findings(self, project_id: int) -> None:
        print("\n--- VULNERABILITY FINDINGS ---")
        findings = self.vuln_tracker.list_findings(project_id)
        if findings:
            print(f"Total Findings: {len(findings)}")
            for f in findings:
                print(f"  - [#{f['id']}] [{f['severity'].upper()}] {f['title']} | Status: {f['validation_status']} | Asset: {f['affected_asset']}")
        else:
            print("  No findings recorded yet.")

    def _handle_generate_report(self, project_id: int) -> None:
        print("\n--- GENERATE BUG BOUNTY REPORT ---")
        prog_name = input("Program Name [Default Program]: ").strip() or "Default Program"
        org = input("Organization [Client Org]: ").strip() or "Client Org"
        summary = input("Executive Summary: ").strip() or "Standard bug bounty assessment conducted under authorized rules of engagement."
        fmt = input("Format (markdown/html/json) [markdown]: ").strip() or "markdown"

        try:
            report_path = self.reporter.generate_program_report(
                project_id=project_id,
                program_name=prog_name,
                organization=org,
                executive_summary=summary,
                report_format=fmt
            )
            print(f"[+] Report generated successfully at:\n    {report_path}")
        except Exception as e:
            print(f"[-] Report generation failed: {e}")
