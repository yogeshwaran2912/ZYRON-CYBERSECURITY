"""
ZYRON - CYBERSECURITY RESEARCH & AUTOMATION FRAMEWORK
Main Terminal Application & Domain Controller
Version: 0.1.0
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.database import DatabaseManager, get_db
from core.evidence_manager import EvidenceManager
from core.exceptions import ZyronException
from core.logger import get_logger, setup_logging
from core.security_manager import SecurityManager
from modules.automation.main import AutomationModule
from modules.bug_bounty.main import BugBountyModule
from modules.penetration_testing.main import PenetrationTestingModule
from modules.red_team.main import RedTeamModule

# Setup application logging
setup_logging()
logger = get_logger("cli")

# Terminal styling constants (ANSI colors compatible with Windows 10/11 Terminal and Linux/macOS)
BLUE = "\033[94m"
CYAN = "\033[96m"
PURPLE = "\033[95m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def clear_screen() -> None:
    """Clear terminal screen cross-platform."""
    # Only clear if terminal is attached
    if sys.stdout.isatty():
        os.system("cls" if platform.system() == "Windows" else "clear")


def print_banner() -> None:
    """Display the ZYRON cybersecurity visual identity header."""
    banner = f"""{PURPLE}{BOLD}
  ███████╗██╗   ██╗██████╗  ██████╗ ███╗   ██╗
  ╚══███╔╝╚██╗ ██╔╝██╔══██╗██╔═══██╗████╗  ██║
    ███╔╝  ╚████╔╝ ██████╔╝██║   ██║██╔██╗ ██║
   ███╔╝    ╚██╔╝  ██╔══██╗██║   ██║██║╚██╗██║
  ███████╗   ██║   ██║  ██║╚██████╔╝██║ ╚████║
  ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝{RESET}
{CYAN}{BOLD}  ZYRON CYBERSECURITY{RESET}
{BLUE}  CYBERSECURITY RESEARCH & AUTOMATION FRAMEWORK{RESET}
{DIM}  Version 0.1.0 | Platform: {platform.system()} {platform.release()} ({platform.machine()}){RESET}
"""
    print(banner)


class ZyronCLI:
    """Master controller for the ZYRON terminal interface."""

    def __init__(self) -> None:
        self.db = get_db()
        # Initialize schema and verify baseline database records
        self.db.initialize_schema()
        self.security_mgr = SecurityManager(self.db)
        self.evidence_mgr = EvidenceManager(self.db)

        # Initialize domain modules
        self.modules = {
            "bug_bounty": BugBountyModule(self.db),
            "red_team": RedTeamModule(self.db),
            "penetration_testing": PenetrationTestingModule(self.db),
            "automation": AutomationModule(self.db)
        }

    def run(self) -> None:
        """Main application execution loop."""
        self.db.log_audit(
            event_type="SESSION_START",
            action="APPLICATION_LAUNCH",
            details="ZYRON CLI session started",
            status="success"
        )

        while True:
            try:
                self._display_main_menu()
                raw_input = input(f"{CYAN}{BOLD}ZYRON > Select option [0-10]: {RESET}")
                choice = raw_input.strip().lstrip("\ufeff")

                if choice == "0":
                    if self._confirm_exit():
                        self._graceful_shutdown()
                        break
                elif choice == "1":
                    self.modules["bug_bounty"].run_menu()
                elif choice == "2":
                    self.modules["red_team"].run_menu()
                elif choice == "3":
                    self.modules["penetration_testing"].run_menu()
                elif choice == "4":
                    self.modules["automation"].run_menu()
                elif choice == "5":
                    self._menu_project_management()
                elif choice == "6":
                    self._menu_vulnerability_findings()
                elif choice == "7":
                    self._menu_evidence_management()
                elif choice == "8":
                    self._menu_reports_documentation()
                elif choice == "9":
                    self._menu_system_info()
                elif choice == "10":
                    self._menu_settings()
                else:
                    print(f"\n{RED}[!] Invalid option '{choice}'. Please enter a number between 0 and 10.{RESET}")
                    input(f"{DIM}Press Enter to continue...{RESET}")

            except KeyboardInterrupt:
                print(f"\n\n{YELLOW}[!] Operation interrupted by user (Ctrl+C).{RESET}")
                if self._confirm_exit():
                    self._graceful_shutdown()
                    break
            except EOFError:
                print(f"\n\n{YELLOW}[!] End of input stream detected. Exiting...{RESET}")
                self._graceful_shutdown()
                break
            except Exception as e:
                logger.error("Unexpected error in main CLI loop: %s", e, exc_info=True)
                print(f"\n{RED}[ERROR] An error occurred: {e}{RESET}")
                input(f"{DIM}Press Enter to continue...{RESET}")

    def _display_main_menu(self) -> None:
        """Render the status bar and the 10 menu options."""
        print_banner()

        dry_run = self.security_mgr.is_dry_run
        dry_run_str = f"{GREEN}ACTIVE{RESET}" if dry_run else f"{RED}DISABLED{RESET}"
        policy_str = f"{PURPLE}DENY (Default){RESET}"

        print(f" {DIM}Scope Policy:{RESET} {policy_str} | {DIM}Dry-Run Mode:{RESET} {dry_run_str} | {DIM}DB:{RESET} {GREEN}Online{RESET}")
        print(" " + "=" * 63)
        print(f"  {BOLD}[1]{RESET}  Bug Bounty Research")
        print(f"  {BOLD}[2]{RESET}  Red Team Operations")
        print(f"  {BOLD}[3]{RESET}  Penetration Testing")
        print(f"  {BOLD}[4]{RESET}  Security Automation")
        print(f"  {BOLD}[5]{RESET}  Project Management")
        print(f"  {BOLD}[6]{RESET}  Vulnerability Findings (Global)")
        print(f"  {BOLD}[7]{RESET}  Evidence Management (Integrity Hashes)")
        print(f"  {BOLD}[8]{RESET}  Reports & Documentation")
        print(f"  {BOLD}[9]{RESET}  System Information")
        print(f"  {BOLD}[10]{RESET} Settings")
        print(f"  {BOLD}[0]{RESET}  Exit")
        print(" " + "=" * 63)

    def _confirm_exit(self) -> bool:
        """Prompt confirmation for application exit."""
        raw_ans = input(f"\n{YELLOW}Are you sure you want to exit ZYRON? (y/N): {RESET}")
        ans = raw_ans.strip().lower().lstrip("\ufeff")
        return ans in ("y", "yes")

    def _graceful_shutdown(self) -> None:
        """Perform orderly shutdown and record audit trail."""
        self.db.log_audit(
            event_type="SESSION_END",
            action="APPLICATION_EXIT",
            details="ZYRON CLI session terminated cleanly",
            status="success"
        )
        print(f"\n{GREEN}[+] ZYRON Framework shutdown cleanly. Goodbye.{RESET}\n")

    # Submenu: [5] Project Management
    def _menu_project_management(self) -> None:
        while True:
            print("\n" + "=" * 65)
            print(f"  {BOLD}ZYRON :: PROJECT MANAGEMENT{RESET}")
            print("=" * 65)
            projects = self.db.get_projects()
            print(f"Total Projects Registered: {len(projects)}\n")
            for p in projects:
                print(f"  - [#{p['id']}] {BOLD}{p['name']}{RESET}")
                print(f"    Domain: {CYAN}{p['module_type']}{RESET} | Status: {p['status']} | Created: {p['created_at'][:10]}")
                if p.get("description"):
                    print(f"    Description: {p['description']}")
                print()

            print("  [1] Create New Project")
            print("  [0] Return to Main Menu")
            print("-" * 65)
            ch = input("Select option [0-1]: ").strip()
            if ch == "0":
                break
            elif ch == "1":
                name = input("Enter Project Name: ").strip()
                if not name:
                    print(f"{RED}[!] Name cannot be empty.{RESET}")
                    continue
                print("Select Module Domain:")
                print("  [1] bug_bounty")
                print("  [2] red_team")
                print("  [3] penetration_testing")
                print("  [4] automation")
                m_sel = input("Domain [1-4]: ").strip()
                m_map = {
                    "1": "bug_bounty",
                    "2": "red_team",
                    "3": "penetration_testing",
                    "4": "automation"
                }
                m_type = m_map.get(m_sel, "bug_bounty")
                desc = input("Project Description: ").strip()
                try:
                    pid = self.db.create_project(name, m_type, desc)
                    print(f"{GREEN}[+] Project #{pid} created successfully.{RESET}")
                except Exception as e:
                    print(f"{RED}[-] Error creating project: {e}{RESET}")

    # Submenu: [6] Vulnerability Findings (Global)
    def _menu_vulnerability_findings(self) -> None:
        print("\n" + "=" * 65)
        print(f"  {BOLD}ZYRON :: GLOBAL VULNERABILITY FINDINGS{RESET}")
        print("=" * 65)
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT f.id, f.title, f.severity, f.validation_status, f.affected_asset, f.cvss_score, p.name AS project_name
                FROM findings f
                JOIN projects p ON f.project_id = p.id
                ORDER BY CASE f.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END, f.id DESC
                """
            )
            findings = [dict(r) for r in cursor.fetchall()]

        if findings:
            print(f"Total Findings Across All Domains: {len(findings)}\n")
            for f in findings:
                sev_color = RED if f["severity"] in ("critical", "high") else (YELLOW if f["severity"] == "medium" else CYAN)
                print(f"  [#{f['id']}] {sev_color}[{f['severity'].upper()}]{RESET} {BOLD}{f['title']}{RESET}")
                print(f"       Asset: {f['affected_asset']} | Status: {f['validation_status']} | Project: {f['project_name']}")
                if f.get("cvss_score"):
                    print(f"       CVSS: {f['cvss_score']}")
        else:
            print("  No vulnerability findings recorded across any project yet.")
        input(f"\n{DIM}Press Enter to return to main menu...{RESET}")

    # Submenu: [7] Evidence Management
    def _menu_evidence_management(self) -> None:
        print("\n" + "=" * 65)
        print(f"  {BOLD}ZYRON :: EVIDENCE INTEGRITY DASHBOARD{RESET}")
        print("=" * 65)
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT e.id, e.title, e.evidence_type, e.sha256_hash, e.content_or_path, e.created_at, p.name AS project_name
                FROM evidence e
                JOIN projects p ON e.project_id = p.id
                ORDER BY e.id DESC
                LIMIT 20
                """
            )
            records = [dict(r) for r in cursor.fetchall()]

        if records:
            print(f"Stored Evidence Records ({len(records)}):\n")
            for r in records:
                print(f"  - [#{r['id']}] {BOLD}{r['title']}{RESET} ({r['evidence_type']})")
                print(f"    SHA-256: {CYAN}{r['sha256_hash']}{RESET}")
                print(f"    Project: {r['project_name']} | Recorded: {r['created_at']}")
        else:
            print("  No evidence records stored yet.")

        verify_choice = input(f"\nVerify cryptographic integrity of an evidence record? (y/N): ").strip().lower()
        if verify_choice == "y":
            eid_str = input("Enter Evidence ID: ").strip()
            try:
                eid = int(eid_str)
                valid, msg = self.evidence_mgr.verify_evidence_integrity(eid)
                if valid:
                    print(f"{GREEN}[+] {msg}{RESET}")
                else:
                    print(f"{RED}[-] {msg}{RESET}")
            except Exception as e:
                print(f"{RED}[!] Error: {e}{RESET}")
            input(f"{DIM}Press Enter to return...{RESET}")

    # Submenu: [8] Reports & Documentation
    def _menu_reports_documentation(self) -> None:
        print("\n" + "=" * 65)
        print(f"  {BOLD}ZYRON :: REPORTS & DOCUMENTATION{RESET}")
        print("=" * 65)
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, title, report_type, file_path, created_at
                FROM reports
                ORDER BY id DESC
                LIMIT 15
                """
            )
            reports = [dict(r) for r in cursor.fetchall()]

        if reports:
            print(f"Generated Reports ({len(reports)}):")
            for rp in reports:
                print(f"  - [#{rp['id']}] [{rp['report_type'].upper()}] {BOLD}{rp['title']}{RESET}")
                print(f"    Location: {rp['file_path']}")
                print(f"    Generated: {rp['created_at']}")
        else:
            print("  No formal reports compiled yet.")

        doc_dir = PROJECT_ROOT / "documentation"
        doc_files = list(doc_dir.glob("*.md")) if doc_dir.is_dir() else []
        print(f"\nAvailable Documentation Guides ({len(doc_files)}):")
        for df in doc_files:
            print(f"  - documentation/{df.name}")

        input(f"\n{DIM}Press Enter to return to main menu...{RESET}")

    # Submenu: [9] System Information
    def _menu_system_info(self) -> None:
        print("\n" + "=" * 65)
        print(f"  {BOLD}ZYRON :: SYSTEM INFORMATION & DATABASE METRICS{RESET}")
        print("=" * 65)
        counts = self.db.get_system_counts()
        print(f"  Framework:         ZYRON v0.1.0")
        print(f"  Host OS:           {platform.system()} {platform.release()} ({platform.version()})")
        print(f"  Architecture:      {platform.machine()}")
        print(f"  Python Runtime:    {sys.version.split()[0]} ({platform.python_implementation()})")
        print(f"  Database Path:     {self.db.db_path}")
        print(f"  Database Status:   Connected (WAL mode active)")
        print(f"  Scope Policy:      DENY by default (Enforced)")
        print(f"  Dry-Run Mode:      {self.security_mgr.is_dry_run}\n")

        print("  Database Table Entity Counts:")
        for tbl, cnt in counts.items():
            print(f"    - {tbl:<20}: {cnt}")

        input(f"\n{DIM}Press Enter to return to main menu...{RESET}")

    # Submenu: [10] Settings
    def _menu_settings(self) -> None:
        print("\n" + "=" * 65)
        print(f"  {BOLD}ZYRON :: SETTINGS & SECURITY CONTROLS{RESET}")
        print("=" * 65)
        curr_dry = self.security_mgr.is_dry_run
        print(f"  [1] Toggle Dry-Run Mode (Current: {GREEN if curr_dry else RED}{curr_dry}{RESET})")
        print(f"  [2] View Recent Audit Log Trail (Last 10 entries)")
        print(f"  [0] Return to Main Menu")
        print("-" * 65)
        ch = input("Select option [0-2]: ").strip()
        if ch == "1":
            new_val = not curr_dry
            self.security_mgr.set_dry_run(new_val)
            print(f"{GREEN}[+] Dry run mode updated to: {new_val}{RESET}")
        elif ch == "2":
            logs = self.db.get_audit_logs(limit=10)
            print("\nRecent Audit Logs:")
            for l in logs:
                print(f"  - [{l['timestamp']}] [{l['status'].upper()}] {l['event_type']} -> {l['action']} ({l.get('details') or ''})")
            input(f"\n{DIM}Press Enter to continue...{RESET}")


def main() -> None:
    """Application entry point."""
    cli = ZyronCLI()
    cli.run()


if __name__ == "__main__":
    main()
