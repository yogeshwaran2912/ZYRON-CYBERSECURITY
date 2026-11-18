"""
ZYRON - Cybersecurity Automation Module Entry Point
Terminal workflow for task execution, parsers, schedulers, and multi-step workflows.
"""

from __future__ import annotations

from core.database import DatabaseManager, get_db
from core.logger import get_logger
from modules.automation.result_parser import ResultParser
from modules.automation.scheduler import LightweightScheduler
from modules.automation.task_runner import TaskRunner
from modules.automation.workflow_manager import WorkflowManager

logger = get_logger("automation.cli")


class AutomationModule:
    """Main controller for the Cybersecurity Automation domain in ZYRON."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()
        self.runner = TaskRunner(self.db)
        self.parser = ResultParser()
        self.scheduler = LightweightScheduler(self.db)
        self.workflow_mgr = WorkflowManager(self.db)

        # Register standard baseline routines
        self._register_default_routines()

    def _register_default_routines(self) -> None:
        """Register safe, vetted default routines."""
        def local_database_vacuum() -> dict[str, str]:
            with self.db.get_connection() as conn:
                conn.execute("VACUUM;")
            return {"status": "vacuum_complete", "details": "SQLite database optimized successfully."}

        def system_audit_summary() -> dict[str, int]:
            return self.db.get_system_counts()

        self.runner.register_routine("database_optimization_vacuum", local_database_vacuum)
        self.runner.register_routine("system_health_audit", system_audit_summary)

    def get_or_create_default_project(self) -> int:
        """Fetch or initialize the baseline Automation project ID."""
        projects = self.db.get_projects(module_type="automation")
        if projects:
            return projects[0]["id"]
        return self.db.create_project(
            name="Security Automation Hub",
            module_type="automation",
            description="Active automation and workflow execution hub"
        )

    def run_menu(self) -> None:
        """Display the Automation interactive menu."""
        project_id = self.get_or_create_default_project()

        while True:
            print("\n" + "=" * 65)
            print("  ZYRON :: CYBERSECURITY AUTOMATION HUB")
            print(f"  Active Project ID: #{project_id}")
            print("=" * 65)
            print("  [1] Predefined Task Runner (Safe Reviewed Python Routines)")
            print("  [2] Workflow: Evidence Cryptographic Integrity Verification")
            print("  [3] Result Parser: Ingest & Deduplicate Finding Lists")
            print("  [4] Scheduled Jobs Manager (Lightweight / On-Demand)")
            print("  [5] Task Execution History & Audit Logs")
            print("  [0] Return to Main Menu")
            print("-" * 65)

            choice = input("Select an option [0-5]: ").strip()

            if choice == "0":
                break
            elif choice == "1":
                self._handle_task_runner(project_id)
            elif choice == "2":
                self._handle_evidence_workflow(project_id)
            elif choice == "3":
                self._handle_parser_dedup()
            elif choice == "4":
                self._handle_scheduler(project_id)
            elif choice == "5":
                self._handle_task_history(project_id)
            else:
                print("\n[!] Invalid selection. Please enter a number between 0 and 5.")

    def _handle_task_runner(self, project_id: int) -> None:
        print("\n--- SAFE TASK RUNNER ---")
        routines = self.runner.list_available_routines()
        print("Available vetted routines:")
        for idx, r in enumerate(routines, start=1):
            print(f"  [{idx}] {r}")

        choice = input(f"Select routine to execute [1-{len(routines)}]: ").strip()
        try:
            selected_idx = int(choice) - 1
            if 0 <= selected_idx < len(routines):
                routine_name = routines[selected_idx]
                print(f"[*] Executing routine '{routine_name}'...")
                res = self.runner.run_task(project_id, routine_name)
                print(f"[+] Task executed successfully: Status={res['status']}")
                print(f"    Output: {res['result'].get('data')}")
            else:
                print("[-] Invalid routine index.")
        except Exception as e:
            print(f"[-] Execution error: {e}")

    def _handle_evidence_workflow(self, project_id: int) -> None:
        print("\n--- EVIDENCE INTEGRITY WORKFLOW ---")
        print("[*] Verifying cryptographic SHA-256 hashes of all stored evidence...")
        res = self.workflow_mgr.run_evidence_integrity_workflow(project_id)
        print(f"[+] Verification completed:")
        print(f"    Total Records: {res['total_records']}")
        print(f"    Verified Valid: {res['verified_valid']}")
        print(f"    Corrupted/Missing: {res['corrupted_or_missing']}")
        if res["details"]:
            for d in res["details"]:
                print(f"    ! [ID #{d['evidence_id']}] {d['title']}: {d['issue']}")

    def _handle_parser_dedup(self) -> None:
        print("\n--- RESULT PARSER & DEDUPLICATION ---")
        print("Enter a JSON array of findings or path to JSON file:")
        source = input("JSON Path or string: ").strip()
        if not source:
            return
        try:
            data = self.parser.parse_json(source)
            if isinstance(data, list):
                unique, dups = self.parser.deduplicate_findings(data)
                print(f"[+] Processed {len(data)} items:")
                print(f"    Unique findings: {len(unique)}")
                print(f"    Duplicates removed: {dups}")
            else:
                print("[!] Input must be a list of finding objects.")
        except Exception as e:
            print(f"[-] Parsing error: {e}")

    def _handle_scheduler(self, project_id: int) -> None:
        print("\n--- SCHEDULED JOBS MANAGER ---")
        jobs = self.scheduler.list_scheduled_jobs(project_id)
        if jobs:
            for j in jobs:
                cfg = j.get("config", {})
                print(f"  - [#{j['id']}] {j['task_name']} | Frequency: {cfg.get('frequency')} | Routine: {cfg.get('routine_name')}")
        else:
            print("  No scheduled jobs registered.")

        add_j = input("\nRegister a scheduled security check? (y/N): ").strip().lower()
        if add_j == "y":
            name = input("Job name: ").strip()
            freq = input("Frequency (daily/weekly/manual) [daily]: ").strip() or "daily"
            target = input("Target: ").strip()
            routine = input("Routine name [system_health_audit]: ").strip() or "system_health_audit"
            self.scheduler.register_scheduled_job(project_id, name, freq, target, routine)
            print("[+] Job registered successfully.")

    def _handle_task_history(self, project_id: int) -> None:
        print("\n--- TASK EXECUTION HISTORY ---")
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, task_name, task_type, status, completed_at, created_at
                FROM tasks
                WHERE project_id = ?
                ORDER BY id DESC
                LIMIT 15
                """,
                (project_id,)
            )
            tasks = [dict(r) for r in cursor.fetchall()]

        if tasks:
            for t in tasks:
                print(f"  - [#{t['id']}] [{t['status'].upper()}] {t['task_name']} ({t['task_type']}) - {t['created_at']}")
        else:
            print("  No tasks executed yet.")
