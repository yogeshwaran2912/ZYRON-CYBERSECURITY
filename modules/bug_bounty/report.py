"""
ZYRON - Bug Bounty Report Generator
Generates formal bug bounty assessment reports and vulnerability disclosures.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.database import DatabaseManager, get_db
from core.report_engine import ReportEngine
from core.scope_manager import ScopeManager


class BugBountyReporter:
    """Creates formatted reports for Bug Bounty research engagements."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()
        self.report_engine = ReportEngine(self.db)
        self.scope_manager = ScopeManager(self.db)

    def generate_program_report(
        self,
        project_id: int,
        program_name: str,
        organization: str,
        executive_summary: str,
        report_format: str = "markdown"
    ) -> Path:
        """Fetch all findings and scope rules for a project and compile a report."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, title, severity, validation_status, affected_asset,
                       description, reproduction_steps, impact, remediation,
                       references_text, cvss_score
                FROM findings
                WHERE project_id = ?
                ORDER BY CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
                """,
                (project_id,)
            )
            findings = [dict(row) for row in cursor.fetchall()]

        scopes = self.scope_manager.list_scopes(project_id)

        title = f"Bug Bounty Research Report - {program_name}"
        return self.report_engine.generate_report(
            project_id=project_id,
            title=title,
            organization=organization,
            module_name="Bug Bounty Research",
            executive_summary=executive_summary,
            findings=findings,
            scope_summary=scopes,
            report_format=report_format
        )
