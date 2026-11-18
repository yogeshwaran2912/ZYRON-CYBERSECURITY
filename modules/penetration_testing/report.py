"""
ZYRON - Penetration Testing Report Generator
Creates comprehensive security assessment reports in Markdown, HTML, and JSON formats.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.database import DatabaseManager, get_db
from core.report_engine import ReportEngine
from core.scope_manager import ScopeManager
from modules.penetration_testing.findings import PenetrationTestFindings


class PenetrationTestReporter:
    """Produces executive and technical penetration testing reports."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()
        self.report_engine = ReportEngine(self.db)
        self.scope_manager = ScopeManager(self.db)
        self.findings_mgr = PenetrationTestFindings(self.db)

    def generate_report(
        self,
        project_id: int,
        client_name: str,
        assessment_type: str,
        executive_summary: str,
        report_format: str = "markdown"
    ) -> Path:
        """Compile complete penetration test assessment report."""
        findings = self.findings_mgr.list_findings(project_id)
        scopes = self.scope_manager.list_scopes(project_id)
        title = f"Penetration Testing Assessment Report - {client_name} ({assessment_type})"

        return self.report_engine.generate_report(
            project_id=project_id,
            title=title,
            organization=client_name,
            module_name=f"Penetration Testing ({assessment_type})",
            executive_summary=executive_summary,
            findings=findings,
            scope_summary=scopes,
            report_format=report_format
        )
