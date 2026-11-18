"""
ZYRON - Web Application Penetration Testing Assessment
Structured records for authentication, authorization, session management, and business logic tests.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from core.database import DatabaseManager, get_db
from core.logger import get_logger
from core.validators import validate_url

logger = get_logger("pentest.web")


class WebAssessmentTracker:
    """Manages web application attack surface documentation and testing checklists."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()

    def record_web_target(
        self,
        project_id: int,
        target_url: str,
        application_name: str,
        tech_stack: str = "",
        auth_mechanism: str = "Cookie-based Session"
    ) -> int:
        """Register a web application target under assessment."""
        valid_url = validate_url(target_url)
        now = datetime.now(timezone.utc).isoformat()
        metadata = {
            "application_name": application_name,
            "tech_stack": tech_stack,
            "auth_mechanism": auth_mechanism
        }

        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO assets (project_id, asset_type, asset_value, category, status, metadata_json, created_at, updated_at)
                VALUES (?, 'url', ?, 'web_application', 'in_scope', ?, ?, ?)
                ON CONFLICT(project_id, asset_type, asset_value) DO UPDATE SET
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (project_id, valid_url, json.dumps(metadata), now, now)
            )
            return cursor.lastrowid or 0

    def record_checklist_item(
        self,
        project_id: int,
        target_url: str,
        test_category: str,
        test_name: str,
        status: str,
        findings_notes: str
    ) -> int:
        """Record an OWASP WSTG test checklist item evaluation."""
        now = datetime.now(timezone.utc).isoformat()
        payload = {
            "target_url": target_url,
            "category": test_category,
            "test_name": test_name,
            "result_status": status,
            "notes": findings_notes
        }

        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO tasks (
                    project_id, task_name, task_type, status, parameters_json, result_json, completed_at, created_at
                )
                VALUES (?, ?, 'web_assessment_check', ?, ?, ?, ?, ?)
                """,
                (
                    project_id, f"[{test_category}] {test_name}",
                    "completed" if status.lower() == "pass" else "failed",
                    json.dumps({"target": target_url, "category": test_category}),
                    json.dumps(payload), now, now
                )
            )
            return cursor.lastrowid or 0
