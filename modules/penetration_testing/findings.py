"""
ZYRON - Penetration Testing Findings Manager
Industry-standard vulnerability tracking with CVSS v3 metrics and remediation retesting.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from core.database import DatabaseManager, get_db
from core.exceptions import ValidationError
from core.logger import get_logger
from core.validators import validate_severity, validate_validation_status

logger = get_logger("pentest.findings")


class PenetrationTestFindings:
    """Manages pentest findings with CVSS metrics and remediation validation."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()

    def add_finding(
        self,
        project_id: int,
        title: str,
        severity: str,
        affected_asset: str,
        description: str,
        impact: str,
        reproduction_steps: str,
        remediation: str,
        cvss_score: float | None = None,
        references_text: str = ""
    ) -> int:
        """Register a validated vulnerability finding from penetration testing."""
        valid_sev = validate_severity(severity)
        if cvss_score is not None and not (0.0 <= cvss_score <= 10.0):
            raise ValidationError("CVSS score must be between 0.0 and 10.0")

        now = datetime.now(timezone.utc).isoformat()
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO findings (
                    project_id, title, severity, validation_status, affected_asset,
                    description, reproduction_steps, impact, remediation,
                    references_text, cvss_score, created_at, updated_at
                )
                VALUES (?, ?, ?, 'validated', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_id, title, valid_sev, affected_asset,
                    description, reproduction_steps, impact, remediation,
                    references_text, cvss_score, now, now
                )
            )
            finding_id = cursor.lastrowid or 0

        self.db.log_audit(
            event_type="PENTEST_FINDING_RECORDED",
            action="CREATE_PENTEST_FINDING",
            target=affected_asset,
            details=f"Finding ID: {finding_id}, Title: {title}, Severity: {valid_sev}",
            status="success"
        )
        logger.info("Recorded pentest finding #%d: '%s' [%s]", finding_id, title, valid_sev.upper())
        return finding_id

    def list_findings(self, project_id: int) -> list[dict[str, Any]]:
        """List all findings for a pentest project ordered by severity."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, project_id, title, severity, validation_status, affected_asset,
                       description, reproduction_steps, impact, remediation,
                       references_text, cvss_score, created_at, updated_at
                FROM findings
                WHERE project_id = ?
                ORDER BY CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END, id ASC
                """,
                (project_id,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def record_retest(self, finding_id: int, is_resolved: bool, retest_notes: str) -> None:
        """Record the outcome of a retest for a previously reported finding."""
        status = "fixed" if is_resolved else "validated"
        now = datetime.now(timezone.utc).isoformat()
        with self.db.get_connection() as conn:
            conn.execute(
                """
                UPDATE findings
                SET validation_status = ?, remediation = remediation || '\n[RETEST NOTE: ' || ? || ']', updated_at = ?
                WHERE id = ?
                """,
                (status, retest_notes, now, finding_id)
            )

        self.db.log_audit(
            event_type="RETEST_COMPLETED",
            action="UPDATE_RETEST_STATUS",
            details=f"Finding #{finding_id} status set to {status}. Notes: {retest_notes}",
            status="success"
        )
