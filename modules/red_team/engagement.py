"""
ZYRON - Red Team Engagement Management
Tracks authorization boundaries, rules of engagement (ROE), and assessment windows.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from core.database import DatabaseManager, get_db
from core.exceptions import ValidationError
from core.logger import get_logger

logger = get_logger("red_team.engagement")


class EngagementManager:
    """Oversees Red Team engagement metadata, approvals, and objectives."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()

    def create_engagement(
        self,
        project_id: int,
        engagement_code: str,
        organization: str,
        authorization_details: str,
        rules_of_engagement: str,
        testing_objectives: str,
        start_date: str | None = None,
        end_date: str | None = None
    ) -> int:
        """Create a new formal Red Team engagement record."""
        now = datetime.now(timezone.utc).isoformat()
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO engagements (
                    project_id, engagement_code, organization, authorization_details,
                    rules_of_engagement, testing_objectives, start_date, end_date,
                    status, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'planned', ?)
                """,
                (
                    project_id, engagement_code.strip().upper(), organization.strip(),
                    authorization_details.strip(), rules_of_engagement.strip(),
                    testing_objectives.strip(), start_date, end_date, now
                )
            )
            eng_id = cursor.lastrowid or 0

        self.db.log_audit(
            event_type="ENGAGEMENT_CREATED",
            action="CREATE_ENGAGEMENT",
            target=engagement_code.strip().upper(),
            details=f"Organization: {organization}, Objectives: {testing_objectives[:100]}",
            status="success"
        )
        logger.info("Created engagement %s (ID: %d)", engagement_code, eng_id)
        return eng_id

    def list_engagements(self, project_id: int) -> list[dict[str, Any]]:
        """List all engagements linked to a project."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, project_id, engagement_code, organization, authorization_details,
                       rules_of_engagement, testing_objectives, start_date, end_date, status, created_at
                FROM engagements
                WHERE project_id = ?
                ORDER BY id DESC
                """,
                (project_id,)
            )
            return [dict(row) for row in cursor.fetchall()]
