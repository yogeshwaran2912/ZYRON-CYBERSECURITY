"""
ZYRON - Red Team Activity Logger
Chronological record-keeping for deconfliction and defensive correlation during engagements.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from core.database import DatabaseManager, get_db
from core.logger import get_logger

logger = get_logger("red_team.activity")


class ActivityLogger:
    """Maintains a synchronized timeline of operator activities for engagement deconfliction."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()

    def log_activity(
        self,
        project_id: int,
        operator: str,
        action: str,
        source_host: str,
        target_host: str,
        tool_name: str,
        notes: str = ""
    ) -> int:
        """Record an operator activity in the audit and task logs."""
        now = datetime.now(timezone.utc).isoformat()
        details_obj = {
            "operator": operator,
            "action": action,
            "source_host": source_host,
            "target_host": target_host,
            "tool_name": tool_name,
            "notes": notes,
            "timestamp": now
        }

        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO tasks (
                    project_id, task_name, task_type, status, parameters_json, result_json, completed_at, created_at
                )
                VALUES (?, ?, 'operator_activity', 'completed', ?, ?, ?, ?)
                """,
                (
                    project_id, f"Activity: {action} ({tool_name})",
                    json.dumps({"operator": operator, "tool": tool_name}),
                    json.dumps(details_obj), now, now
                )
            )
            act_id = cursor.lastrowid or 0

        self.db.log_audit(
            event_type="OPERATOR_ACTIVITY",
            action=action,
            actor=operator,
            target=target_host,
            details=f"Tool: {tool_name}, Source: {source_host}",
            status="success"
        )
        logger.info("Logged activity #%d by %s: %s -> %s via %s", act_id, operator, action, target_host, tool_name)
        return act_id

    def list_activities(self, project_id: int, limit: int = 50) -> list[dict[str, Any]]:
        """List operator activities chronologically."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, project_id, task_name, result_json, completed_at, created_at
                FROM tasks
                WHERE project_id = ? AND task_type = 'operator_activity'
                ORDER BY id DESC
                LIMIT ?
                """,
                (project_id, limit)
            )
            rows = cursor.fetchall()

        results = []
        for r in rows:
            d = dict(r)
            try:
                d["details"] = json.loads(d.get("result_json") or "{}")
            except json.JSONDecodeError:
                d["details"] = {}
            results.append(d)
        return results
