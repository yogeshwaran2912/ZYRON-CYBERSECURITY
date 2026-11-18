"""
ZYRON - Lightweight Job Scheduler
Lightweight scheduling system optimized for 8 GB RAM systems without heavy daemon background processes.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Callable

from core.database import DatabaseManager, get_db
from core.logger import get_logger

logger = get_logger("automation.scheduler")


class LightweightScheduler:
    """Manages scheduled security assessment routines without background daemon overhead."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()

    def register_scheduled_job(
        self,
        project_id: int,
        job_name: str,
        frequency: str,
        target: str,
        routine_name: str
    ) -> int:
        """Register a planned recurring security check (e.g., daily, weekly, manual)."""
        now = datetime.now(timezone.utc).isoformat()
        freq = frequency.strip().lower()
        if freq not in ("daily", "weekly", "manual"):
            freq = "manual"

        params = {
            "frequency": freq,
            "target": target,
            "routine_name": routine_name,
            "last_run": None
        }

        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO tasks (project_id, task_name, task_type, status, parameters_json, created_at)
                VALUES (?, ?, 'scheduled_job', 'registered', ?, ?)
                """,
                (project_id, job_name, json.dumps(params), now)
            )
            job_id = cursor.lastrowid or 0

        logger.info("Registered scheduled job #%d: '%s' [%s]", job_id, job_name, freq)
        return job_id

    def list_scheduled_jobs(self, project_id: int) -> list[dict[str, Any]]:
        """List all configured scheduled jobs."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, project_id, task_name, status, parameters_json, created_at
                FROM tasks
                WHERE project_id = ? AND task_type = 'scheduled_job'
                ORDER BY id ASC
                """,
                (project_id,)
            )
            rows = cursor.fetchall()

        results = []
        for r in rows:
            d = dict(r)
            try:
                d["config"] = json.loads(d.get("parameters_json") or "{}")
            except json.JSONDecodeError:
                d["config"] = {}
            results.append(d)
        return results
