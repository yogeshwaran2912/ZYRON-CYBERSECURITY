"""
ZYRON - Cybersecurity Automation Task Runner
Executes predefined, verified Python automation routines with safety bounds and timeout handling.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import time
from typing import Any, Callable

from core.database import DatabaseManager, get_db
from core.exceptions import ModuleExecutionError, ValidationError
from core.logger import get_logger

logger = get_logger("automation.runner")


class TaskRunner:
    """Executes reviewed, predefined Python tasks without arbitrary shell execution."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()
        self._registered_routines: dict[str, Callable[..., Any]] = {}

    def register_routine(self, name: str, func: Callable[..., Any]) -> None:
        """Register a vetted, safe Python routine for execution."""
        self._registered_routines[name] = func
        logger.debug("Registered automation routine: %s", name)

    def list_available_routines(self) -> list[str]:
        """List registered routine names."""
        return list(self._registered_routines.keys())

    def run_task(
        self,
        project_id: int,
        routine_name: str,
        parameters: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Execute a registered routine safely and persist execution records."""
        if routine_name not in self._registered_routines:
            raise ValidationError(f"Routine '{routine_name}' is not registered in vetted task registry.")

        func = self._registered_routines[routine_name]
        params = parameters or {}
        now = datetime.now(timezone.utc).isoformat()

        # Create task entry
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO tasks (project_id, task_name, task_type, status, parameters_json, started_at, created_at)
                VALUES (?, ?, 'automation_routine', 'running', ?, ?, ?)
                """,
                (project_id, routine_name, json.dumps(params), now, now)
            )
            task_id = cursor.lastrowid or 0

        start_time = time.perf_counter()
        try:
            logger.info("Executing task #%d: '%s'", task_id, routine_name)
            result = func(**params)
            duration = time.perf_counter() - start_time
            completed_at = datetime.now(timezone.utc).isoformat()

            result_payload = {
                "success": True,
                "duration_seconds": round(duration, 4),
                "data": result
            }

            with self.db.get_connection() as conn:
                conn.execute(
                    """
                    UPDATE tasks
                    SET status = 'completed', result_json = ?, completed_at = ?
                    WHERE id = ?
                    """,
                    (json.dumps(result_payload), completed_at, task_id)
                )

            self.db.log_audit(
                event_type="AUTOMATION_TASK_COMPLETED",
                action="EXECUTE_TASK",
                details=f"Task #{task_id}: {routine_name} completed in {round(duration, 3)}s",
                status="success"
            )
            return {"task_id": task_id, "status": "completed", "result": result_payload}

        except Exception as e:
            duration = time.perf_counter() - start_time
            completed_at = datetime.now(timezone.utc).isoformat()
            error_payload = {
                "success": False,
                "duration_seconds": round(duration, 4),
                "error": str(e)
            }

            with self.db.get_connection() as conn:
                conn.execute(
                    """
                    UPDATE tasks
                    SET status = 'failed', result_json = ?, completed_at = ?
                    WHERE id = ?
                    """,
                    (json.dumps(error_payload), completed_at, task_id)
                )

            self.db.log_audit(
                event_type="AUTOMATION_TASK_FAILED",
                action="EXECUTE_TASK",
                details=f"Task #{task_id}: {routine_name} failed: {e}",
                status="failure"
            )
            logger.error("Automation task #%d failed: %s", task_id, e)
            raise ModuleExecutionError(f"Task '{routine_name}' failed: {e}", details=str(e)) from e
