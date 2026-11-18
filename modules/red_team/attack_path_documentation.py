"""
ZYRON - Red Team Attack Path Documentation
Methodological tracking of assessment stages mapped to the Cyber Kill Chain and MITRE ATT&CK.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from core.database import DatabaseManager, get_db
from core.logger import get_logger

logger = get_logger("red_team.attack_path")

RED_TEAM_PHASES = [
    "Reconnaissance",
    "Enumeration",
    "Initial Access Assessment",
    "Privilege Escalation Assessment",
    "Lateral Movement Assessment",
    "Persistence Assessment",
    "Detection Validation",
    "Reporting"
]


class AttackPathTracker:
    """Documents simulated attack paths and defense detection opportunities."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()

    def record_attack_step(
        self,
        project_id: int,
        phase: str,
        step_name: str,
        technique_id: str,
        target_asset: str,
        success: bool,
        observations: str,
        defensive_indicators: str
    ) -> int:
        """Record an evaluated attack step within the engagement."""
        now = datetime.now(timezone.utc).isoformat()
        metadata = {
            "phase": phase,
            "technique_id": technique_id,
            "target_asset": target_asset,
            "outcome": "success" if success else "blocked_or_prevented",
            "observations": observations,
            "defensive_indicators": defensive_indicators
        }

        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO tasks (project_id, task_name, task_type, status, parameters_json, result_json, completed_at, created_at)
                VALUES (?, ?, 'attack_path_step', ?, ?, ?, ?, ?)
                """,
                (
                    project_id, f"[{technique_id}] {step_name}",
                    "completed" if success else "failed",
                    json.dumps({"phase": phase, "technique": technique_id, "target": target_asset}),
                    json.dumps(metadata), now, now
                )
            )
            step_id = cursor.lastrowid or 0

        logger.info("Recorded attack step #%d: [%s] %s (%s)", step_id, technique_id, step_name, phase)
        return step_id

    def list_attack_steps(self, project_id: int) -> list[dict[str, Any]]:
        """List all recorded attack steps for the project."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, project_id, task_name, status, parameters_json, result_json, created_at
                FROM tasks
                WHERE project_id = ? AND task_type = 'attack_path_step'
                ORDER BY id ASC
                """,
                (project_id,)
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
