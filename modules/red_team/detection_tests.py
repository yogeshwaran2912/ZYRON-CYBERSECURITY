"""
ZYRON - Red Team Detection Testing
Evaluates defensive detection coverage (EDR, SIEM, Sysmon) against simulated techniques.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from core.database import DatabaseManager, get_db
from core.logger import get_logger

logger = get_logger("red_team.detections")

DETECTION_OUTCOMES = ["detected", "alerted", "blocked", "missed"]


class DetectionTester:
    """Manages purple-team style detection verification against MITRE ATT&CK techniques."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()

    def record_detection_test(
        self,
        project_id: int,
        technique_name: str,
        mitre_id: str,
        simulation_details: str,
        expected_telemetry: str,
        actual_outcome: str,
        detection_source: str,
        remediation_guidance: str
    ) -> int:
        """Record the defensive outcome of a controlled simulation."""
        now = datetime.now(timezone.utc).isoformat()
        outcome = actual_outcome.lower()
        if outcome not in DETECTION_OUTCOMES:
            outcome = "missed"

        test_data = {
            "technique_name": technique_name,
            "mitre_id": mitre_id,
            "simulation_details": simulation_details,
            "expected_telemetry": expected_telemetry,
            "actual_outcome": outcome,
            "detection_source": detection_source,
            "remediation_guidance": remediation_guidance
        }

        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO tasks (
                    project_id, task_name, task_type, status, parameters_json, result_json, completed_at, created_at
                )
                VALUES (?, ?, 'detection_test', ?, ?, ?, ?, ?)
                """,
                (
                    project_id, f"Detection Test: {technique_name} ({mitre_id})",
                    "completed",
                    json.dumps({"mitre_id": mitre_id, "source": detection_source}),
                    json.dumps(test_data), now, now
                )
            )
            test_id = cursor.lastrowid or 0

        self.db.log_audit(
            event_type="DETECTION_TEST_LOGGED",
            action="RECORD_DETECTION_TEST",
            target=mitre_id,
            details=f"Technique: {technique_name}, Outcome: {outcome.upper()}",
            status="success"
        )
        logger.info("Recorded detection test #%d: %s (%s) -> %s", test_id, technique_name, mitre_id, outcome)
        return test_id

    def list_detection_tests(self, project_id: int) -> list[dict[str, Any]]:
        """Retrieve all recorded detection evaluation results."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, project_id, task_name, parameters_json, result_json, completed_at, created_at
                FROM tasks
                WHERE project_id = ? AND task_type = 'detection_test'
                ORDER BY id DESC
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
