"""
Tests for ZYRON Central Database Layer
Validates normalized tables, foreign key constraints, transactions, and audit logging.
"""

from __future__ import annotations

import sqlite3
import pytest
from pathlib import Path

from core.database import DatabaseManager
from core.exceptions import DatabaseError


@pytest.fixture
def test_db(tmp_path: Path) -> DatabaseManager:
    """Fixture providing a fresh isolated SQLite database instance."""
    db_file = tmp_path / "test_zyron.db"
    db_mgr = DatabaseManager(db_path=db_file)
    db_mgr.initialize_schema()
    return db_mgr


def test_schema_initialization(test_db: DatabaseManager) -> None:
    """Verify all 11 required tables and indexes exist."""
    required_tables = [
        "users_or_operators",
        "projects",
        "programs",
        "engagements",
        "scopes",
        "assets",
        "findings",
        "evidence",
        "tasks",
        "audit_logs",
        "reports"
    ]
    with test_db.get_connection() as conn:
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row["name"] for row in cursor.fetchall()]

    for t in required_tables:
        assert t in tables, f"Expected table '{t}' was not found in database."


def test_baseline_projects_seeded(test_db: DatabaseManager) -> None:
    """Verify that the 4 baseline domain projects were seeded."""
    projects = test_db.get_projects()
    assert len(projects) >= 4

    module_types = {p["module_type"] for p in projects}
    assert "bug_bounty" in module_types
    assert "red_team" in module_types
    assert "penetration_testing" in module_types
    assert "automation" in module_types


def test_foreign_key_enforcement(test_db: DatabaseManager) -> None:
    """Verify that SQLite foreign key constraints are strictly enforced."""
    with pytest.raises(DatabaseError):
        # Attempt to insert scope for non-existent project_id 99999
        with test_db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scopes (project_id, target_type, target_value, is_excluded, created_at)
                VALUES (99999, 'domain', 'test.com', 0, '2026-01-01T00:00:00')
                """
            )


def test_audit_logging(test_db: DatabaseManager) -> None:
    """Verify audit log records can be stored and retrieved."""
    log_id = test_db.log_audit(
        event_type="TEST_EVENT",
        action="RUN_UNIT_TEST",
        actor="test_runner",
        target="127.0.0.1",
        details="Unit test audit verification",
        status="success"
    )
    assert log_id > 0

    logs = test_db.get_audit_logs(limit=10)
    assert len(logs) >= 1
    assert logs[0]["action"] == "RUN_UNIT_TEST"
    assert logs[0]["actor"] == "test_runner"
    assert logs[0]["target"] == "127.0.0.1"


def test_system_counts(test_db: DatabaseManager) -> None:
    """Verify system entity counts return non-negative integers for all tables."""
    counts = test_db.get_system_counts()
    assert counts["projects"] >= 4
    assert counts["users_or_operators"] >= 1
    assert counts["findings"] == 0
