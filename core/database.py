"""
ZYRON Cybersecurity Framework - Central Database Layer
SQLite normalized schema with foreign keys, transactions, and parameterized queries.
"""

from __future__ import annotations

import contextlib
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Generator, Sequence

from core.exceptions import DatabaseError
from core.logger import get_logger

logger = get_logger("database")

DEFAULT_DB_REL_PATH = Path("database") / "zyron.db"


class DatabaseManager:
    """Manages SQLite database connections, transactions, schema initialization and migrations."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            project_root = Path(__file__).resolve().parent.parent
            self.db_path = project_root / DEFAULT_DB_REL_PATH
        else:
            self.db_path = Path(db_path)

        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextlib.contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager yielding a SQLite connection with foreign keys and WAL enabled."""
        conn = None
        try:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=20.0,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            yield conn
            conn.commit()
        except sqlite3.Error as e:
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            logger.error("Database transaction error: %s", e)
            raise DatabaseError(f"Database operation failed: {e}", details=str(e)) from e
        finally:
            if conn:
                conn.close()

    def initialize_schema(self) -> None:
        """Create all 11 required normalized tables and required indexes."""
        logger.info("Initializing ZYRON central database schema at %s", self.db_path)

        ddl_statements = [
            # 1. users_or_operators
            """
            CREATE TABLE IF NOT EXISTS users_or_operators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL
            );
            """,

            # 2. projects
            """
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                module_type TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """,

            # 3. programs (Bug Bounty)
            """
            CREATE TABLE IF NOT EXISTS programs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                organization TEXT NOT NULL,
                scope_description TEXT,
                testing_restrictions TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """,

            # 4. engagements (Red Team / Pentest)
            """
            CREATE TABLE IF NOT EXISTS engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                engagement_code TEXT UNIQUE NOT NULL,
                organization TEXT NOT NULL,
                authorization_details TEXT NOT NULL,
                start_date TEXT,
                end_date TEXT,
                rules_of_engagement TEXT,
                testing_objectives TEXT,
                status TEXT NOT NULL DEFAULT 'planned',
                created_at TEXT NOT NULL
            );
            """,

            # 5. scopes
            """
            CREATE TABLE IF NOT EXISTS scopes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                target_type TEXT NOT NULL,
                target_value TEXT NOT NULL,
                is_excluded INTEGER NOT NULL DEFAULT 0,
                description TEXT,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(project_id, target_type, target_value)
            );
            """,

            # 6. assets
            """
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                asset_type TEXT NOT NULL,
                asset_value TEXT NOT NULL,
                category TEXT DEFAULT 'general',
                status TEXT NOT NULL DEFAULT 'discovered',
                metadata_json TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(project_id, asset_type, asset_value)
            );
            """,

            # 7. findings
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                validation_status TEXT NOT NULL DEFAULT 'potential',
                affected_asset TEXT NOT NULL,
                description TEXT,
                reproduction_steps TEXT,
                impact TEXT,
                remediation TEXT,
                references_text TEXT,
                cvss_score REAL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """,

            # 8. evidence
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
                title TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                content_or_path TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL
            );
            """,

            # 9. tasks
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
                task_name TEXT NOT NULL,
                task_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                parameters_json TEXT DEFAULT '{}',
                result_json TEXT DEFAULT '{}',
                started_at TEXT,
                completed_at TEXT,
                created_at TEXT NOT NULL
            );
            """,

            # 10. audit_logs
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                details TEXT,
                target TEXT,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            """,

            # 11. reports
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                report_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                summary TEXT,
                created_at TEXT NOT NULL
            );
            """,

            # Indexes for performance
            "CREATE INDEX IF NOT EXISTS idx_projects_module_type ON projects(module_type);",
            "CREATE INDEX IF NOT EXISTS idx_scopes_project ON scopes(project_id);",
            "CREATE INDEX IF NOT EXISTS idx_assets_project ON assets(project_id);",
            "CREATE INDEX IF NOT EXISTS idx_findings_project_sev ON findings(project_id, severity);",
            "CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);",
            "CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);",
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);"
        ]

        with self.get_connection() as conn:
            for statement in ddl_statements:
                conn.execute(statement)

        # Seed initial operator and baseline projects
        self._seed_initial_data()
        logger.info("Database schema initialized and verified successfully.")

    def _seed_initial_data(self) -> None:
        """Seed default operator and baseline projects for each domain."""
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            # Seed operator
            conn.execute(
                """
                INSERT OR IGNORE INTO users_or_operators (username, role, status, created_at)
                VALUES (?, ?, ?, ?)
                """,
                ("analyst", "Lead Security Engineer", "active", now)
            )

            # Seed 4 foundational project records (one per cybersecurity domain)
            baseline_projects = [
                (
                    "Default Bug Bounty Workspace",
                    "bug_bounty",
                    "Standard workspace for authorized bug bounty research programs, scope tracking, and asset discovery."
                ),
                (
                    "Authorized Red Team Lab",
                    "red_team",
                    "Controlled lab engagement workspace for Active Directory simulation, MITRE ATT&CK mapping, and detection tests."
                ),
                (
                    "Internal Penetration Test Workspace",
                    "penetration_testing",
                    "Authorized internal network and web assessment workspace with port, service, and vulnerability documentation."
                ),
                (
                    "Security Automation Hub",
                    "automation",
                    "Central task runner and automated workflow workspace for verified Python security routines."
                )
            ]

            for name, module_type, desc in baseline_projects:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO projects (name, module_type, description, status, created_at, updated_at)
                    VALUES (?, ?, ?, 'active', ?, ?)
                    """,
                    (name, module_type, desc, now, now)
                )

    # Reusable query helpers

    def log_audit(
        self,
        event_type: str,
        action: str,
        actor: str = "analyst",
        details: str | None = None,
        target: str | None = None,
        status: str = "success"
    ) -> int:
        """Record an audit trail event directly into SQLite."""
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_logs (event_type, action, actor, details, target, status, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (event_type, action, actor, details, target, status, now)
            )
            return cursor.lastrowid

    def get_audit_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve recent audit logs in descending order."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, event_type, action, actor, details, target, status, timestamp
                FROM audit_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_projects(self, module_type: str | None = None) -> list[dict[str, Any]]:
        """List all projects or filter by module type."""
        with self.get_connection() as conn:
            if module_type:
                cursor = conn.execute(
                    """
                    SELECT id, name, module_type, description, status, created_at, updated_at
                    FROM projects
                    WHERE module_type = ?
                    ORDER BY id ASC
                    """,
                    (module_type,)
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT id, name, module_type, description, status, created_at, updated_at
                    FROM projects
                    ORDER BY id ASC
                    """
                )
            return [dict(row) for row in cursor.fetchall()]

    def create_project(self, name: str, module_type: str, description: str = "") -> int:
        """Create a new project record."""
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO projects (name, module_type, description, status, created_at, updated_at)
                VALUES (?, ?, ?, 'active', ?, ?)
                """,
                (name, module_type, description, now, now)
            )
            return cursor.lastrowid

    def get_system_counts(self) -> dict[str, int]:
        """Return row counts for all core entities for system dashboard."""
        counts = {}
        tables = [
            "projects", "programs", "engagements", "scopes", "assets",
            "findings", "evidence", "tasks", "audit_logs", "reports", "users_or_operators"
        ]
        with self.get_connection() as conn:
            for table in tables:
                cursor = conn.execute(f"SELECT COUNT(*) AS cnt FROM {table}")
                counts[table] = cursor.fetchone()["cnt"]
        return counts


# Global database manager singleton
_db_instance: DatabaseManager | None = None


def get_db(db_path: str | Path | None = None) -> DatabaseManager:
    """Return the central DatabaseManager singleton instance."""
    global _db_instance
    if _db_instance is None or db_path is not None:
        _db_instance = DatabaseManager(db_path)
    return _db_instance
