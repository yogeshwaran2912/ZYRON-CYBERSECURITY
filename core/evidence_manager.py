"""
ZYRON Cybersecurity Framework - Central Evidence Manager
Manages cryptographic evidence records, SHA-256 integrity verification, and local storage.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

from core.database import DatabaseManager, get_db
from core.exceptions import EvidenceError
from core.logger import get_logger

logger = get_logger("evidence_manager")


class EvidenceManager:
    """Handles evidence collection, local persistence, finding association, and cryptographic hashing."""

    def __init__(self, db: DatabaseManager | None = None, evidence_dir: Path | None = None) -> None:
        self.db = db or get_db()
        if evidence_dir is None:
            project_root = Path(__file__).resolve().parent.parent
            self.evidence_dir = project_root / "evidence"
        else:
            self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def calculate_sha256(data: bytes | str) -> str:
        """Compute SHA-256 cryptographic hash of data string or bytes."""
        hasher = hashlib.sha256()
        if isinstance(data, str):
            hasher.update(data.encode("utf-8"))
        else:
            hasher.update(data)
        return hasher.hexdigest()

    def record_text_evidence(
        self,
        project_id: int,
        title: str,
        content: str,
        finding_id: int | None = None,
        description: str = "",
        evidence_type: str = "text"
    ) -> int:
        """Store text, JSON, or CSV evidence and log its cryptographic fingerprint."""
        now = datetime.now(timezone.utc).isoformat()
        sha256_hash = self.calculate_sha256(content)

        # Persist copy to local evidence folder with timestamped filename
        safe_name = f"evidence_p{project_id}_{int(datetime.now(timezone.utc).timestamp())}.txt"
        file_path = self.evidence_dir / safe_name
        try:
            file_path.write_text(content, encoding="utf-8")
        except OSError as e:
            raise EvidenceError(f"Failed to persist evidence file to disk: {e}") from e

        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO evidence (project_id, finding_id, title, evidence_type, content_or_path, sha256_hash, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (project_id, finding_id, title, evidence_type, str(file_path), sha256_hash, description, now)
            )
            evidence_id = cursor.lastrowid or 0

        self.db.log_audit(
            event_type="EVIDENCE_RECORDED",
            action="CREATE_EVIDENCE",
            details=f"Title: {title}, SHA-256: {sha256_hash[:12]}...",
            target=str(file_path),
            status="success"
        )
        logger.info("Recorded %s evidence (ID: %d) with SHA-256: %s", evidence_type, evidence_id, sha256_hash)
        return evidence_id

    def record_file_reference(
        self,
        project_id: int,
        title: str,
        file_path_str: str,
        finding_id: int | None = None,
        description: str = "",
        evidence_type: str = "screenshot_ref"
    ) -> int:
        """Register a binary file or screenshot evidence with SHA-256 verification."""
        path = Path(file_path_str)
        if not path.is_file():
            raise EvidenceError(f"Evidence target file not found: {file_path_str}")

        try:
            file_bytes = path.read_bytes()
            sha256_hash = self.calculate_sha256(file_bytes)
        except OSError as e:
            raise EvidenceError(f"Failed to read evidence file: {e}") from e

        now = datetime.now(timezone.utc).isoformat()
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO evidence (project_id, finding_id, title, evidence_type, content_or_path, sha256_hash, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (project_id, finding_id, title, evidence_type, str(path.resolve()), sha256_hash, description, now)
            )
            evidence_id = cursor.lastrowid or 0

        self.db.log_audit(
            event_type="EVIDENCE_REGISTERED",
            action="REGISTER_FILE_EVIDENCE",
            details=f"Title: {title}, SHA-256: {sha256_hash[:12]}...",
            target=str(path.resolve()),
            status="success"
        )
        return evidence_id

    def verify_evidence_integrity(self, evidence_id: int) -> tuple[bool, str]:
        """
        Check that evidence has not been tampered with or modified on disk.
        Returns: (is_valid: bool, status_message: str)
        """
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, title, evidence_type, content_or_path, sha256_hash
                FROM evidence
                WHERE id = ?
                """,
                (evidence_id,)
            )
            row = cursor.fetchone()

        if not row:
            return False, f"Evidence record #{evidence_id} not found."

        stored_hash = row["sha256_hash"]
        target_path = Path(row["content_or_path"])

        if not target_path.exists():
            return False, f"Evidence file missing at: {target_path}"

        try:
            current_bytes = target_path.read_bytes()
            current_hash = self.calculate_sha256(current_bytes)
        except OSError as e:
            return False, f"Error reading evidence file: {e}"

        if current_hash.lower() == stored_hash.lower():
            return True, f"Cryptographic integrity verified. Hash matches: {current_hash[:16]}..."
        else:
            return False, f"INTEGRITY VIOLATION: Stored={stored_hash[:16]}... Current={current_hash[:16]}..."

    def list_evidence(self, project_id: int, finding_id: int | None = None) -> list[dict[str, Any]]:
        """List evidence records for a project or specific finding."""
        with self.db.get_connection() as conn:
            if finding_id is not None:
                cursor = conn.execute(
                    """
                    SELECT id, project_id, finding_id, title, evidence_type, content_or_path, sha256_hash, description, created_at
                    FROM evidence
                    WHERE project_id = ? AND finding_id = ?
                    ORDER BY id DESC
                    """,
                    (project_id, finding_id)
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT id, project_id, finding_id, title, evidence_type, content_or_path, sha256_hash, description, created_at
                    FROM evidence
                    WHERE project_id = ?
                    ORDER BY id DESC
                    """,
                    (project_id,)
                )
            return [dict(row) for row in cursor.fetchall()]
