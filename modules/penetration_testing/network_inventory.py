"""
ZYRON - Penetration Testing Network Inventory
Documents authorized host assets, IP ranges, subnets, and network segmentation notes.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from core.database import DatabaseManager, get_db
from core.exceptions import ValidationError
from core.logger import get_logger
from core.validators import validate_cidr, validate_ip

logger = get_logger("pentest.network")


class NetworkInventory:
    """Manages target network segments, authorized hosts, and routing topology."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()

    def add_network_host(
        self,
        project_id: int,
        ip_address: str,
        hostname: str = "",
        os_fingerprint: str = "",
        segment: str = "internal",
        notes: str = ""
    ) -> int:
        """Register an authorized host target in the penetration test scope."""
        valid_ip = validate_ip(ip_address)
        now = datetime.now(timezone.utc).isoformat()
        metadata = {
            "hostname": hostname,
            "os_fingerprint": os_fingerprint,
            "segment": segment,
            "notes": notes
        }

        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO assets (project_id, asset_type, asset_value, category, status, metadata_json, created_at, updated_at)
                VALUES (?, 'ip', ?, 'pentest_host', 'authorized', ?, ?, ?)
                ON CONFLICT(project_id, asset_type, asset_value) DO UPDATE SET
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (project_id, valid_ip, json.dumps(metadata), now, now)
            )
            return cursor.lastrowid or 0

    def list_network_hosts(self, project_id: int) -> list[dict[str, Any]]:
        """List all network targets recorded for the assessment."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, project_id, asset_type, asset_value, category, status, metadata_json, created_at
                FROM assets
                WHERE project_id = ? AND category = 'pentest_host'
                ORDER BY id ASC
                """,
                (project_id,)
            )
            rows = cursor.fetchall()

        results = []
        for r in rows:
            d = dict(r)
            try:
                d["metadata"] = json.loads(d.get("metadata_json") or "{}")
            except json.JSONDecodeError:
                d["metadata"] = {}
            results.append(d)
        return results
