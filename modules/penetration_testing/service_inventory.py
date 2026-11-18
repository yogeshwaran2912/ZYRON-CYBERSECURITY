"""
ZYRON - Penetration Testing Port & Service Inventory
Tracks open ports, service versions, application banners, and TLS capabilities.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from core.database import DatabaseManager, get_db
from core.exceptions import ValidationError
from core.logger import get_logger
from core.validators import validate_port

logger = get_logger("pentest.service")


class ServiceInventory:
    """Documents identified network services, daemon versions, and banners."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()

    def record_service(
        self,
        project_id: int,
        host_ip: str,
        port: int | str,
        protocol: str = "tcp",
        service_name: str = "unknown",
        version: str = "",
        banner: str = ""
    ) -> int:
        """Register an identified listening service on an authorized host."""
        valid_port = validate_port(port)
        protocol = protocol.lower()
        now = datetime.now(timezone.utc).isoformat()
        asset_identifier = f"{host_ip}:{valid_port}/{protocol}"

        metadata = {
            "host_ip": host_ip,
            "port": valid_port,
            "protocol": protocol,
            "service_name": service_name,
            "version": version,
            "banner": banner
        }

        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO assets (project_id, asset_type, asset_value, category, status, metadata_json, created_at, updated_at)
                VALUES (?, 'service', ?, 'network_service', 'open', ?, ?, ?)
                ON CONFLICT(project_id, asset_type, asset_value) DO UPDATE SET
                    metadata_json = excluded.metadata_json,
                    status = excluded.status,
                    updated_at = excluded.updated_at
                """,
                (project_id, asset_identifier, json.dumps(metadata), now, now)
            )
            return cursor.lastrowid or 0

    def list_services(self, project_id: int, host_ip: str | None = None) -> list[dict[str, Any]]:
        """List listening services for a specific host or across the entire assessment."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, project_id, asset_type, asset_value, category, status, metadata_json, created_at
                FROM assets
                WHERE project_id = ? AND category = 'network_service'
                ORDER BY id ASC
                """,
                (project_id,)
            )
            rows = cursor.fetchall()

        results = []
        for r in rows:
            d = dict(r)
            try:
                meta = json.loads(d.get("metadata_json") or "{}")
            except json.JSONDecodeError:
                meta = {}
            if host_ip and meta.get("host_ip") != host_ip:
                continue
            d["metadata"] = meta
            results.append(d)
        return results
