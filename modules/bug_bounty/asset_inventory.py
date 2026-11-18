"""
ZYRON - Bug Bounty Asset Inventory
Manages domains, subdomains, IPs, and web service records in SQLite.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from core.database import DatabaseManager, get_db
from core.exceptions import ValidationError
from core.logger import get_logger
from core.validators import validate_domain, validate_ip

logger = get_logger("bug_bounty.assets")


class AssetInventory:
    """Handles asset tracking and categorization for Bug Bounty programs."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()

    def add_asset(
        self,
        project_id: int,
        asset_type: str,
        asset_value: str,
        category: str = "general",
        status: str = "discovered",
        metadata: dict[str, Any] | None = None
    ) -> int:
        """Register an asset within a bug bounty project."""
        asset_type = asset_type.strip().lower()
        asset_value = asset_value.strip().lower()

        if asset_type in ("domain", "subdomain"):
            asset_value = validate_domain(asset_value)
        elif asset_type == "ip":
            asset_value = validate_ip(asset_value)

        now = datetime.now(timezone.utc).isoformat()
        metadata_json = json.dumps(metadata or {})

        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO assets (project_id, asset_type, asset_value, category, status, metadata_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, asset_type, asset_value) DO UPDATE SET
                    category = excluded.category,
                    status = excluded.status,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (project_id, asset_type, asset_value, category, status, metadata_json, now, now)
            )
            asset_id = cursor.lastrowid or 0

        logger.info("Asset recorded: %s (%s) for Project #%d", asset_value, asset_type, project_id)
        return asset_id

    def list_assets(self, project_id: int, asset_type: str | None = None) -> list[dict[str, Any]]:
        """List assets under a project with optional type filter."""
        with self.db.get_connection() as conn:
            if asset_type:
                cursor = conn.execute(
                    """
                    SELECT id, project_id, asset_type, asset_value, category, status, metadata_json, created_at, updated_at
                    FROM assets
                    WHERE project_id = ? AND asset_type = ?
                    ORDER BY id DESC
                    """,
                    (project_id, asset_type.lower())
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT id, project_id, asset_type, asset_value, category, status, metadata_json, created_at, updated_at
                    FROM assets
                    WHERE project_id = ?
                    ORDER BY id DESC
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
