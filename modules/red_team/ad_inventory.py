"""
ZYRON - Active Directory Security Lab Inventory
Documents domain architecture, accounts, Kerberos risks, and BloodHound assessment exports.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from core.database import DatabaseManager, get_db
from core.exceptions import ValidationError
from core.logger import get_logger

logger = get_logger("red_team.ad")


class ActiveDirectoryInventory:
    """Manages Active Directory structure, identity auditing, and defensive recommendations."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()

    def record_domain_controller(
        self,
        project_id: int,
        hostname: str,
        ip_address: str,
        domain_name: str,
        os_version: str = "",
        is_global_catalog: bool = True
    ) -> int:
        """Register a Domain Controller asset in the lab environment."""
        now = datetime.now(timezone.utc).isoformat()
        metadata = {
            "domain_name": domain_name,
            "os_version": os_version,
            "is_global_catalog": is_global_catalog,
            "role": "Domain Controller"
        }
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO assets (project_id, asset_type, asset_value, category, status, metadata_json, created_at, updated_at)
                VALUES (?, 'service', ?, 'active_directory_dc', 'verified', ?, ?, ?)
                ON CONFLICT(project_id, asset_type, asset_value) DO UPDATE SET
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (project_id, f"{hostname}.{domain_name}", json.dumps(metadata), now, now)
            )
            return cursor.lastrowid or 0

    def record_ad_misconfiguration(
        self,
        project_id: int,
        title: str,
        category: str,
        affected_object: str,
        mitre_technique: str,
        description: str,
        defensive_recommendation: str
    ) -> int:
        """Document an AD misconfiguration (e.g. Kerberoasting, AS-REP Roasting, Unconstrained Delegation)."""
        now = datetime.now(timezone.utc).isoformat()
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO findings (
                    project_id, title, severity, validation_status, affected_asset,
                    description, reproduction_steps, impact, remediation,
                    references_text, cvss_score, created_at, updated_at
                )
                VALUES (?, ?, 'high', 'validated', ?, ?, ?, ?, ?, ?, 7.5, ?, ?)
                """,
                (
                    project_id, title, affected_object, description,
                    f"Assessment category: {category}",
                    f"Allows unauthorized privilege escalation or credential access ({mitre_technique})",
                    defensive_recommendation, f"MITRE ATT&CK: {mitre_technique}",
                    now, now
                )
            )
            fid = cursor.lastrowid or 0

        logger.info("Recorded AD finding #%d: '%s' on %s", fid, title, affected_object)
        return fid

    def ingest_bloodhound_summary(self, project_id: int, json_path: str | Path) -> dict[str, Any]:
        """Parse BloodHound export JSON summary safely and document attack paths."""
        path = Path(json_path)
        if not path.is_file():
            raise ValidationError(f"BloodHound file not found at {json_path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise ValidationError(f"Invalid BloodHound JSON file: {e}") from e

        # Extract high-level metrics
        meta = data.get("meta", {})
        data_count = data.get("data", [])
        summary = {
            "type": meta.get("type", "unknown"),
            "total_nodes": len(data_count) if isinstance(data_count, list) else 0,
            "source_file": str(path.name)
        }

        self.db.log_audit(
            event_type="BLOODHOUND_INGESTION",
            action="PARSE_AD_DATA",
            target=str(path.name),
            details=f"Type: {summary['type']}, Nodes: {summary['total_nodes']}",
            status="success"
        )
        return summary
