"""
ZYRON Cybersecurity Framework - Central Scope & Authorization Manager
Default Policy: DENY unless explicitly authorized.
Blocks any out-of-scope or excluded targets before security actions are performed.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
from typing import Any
from urllib.parse import urlparse

from core.database import DatabaseManager, get_db
from core.exceptions import ScopeViolationError, ValidationError
from core.logger import get_logger
from core.validators import validate_cidr, validate_domain, validate_ip

logger = get_logger("scope_manager")


class ScopeManager:
    """Enforces authorization boundaries and default-deny scope policies."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()

    def add_scope_target(
        self,
        project_id: int,
        target_type: str,
        target_value: str,
        is_excluded: bool = False,
        description: str = "",
        expires_at: str | None = None
    ) -> int:
        """Register an authorized or explicitly excluded target under a project."""
        target_type = target_type.strip().lower()
        target_value = target_value.strip().lower()

        # Validate format based on target_type
        if target_type == "ip":
            target_value = validate_ip(target_value)
        elif target_type == "cidr":
            target_value = validate_cidr(target_value)
        elif target_type in ("domain", "subdomain"):
            target_value = validate_domain(target_value)
        elif target_type == "url":
            parsed = urlparse(target_value)
            if not parsed.hostname:
                raise ValidationError(f"Invalid URL for scope: '{target_value}'")
        else:
            raise ValidationError(f"Unsupported target_type: '{target_type}'. Must be ip, cidr, domain, or url.")

        now = datetime.now(timezone.utc).isoformat()
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scopes (project_id, target_type, target_value, is_excluded, description, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, target_type, target_value) DO UPDATE SET
                    is_excluded = excluded.is_excluded,
                    description = excluded.description,
                    expires_at = excluded.expires_at
                """,
                (project_id, target_type, target_value, 1 if is_excluded else 0, description, expires_at, now)
            )
            scope_id = cursor.lastrowid or 0

        action = "EXCLUDE_TARGET" if is_excluded else "AUTHORIZE_TARGET"
        self.db.log_audit(
            event_type="SCOPE_CONFIG",
            action=action,
            target=target_value,
            details=f"Project ID: {project_id}, Type: {target_type}",
            status="success"
        )
        logger.info("Configured %s rule for target '%s' (Project ID: %d)", action, target_value, project_id)
        return scope_id

    def list_scopes(self, project_id: int) -> list[dict[str, Any]]:
        """Retrieve all active scope rules for a project."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, project_id, target_type, target_value, is_excluded, description, expires_at, created_at
                FROM scopes
                WHERE project_id = ?
                ORDER BY is_excluded DESC, id ASC
                """,
                (project_id,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def is_in_scope(self, project_id: int, target: str) -> tuple[bool, str]:
        """
        Evaluate if a target is authorized within project scope.
        Returns: (is_allowed: bool, reason: str)
        Default Policy: DENY unless explicitly matched in authorized rules.
        """
        raw_target = target.strip().lower()

        # If a full URL is passed, extract the hostname / IP
        if "://" in raw_target:
            parsed = urlparse(raw_target)
            target_host = parsed.hostname or raw_target
        else:
            target_host = raw_target.split("/")[0].split(":")[0]

        scopes = self.list_scopes(project_id)
        if not scopes:
            return False, "No scope rules registered for project (Default Policy: DENY)"

        # Check for scope expiration
        now_iso = datetime.now(timezone.utc).isoformat()

        # Step 1: Check Explicit Exclusions FIRST
        for s in scopes:
            if s["is_excluded"]:
                if self._matches_rule(target_host, s["target_type"], s["target_value"]):
                    return False, f"Target matches explicit EXCLUSION rule: {s['target_value']}"

        # Step 2: Check Authorized Inclusions
        matched_rule = None
        for s in scopes:
            if not s["is_excluded"]:
                # Expiry check
                if s["expires_at"] and s["expires_at"] < now_iso:
                    continue
                if self._matches_rule(target_host, s["target_type"], s["target_value"]):
                    matched_rule = s
                    break

        if matched_rule:
            return True, f"Target matches authorized rule: {matched_rule['target_value']} ({matched_rule['target_type']})"

        return False, "Target not present in authorized scope list (Default Policy: DENY)"

    def verify_scope_or_raise(self, project_id: int, target: str) -> None:
        """Validate scope or immediately raise ScopeViolationError and log audit block."""
        allowed, reason = self.is_in_scope(project_id, target)
        if not allowed:
            self.db.log_audit(
                event_type="SCOPE_VIOLATION_BLOCKED",
                action="DENY_ACCESS",
                target=target,
                details=f"Project ID: {project_id} - Reason: {reason}",
                status="denied"
            )
            logger.warning("BLOCKED unauthorized target '%s' on project %d: %s", target, project_id, reason)
            raise ScopeViolationError(f"Access to '{target}' denied by Scope Manager: {reason}")
        
        self.db.log_audit(
            event_type="SCOPE_CHECK",
            action="PERMIT_ACCESS",
            target=target,
            details=f"Project ID: {project_id} - {reason}",
            status="success"
        )

    def _matches_rule(self, target: str, rule_type: str, rule_value: str) -> bool:
        """Helper to match a given target against a scope entry."""
        rule_value = rule_value.lower()
        if rule_type in ("domain", "subdomain"):
            # Exact domain match or sub-domain match
            if target == rule_value:
                return True
            if target.endswith("." + rule_value):
                return True
            return False

        if rule_type == "ip":
            return target == rule_value

        if rule_type == "cidr":
            try:
                ip_obj = ipaddress.ip_address(target)
                net_obj = ipaddress.ip_network(rule_value, strict=False)
                return ip_obj in net_obj
            except ValueError:
                return False

        if rule_type == "url":
            parsed_rule = urlparse(rule_value)
            return target == (parsed_rule.hostname or rule_value).lower()

        return False
