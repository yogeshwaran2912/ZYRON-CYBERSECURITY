"""
ZYRON Cybersecurity Framework - Central Security & Policy Manager
Controls operational dry-run modes, authorization checks, and execution safety rules.
"""

from __future__ import annotations

from typing import Any
import yaml
from pathlib import Path

from core.database import DatabaseManager, get_db
from core.exceptions import AuthorizationError, ConfigurationError
from core.logger import get_logger

logger = get_logger("security_manager")


class SecurityManager:
    """Enforces dry-run state, approval workflow for active tests, and system configuration."""

    def __init__(self, db: DatabaseManager | None = None, config_path: Path | None = None) -> None:
        self.db = db or get_db()
        self.config_path = config_path or Path(__file__).resolve().parent.parent / "config" / "settings.yaml"
        self.settings = self._load_settings()

    def _load_settings(self) -> dict[str, Any]:
        """Load settings from YAML or return secure defaults."""
        if self.config_path.is_file():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                logger.error("Failed to load settings from %s: %s", self.config_path, e)

        # Fallback secure defaults
        return {
            "app": {"name": "ZYRON CYBERSECURITY", "version": "0.1.0"},
            "security": {
                "enforce_scope": True,
                "default_policy": "DENY",
                "require_authorization": True,
                "dry_run_default": True
            }
        }

    @property
    def is_dry_run(self) -> bool:
        """Returns True if framework is operating in non-intrusive dry-run mode."""
        return bool(self.settings.get("security", {}).get("dry_run_default", True))

    def set_dry_run(self, enabled: bool) -> None:
        """Toggle dry-run mode."""
        if "security" not in self.settings:
            self.settings["security"] = {}
        self.settings["security"]["dry_run_default"] = enabled
        self.db.log_audit(
            event_type="SECURITY_CONFIG",
            action="TOGGLE_DRY_RUN",
            details=f"Dry run set to: {enabled}",
            status="success"
        )
        logger.info("Security dry-run mode set to: %s", enabled)

    def verify_active_test_authorized(self, action_description: str, confirmed: bool) -> None:
        """Ensure active security tests receive explicit interactive confirmation."""
        if not confirmed:
            self.db.log_audit(
                event_type="UNAUTHORIZED_ACTION_PREVENTED",
                action="ACTIVE_TEST_REJECTED",
                details=action_description,
                status="denied"
            )
            raise AuthorizationError(
                f"Active testing rejected: explicit confirmation required for '{action_description}'."
            )
        
        self.db.log_audit(
            event_type="ACTIVE_TEST_AUTHORIZED",
            action="CONFIRM_EXECUTION",
            details=action_description,
            status="success"
        )
