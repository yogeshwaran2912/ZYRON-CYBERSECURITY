"""
ZYRON - Bug Bounty DNS Reconnaissance
Safe, scope-verified DNS resolution and record mapping.
"""

from __future__ import annotations

from datetime import datetime, timezone
import socket
from typing import Any

from core.database import DatabaseManager, get_db
from core.exceptions import ScopeViolationError, ValidationError
from core.logger import get_logger
from core.scope_manager import ScopeManager
from core.validators import validate_domain
from modules.bug_bounty.asset_inventory import AssetInventory

logger = get_logger("bug_bounty.dns")


class DNSRecon:
    """Performs DNS resolution on authorized domains and stores discovered IP assets."""

    def __init__(
        self,
        db: DatabaseManager | None = None,
        scope_manager: ScopeManager | None = None,
        inventory: AssetInventory | None = None
    ) -> None:
        self.db = db or get_db()
        self.scope_manager = scope_manager or ScopeManager(self.db)
        self.inventory = inventory or AssetInventory(self.db)

    def resolve_domain(self, project_id: int, domain: str) -> dict[str, Any]:
        """
        Resolve IPv4 and IPv6 addresses for an authorized domain.
        Enforces scope authorization prior to performing DNS resolution.
        """
        valid_domain = validate_domain(domain)

        # Enforce Scope: Raises ScopeViolationError if unauthorized
        self.scope_manager.verify_scope_or_raise(project_id, valid_domain)

        discovered_ips: list[str] = []
        cnames: list[str] = []

        try:
            # Query standard address info
            addr_info = socket.getaddrinfo(valid_domain, None)
            for item in addr_info:
                ip = item[4][0]
                if ip not in discovered_ips:
                    discovered_ips.append(ip)

            # Attempt canonical name lookup
            try:
                host_info = socket.gethostbyname_ex(valid_domain)
                for alias in host_info[1]:
                    if alias not in cnames:
                        cnames.append(alias)
            except (socket.herror, socket.gaierror):
                pass

        except socket.gaierror as e:
            logger.warning("DNS resolution failed for %s: %s", valid_domain, e)
            return {
                "domain": valid_domain,
                "status": "unresolved",
                "error": str(e),
                "ips": [],
                "cnames": []
            }

        # Store resolved domain and IPs in inventory
        self.inventory.add_asset(
            project_id=project_id,
            asset_type="domain",
            asset_value=valid_domain,
            category="target_domain",
            status="active",
            metadata={"ips": discovered_ips, "cnames": cnames}
        )

        for ip in discovered_ips:
            self.inventory.add_asset(
                project_id=project_id,
                asset_type="ip",
                asset_value=ip,
                category="dns_resolved",
                status="active",
                metadata={"associated_domain": valid_domain}
            )

        self.db.log_audit(
            event_type="DNS_RECON",
            action="RESOLVE_DOMAIN",
            target=valid_domain,
            details=f"Discovered {len(discovered_ips)} IPs: {', '.join(discovered_ips)}",
            status="success"
        )

        logger.info("DNS Recon completed for %s: %d IPs discovered", valid_domain, len(discovered_ips))
        return {
            "domain": valid_domain,
            "status": "resolved",
            "ips": discovered_ips,
            "cnames": cnames,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
