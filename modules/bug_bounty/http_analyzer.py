"""
ZYRON - Bug Bounty HTTP & Header Security Analyzer
Inspects HTTP security headers, TLS configuration, and server disclosures on authorized targets.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ssl
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from core.database import DatabaseManager, get_db
from core.exceptions import ScopeViolationError, ValidationError
from core.logger import get_logger
from core.scope_manager import ScopeManager
from core.validators import validate_url

logger = get_logger("bug_bounty.http")

RECOMMENDED_SECURITY_HEADERS = [
    ("Strict-Transport-Security", "Enforces HTTPS connections and prevents SSL stripping."),
    ("Content-Security-Policy", "Mitigates Cross-Site Scripting (XSS) and data injection."),
    ("X-Frame-Options", "Protects against Clickjacking framing attacks."),
    ("X-Content-Type-Options", "Prevents MIME-type confusion / sniffing attacks."),
    ("Referrer-Policy", "Controls leakage of referrer information in outgoing requests."),
    ("Permissions-Policy", "Restricts browser feature access (e.g. camera, microphone).")
]


class HTTPAnalyzer:
    """Analyzes web targets for missing security headers, information disclosures, and TLS parameters."""

    def __init__(self, db: DatabaseManager | None = None, scope_manager: ScopeManager | None = None) -> None:
        self.db = db or get_db()
        self.scope_manager = scope_manager or ScopeManager(self.db)

    def analyze_headers(self, project_id: int, target_url: str, timeout: float = 5.0) -> dict[str, Any]:
        """
        Inspect HTTP response headers for an authorized target.
        Enforces scope authorization prior to issuing requests.
        """
        valid_url = validate_url(target_url)

        # Enforce scope check
        self.scope_manager.verify_scope_or_raise(project_id, valid_url)

        logger.info("Analyzing HTTP security headers for %s (Project #%d)", valid_url, project_id)

        req = urllib.request.Request(
            valid_url,
            headers={"User-Agent": "Mozilla/5.0 (ZYRON Security Research Engine v0.1.0)"}
        )
        ctx = ssl.create_default_context()

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                status_code = response.status
                headers = dict(response.headers)
        except urllib.error.HTTPError as e:
            status_code = e.code
            headers = dict(e.headers)
        except Exception as e:
            logger.warning("HTTP connection failed for %s: %s", valid_url, e)
            return {
                "target_url": valid_url,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        # Analyze headers
        present_headers: dict[str, str] = {}
        missing_headers: list[dict[str, str]] = []

        headers_lower = {k.lower(): (k, v) for k, v in headers.items()}

        for header_name, purpose in RECOMMENDED_SECURITY_HEADERS:
            key_lower = header_name.lower()
            if key_lower in headers_lower:
                orig_key, val = headers_lower[key_lower]
                present_headers[orig_key] = val
            else:
                missing_headers.append({"header": header_name, "purpose": purpose})

        # Check for information disclosure headers
        disclosures = {}
        for h in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            if h in headers_lower:
                orig_key, val = headers_lower[h]
                disclosures[orig_key] = val

        security_score = int((len(present_headers) / len(RECOMMENDED_SECURITY_HEADERS)) * 100)

        result = {
            "target_url": valid_url,
            "status": "analyzed",
            "http_status": status_code,
            "security_score_percent": security_score,
            "present_security_headers": present_headers,
            "missing_security_headers": missing_headers,
            "information_disclosure_headers": disclosures,
            "all_headers": headers,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        self.db.log_audit(
            event_type="HTTP_ANALYSIS",
            action="ANALYZE_HEADERS",
            target=valid_url,
            details=f"Score: {security_score}%, Missing: {len(missing_headers)} headers",
            status="success"
        )
        return result
