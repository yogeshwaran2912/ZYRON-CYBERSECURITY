"""
ZYRON Cybersecurity Framework - Input Validation Layer
Rigorous validation for IPs, CIDRs, domains, URLs, ports, severities, and sanitized inputs.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from core.exceptions import ValidationError

# Regex definitions
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
HOSTNAME_REGEX = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)
SAFE_IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.\s]{1,100}$")

VALID_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
VALID_STATUSES = {"potential", "suspected", "validated", "false_positive", "fixed"}
VALID_MODULE_TYPES = {"bug_bounty", "red_team", "penetration_testing", "automation"}
VALID_TARGET_TYPES = {"domain", "subdomain", "ip", "cidr", "url"}


def validate_ip(ip_str: str) -> str:
    """Validate IPv4 or IPv6 address and return normalized string."""
    ip_str = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return str(ip_obj)
    except ValueError as e:
        raise ValidationError(f"Invalid IP address: '{ip_str}'", details=str(e)) from e


def validate_cidr(cidr_str: str) -> str:
    """Validate IPv4 or IPv6 network in CIDR notation."""
    cidr_str = cidr_str.strip()
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
        return str(network)
    except ValueError as e:
        raise ValidationError(f"Invalid CIDR network: '{cidr_str}'", details=str(e)) from e


def validate_domain(domain: str) -> str:
    """Validate a fully qualified domain name (FQDN)."""
    domain = domain.strip().lower()
    if len(domain) > 253 or not DOMAIN_REGEX.match(domain):
        raise ValidationError(f"Invalid domain name: '{domain}'")
    return domain


def validate_url(url_str: str) -> str:
    """Validate a web URL with http or https protocol."""
    url_str = url_str.strip()
    parsed = urlparse(url_str)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError(f"Invalid URL scheme '{parsed.scheme}'. Only http and https are permitted.")
    if not parsed.netloc:
        raise ValidationError(f"Invalid URL: missing network location in '{url_str}'.")
    return url_str


def validate_port(port: int | str) -> int:
    """Validate network port number (1-65535)."""
    try:
        p = int(port)
        if 1 <= p <= 65535:
            return p
        raise ValidationError(f"Port must be between 1 and 65535. Received: {p}")
    except (ValueError, TypeError) as e:
        raise ValidationError(f"Invalid port value: '{port}'") from e


def validate_severity(severity: str) -> str:
    """Validate vulnerability severity level."""
    normalized = severity.strip().lower()
    if normalized not in VALID_SEVERITIES:
        raise ValidationError(
            f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
        )
    return normalized


def validate_validation_status(status: str) -> str:
    """Validate vulnerability verification status."""
    normalized = status.strip().lower()
    if normalized not in VALID_STATUSES:
        raise ValidationError(
            f"Invalid validation status '{status}'. Must be one of: {', '.join(sorted(VALID_STATUSES))}"
        )
    return normalized


def validate_module_type(module_type: str) -> str:
    """Validate module classification."""
    normalized = module_type.strip().lower()
    if normalized not in VALID_MODULE_TYPES:
        raise ValidationError(
            f"Invalid module type '{module_type}'. Must be one of: {', '.join(sorted(VALID_MODULE_TYPES))}"
        )
    return normalized


def sanitize_text(text: str, max_length: int = 500) -> str:
    """Sanitize general input text, strip dangerous control characters."""
    if not isinstance(text, str):
        return ""
    # Strip null bytes and non-printable control characters (except newline, tab)
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text).strip()
    return sanitized[:max_length]


def sanitize_filename(filename: str) -> str:
    """Ensure a filename contains only alphanumeric characters, dashes, and underscores."""
    filename = filename.strip()
    # Prevent path traversal
    if ".." in filename or "/" in filename or "\\" in filename:
        raise ValidationError("Potential directory traversal detected in filename.")
    clean = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", filename)
    if not clean:
        raise ValidationError("Filename is empty after sanitization.")
    return clean
