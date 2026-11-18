"""
Tests for ZYRON Input Validation Layer
Validates IP, CIDR, domain, URL, port, severity, and sanitization logic.
"""

from __future__ import annotations

import pytest

from core.exceptions import ValidationError
from core.validators import (
    sanitize_filename,
    sanitize_text,
    validate_cidr,
    validate_domain,
    validate_ip,
    validate_port,
    validate_severity,
    validate_url,
    validate_validation_status,
)


def test_ip_validation() -> None:
    """Test IPv4 and IPv6 validation."""
    assert validate_ip("192.168.1.1") == "192.168.1.1"
    assert validate_ip("  10.0.0.1  ") == "10.0.0.1"
    assert validate_ip("::1") == "::1"

    with pytest.raises(ValidationError):
        validate_ip("999.999.999.999")
    with pytest.raises(ValidationError):
        validate_ip("invalid-ip")


def test_cidr_validation() -> None:
    """Test CIDR subnet notation validation."""
    assert validate_cidr("192.168.0.0/24") == "192.168.0.0/24"
    assert validate_cidr("10.0.0.0/8") == "10.0.0.0/8"

    with pytest.raises(ValidationError):
        validate_cidr("192.168.1.1/33")
    with pytest.raises(ValidationError):
        validate_cidr("not-a-cidr")


def test_domain_validation() -> None:
    """Test domain name validation."""
    assert validate_domain("example.com") == "example.com"
    assert validate_domain("Sub.Target-Domain.co.uk") == "sub.target-domain.co.uk"

    with pytest.raises(ValidationError):
        validate_domain("-invalid.com")
    with pytest.raises(ValidationError):
        validate_domain("no_underscores_in_host.com")


def test_url_validation() -> None:
    """Test URL scheme and structure validation."""
    assert validate_url("https://example.com/api") == "https://example.com/api"
    assert validate_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"

    with pytest.raises(ValidationError):
        validate_url("ftp://example.com/file")
    with pytest.raises(ValidationError):
        validate_url("javascript:alert(1)")


def test_port_validation() -> None:
    """Test port boundaries (1-65535)."""
    assert validate_port(80) == 80
    assert validate_port("443") == 443
    assert validate_port(65535) == 65535

    with pytest.raises(ValidationError):
        validate_port(0)
    with pytest.raises(ValidationError):
        validate_port(65536)
    with pytest.raises(ValidationError):
        validate_port("ssh")


def test_severity_validation() -> None:
    """Test vulnerability severity levels."""
    for sev in ("informational", "low", "medium", "high", "critical"):
        assert validate_severity(sev) == sev
        assert validate_severity(sev.upper()) == sev

    with pytest.raises(ValidationError):
        validate_severity("catastrophic")


def test_validation_status() -> None:
    """Test finding verification status lifecycle."""
    for st in ("potential", "suspected", "validated", "false_positive", "fixed"):
        assert validate_validation_status(st) == st

    with pytest.raises(ValidationError):
        validate_validation_status("unverified_unknown")


def test_sanitize_filename_prevents_traversal() -> None:
    """Verify directory traversal is prevented in filename sanitizer."""
    assert sanitize_filename("safe_report-01.txt") == "safe_report-01.txt"

    with pytest.raises(ValidationError):
        sanitize_filename("../../etc/passwd")
    with pytest.raises(ValidationError):
        sanitize_filename("..\\boot.ini")
