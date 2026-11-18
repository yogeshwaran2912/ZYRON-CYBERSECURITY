"""
Tests for ZYRON Scope and Authorization Manager
Validates Default DENY policy, domain/subdomain checks, CIDR matching, and explicit exclusions.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from core.database import DatabaseManager
from core.exceptions import ScopeViolationError, ValidationError
from core.scope_manager import ScopeManager


@pytest.fixture
def scope_setup(tmp_path: Path) -> tuple[DatabaseManager, ScopeManager, int]:
    """Provide a fresh database with a test project and ScopeManager."""
    db_file = tmp_path / "test_scope.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()
    project_id = db.create_project("Scope Test Project", "bug_bounty", "Testing scope logic")
    mgr = ScopeManager(db)
    return db, mgr, project_id


def test_default_deny_policy(scope_setup: tuple[DatabaseManager, ScopeManager, int]) -> None:
    """Verify that any target is denied if no scope rules are configured."""
    _, mgr, pid = scope_setup
    allowed, reason = mgr.is_in_scope(pid, "example.com")
    assert not allowed
    assert "DEFAULT" in reason.upper() or "DENY" in reason.upper()

    with pytest.raises(ScopeViolationError):
        mgr.verify_scope_or_raise(pid, "example.com")


def test_authorized_domain_and_subdomain(scope_setup: tuple[DatabaseManager, ScopeManager, int]) -> None:
    """Verify authorized domains match both exact domain and subdomains."""
    _, mgr, pid = scope_setup
    mgr.add_scope_target(pid, "domain", "authorized-target.org")

    # Exact match
    allowed, _ = mgr.is_in_scope(pid, "authorized-target.org")
    assert allowed

    # Subdomain match
    allowed, _ = mgr.is_in_scope(pid, "api.authorized-target.org")
    assert allowed

    # Unrelated target
    allowed, _ = mgr.is_in_scope(pid, "attacker.org")
    assert not allowed


def test_explicit_exclusion_takes_precedence(scope_setup: tuple[DatabaseManager, ScopeManager, int]) -> None:
    """Verify that an explicit exclusion blocks a target even if the parent domain is authorized."""
    _, mgr, pid = scope_setup
    # Authorize wildcard parent domain
    mgr.add_scope_target(pid, "domain", "secure-corp.com", is_excluded=False)
    # Explicitly exclude internal portal
    mgr.add_scope_target(pid, "domain", "internal.secure-corp.com", is_excluded=True)

    # Allowed: normal subdomain
    allowed, _ = mgr.is_in_scope(pid, "public.secure-corp.com")
    assert allowed

    # Blocked: explicitly excluded asset
    allowed, reason = mgr.is_in_scope(pid, "internal.secure-corp.com")
    assert not allowed
    assert "EXCLUSION" in reason.upper()


def test_cidr_range_matching(scope_setup: tuple[DatabaseManager, ScopeManager, int]) -> None:
    """Verify that IP addresses within authorized CIDR are permitted."""
    _, mgr, pid = scope_setup
    mgr.add_scope_target(pid, "cidr", "10.0.0.0/24")

    # In range
    allowed, _ = mgr.is_in_scope(pid, "10.0.0.45")
    assert allowed

    # Out of range
    allowed, _ = mgr.is_in_scope(pid, "10.0.1.1")
    assert not allowed
