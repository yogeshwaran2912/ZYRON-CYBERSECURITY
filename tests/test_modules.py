"""
Tests for ZYRON Domain Modules
Validates Bug Bounty, Red Team, Penetration Testing, and Automation module operations.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from core.database import DatabaseManager
from modules.automation.main import AutomationModule
from modules.automation.result_parser import ResultParser
from modules.automation.task_runner import TaskRunner
from modules.bug_bounty.asset_inventory import AssetInventory
from modules.bug_bounty.main import BugBountyModule
from modules.bug_bounty.vulnerability_tracker import VulnerabilityTracker
from modules.penetration_testing.findings import PenetrationTestFindings
from modules.penetration_testing.main import PenetrationTestingModule
from modules.penetration_testing.network_inventory import NetworkInventory
from modules.penetration_testing.service_inventory import ServiceInventory
from modules.red_team.activity_logger import ActivityLogger
from modules.red_team.ad_inventory import ActiveDirectoryInventory
from modules.red_team.attack_path_documentation import AttackPathTracker
from modules.red_team.engagement import EngagementManager
from modules.red_team.main import RedTeamModule


@pytest.fixture
def module_db(tmp_path: Path) -> DatabaseManager:
    """Fixture providing an isolated database instance for module tests."""
    db_file = tmp_path / "test_modules.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()
    return db


def test_module_instantiation(module_db: DatabaseManager) -> None:
    """Verify all four domain module classes instantiate cleanly."""
    bb = BugBountyModule(module_db)
    rt = RedTeamModule(module_db)
    pt = PenetrationTestingModule(module_db)
    auto = AutomationModule(module_db)

    assert bb.get_or_create_default_project() > 0
    assert rt.get_or_create_default_project() > 0
    assert pt.get_or_create_default_project() > 0
    assert auto.get_or_create_default_project() > 0


def test_bug_bounty_workflow(module_db: DatabaseManager) -> None:
    """Verify Bug Bounty asset tracking and vulnerability recording."""
    inv = AssetInventory(module_db)
    tracker = VulnerabilityTracker(module_db)
    pid = module_db.create_project("BB Workflow Test", "bug_bounty")

    # Add asset
    aid = inv.add_asset(pid, "domain", "api.example.com", category="target_api")
    assert aid > 0
    assets = inv.list_assets(pid)
    assert len(assets) == 1
    assert assets[0]["asset_value"] == "api.example.com"

    # Record finding
    fid = tracker.record_finding(
        project_id=pid,
        title="BOLA on /api/user/profile",
        severity="high",
        affected_asset="api.example.com",
        description="IDOR allows accessing other user data",
        reproduction_steps="Change user ID in request body",
        impact="Unauthorized data leakage",
        remediation="Enforce object-level authorization checks",
        validation_status="suspected"
    )
    assert fid > 0
    findings = tracker.list_findings(pid)
    assert len(findings) == 1
    assert findings[0]["validation_status"] == "suspected"

    # Update status to validated
    tracker.update_status(fid, "validated")
    updated = tracker.list_findings(pid)
    assert updated[0]["validation_status"] == "validated"


def test_red_team_engagement_and_attack_path(module_db: DatabaseManager) -> None:
    """Verify Red Team engagement management, AD inventory, and attack paths."""
    eng_mgr = EngagementManager(module_db)
    ad_inv = ActiveDirectoryInventory(module_db)
    attack_mgr = AttackPathTracker(module_db)
    pid = module_db.create_project("Red Team Test", "red_team")

    # Create engagement
    eid = eng_mgr.create_engagement(
        project_id=pid,
        engagement_code="RT-TEST-001",
        organization="Cyber Lab",
        authorization_details="Lab Simulation Approval",
        rules_of_engagement="No real-world destruction; isolated lab only",
        testing_objectives="Test detection for token impersonation"
    )
    assert eid > 0

    # Record Domain Controller
    dc_id = ad_inv.record_domain_controller(pid, "DC01", "192.168.10.10", "lab.local")
    assert dc_id > 0

    # Record Attack Step
    step_id = attack_mgr.record_attack_step(
        project_id=pid,
        phase="Privilege Escalation",
        step_name="PrintSpoofer Token Impersonation",
        technique_id="T1134.001",
        target_asset="WIN-SRV01",
        success=True,
        observations="Elevated from NetworkService to SYSTEM",
        defensive_indicators="Named pipe creation observed in Sysmon Event 17"
    )
    assert step_id > 0
    steps = attack_mgr.list_attack_steps(pid)
    assert len(steps) == 1
    assert steps[0]["task_name"] == "[T1134.001] PrintSpoofer Token Impersonation"


def test_penetration_testing_inventory(module_db: DatabaseManager) -> None:
    """Verify pentest network and service inventory operations."""
    net_inv = NetworkInventory(module_db)
    svc_inv = ServiceInventory(module_db)
    pt_findings = PenetrationTestFindings(module_db)
    pid = module_db.create_project("PT Inventory Test", "penetration_testing")

    # Add network host
    hid = net_inv.add_network_host(pid, "10.0.5.20", hostname="app-db.corp.local")
    assert hid > 0

    # Record service
    sid = svc_inv.record_service(
        project_id=pid,
        host_ip="10.0.5.20",
        port=5432,
        protocol="tcp",
        service_name="postgresql",
        version="PostgreSQL 14.2",
        banner="PostgreSQL 14.2 (Ubuntu 22.04)"
    )
    assert sid > 0
    services = svc_inv.list_services(pid, host_ip="10.0.5.20")
    assert len(services) == 1
    assert services[0]["metadata"]["port"] == 5432

    # Add pentest finding
    fid = pt_findings.add_finding(
        project_id=pid,
        title="Default PostgreSQL Credentials",
        severity="critical",
        affected_asset="10.0.5.20:5432",
        description="Database accessible with postgres:postgres",
        impact="Complete database compromise",
        reproduction_steps="psql -h 10.0.5.20 -U postgres",
        remediation="Change default administrative credentials",
        cvss_score=9.8
    )
    assert fid > 0


def test_automation_task_runner_and_parser(module_db: DatabaseManager) -> None:
    """Verify task runner execution safety and result deduplication."""
    runner = TaskRunner(module_db)
    parser = ResultParser()
    pid = module_db.create_project("Automation Test", "automation")

    # Register and run custom routine
    def mock_security_check(target: str) -> dict[str, str]:
        return {"target": target, "status": "secure"}

    runner.register_routine("mock_check", mock_security_check)
    res = runner.run_task(pid, "mock_check", {"target": "192.168.1.1"})
    assert res["status"] == "completed"
    assert res["result"]["data"]["target"] == "192.168.1.1"

    # Test deduplication
    duplicate_sample = [
        {"affected_asset": "example.com", "title": "Missing HSTS", "severity": "low"},
        {"affected_asset": "example.com", "title": "Missing HSTS", "severity": "low"},
        {"affected_asset": "example.com", "title": "Open Port 22", "severity": "informational"}
    ]
    unique, count = parser.deduplicate_findings(duplicate_sample)
    assert len(unique) == 2
    assert count == 1
