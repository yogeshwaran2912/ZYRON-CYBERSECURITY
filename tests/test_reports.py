"""
Tests for ZYRON Report Engine & Evidence Manager
Validates Markdown, HTML, JSON report rendering and SHA-256 evidence integrity.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from core.database import DatabaseManager
from core.evidence_manager import EvidenceManager
from core.report_engine import ReportEngine


@pytest.fixture
def report_setup(tmp_path: Path) -> tuple[DatabaseManager, ReportEngine, EvidenceManager, int]:
    """Provide a fresh database with ReportEngine and EvidenceManager."""
    db_file = tmp_path / "test_report.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()
    project_id = db.create_project("Reporting Test Project", "bug_bounty", "Testing reports")
    reports_dir = tmp_path / "reports"
    evidence_dir = tmp_path / "evidence"
    r_engine = ReportEngine(db, reports_dir=reports_dir)
    e_mgr = EvidenceManager(db, evidence_dir=evidence_dir)
    return db, r_engine, e_mgr, project_id


def test_markdown_report_generation(report_setup: tuple[DatabaseManager, ReportEngine, EvidenceManager, int]) -> None:
    """Verify Markdown report generation with executive summary and findings."""
    _, r_engine, _, pid = report_setup
    sample_findings = [
        {
            "title": "Cross-Site Scripting in Search Query",
            "severity": "high",
            "validation_status": "validated",
            "affected_asset": "https://test.example.com/search",
            "description": "Reflected XSS identified.",
            "impact": "Account takeover risk.",
            "remediation": "Context-aware HTML encoding.",
            "cvss_score": 7.2
        }
    ]

    path = r_engine.generate_report(
        project_id=pid,
        title="Automated Test Security Assessment",
        organization="Test Corp",
        module_name="Bug Bounty Research",
        executive_summary="Testing automated report generation.",
        findings=sample_findings,
        report_format="markdown"
    )

    assert path.is_file()
    content = path.read_text(encoding="utf-8")
    assert "# Automated Test Security Assessment" in content
    assert "Cross-Site Scripting" in content
    assert "CRITICAL" in content or "HIGH" in content


def test_html_report_generation(report_setup: tuple[DatabaseManager, ReportEngine, EvidenceManager, int]) -> None:
    """Verify HTML report rendering with styled cards and valid HTML doctype."""
    _, r_engine, _, pid = report_setup
    path = r_engine.generate_report(
        project_id=pid,
        title="HTML Security Assessment",
        organization="Test Corp",
        module_name="Penetration Testing",
        executive_summary="HTML layout verification.",
        findings=[],
        report_format="html"
    )

    assert path.is_file()
    content = path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "HTML Security Assessment" in content


def test_evidence_sha256_integrity(report_setup: tuple[DatabaseManager, ReportEngine, EvidenceManager, int]) -> None:
    """Verify cryptographic SHA-256 verification and tampering detection."""
    _, _, e_mgr, pid = report_setup
    evidence_text = "CONFIDENTIAL: Proof of Concept HTTP Request & Response Payload"
    eid = e_mgr.record_text_evidence(
        project_id=pid,
        title="HTTP Request Reproduction",
        content=evidence_text,
        description="Reproduction proof"
    )

    # Verification before tampering
    valid, msg = e_mgr.verify_evidence_integrity(eid)
    assert valid, f"Integrity check failed: {msg}"

    # Tamper with the evidence file directly on disk
    evidence_records = e_mgr.list_evidence(pid)
    file_path = Path(evidence_records[0]["content_or_path"])
    file_path.write_text("TAMPERED CONTENT INSERTED BY UNKNOWN ACTOR", encoding="utf-8")

    # Verification after tampering
    tampered_valid, tamper_msg = e_mgr.verify_evidence_integrity(eid)
    assert not tampered_valid
    assert "VIOLATION" in tamper_msg
