"""
ZYRON - Cybersecurity Workflow Manager
Chains vetted assessment components into deterministic, repeatable security workflows.
"""

from __future__ import annotations

from typing import Any

from core.database import DatabaseManager, get_db
from core.evidence_manager import EvidenceManager
from core.logger import get_logger
from core.scope_manager import ScopeManager
from modules.bug_bounty.http_analyzer import HTTPAnalyzer

logger = get_logger("automation.workflow")


class WorkflowManager:
    """Coordinates multi-step cybersecurity automation workflows."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_db()
        self.scope_manager = ScopeManager(self.db)
        self.evidence_mgr = EvidenceManager(self.db)
        self.http_analyzer = HTTPAnalyzer(self.db, self.scope_manager)

    def run_evidence_integrity_workflow(self, project_id: int) -> dict[str, Any]:
        """Verify the cryptographic SHA-256 integrity of all evidence files for a project."""
        evidence_records = self.evidence_mgr.list_evidence(project_id)
        total = len(evidence_records)
        verified = 0
        corrupted = 0
        failures: list[dict[str, Any]] = []

        for ev in evidence_records:
            valid, msg = self.evidence_mgr.verify_evidence_integrity(ev["id"])
            if valid:
                verified += 1
            else:
                corrupted += 1
                failures.append({"evidence_id": ev["id"], "title": ev["title"], "issue": msg})

        result = {
            "workflow": "evidence_integrity_verification",
            "total_records": total,
            "verified_valid": verified,
            "corrupted_or_missing": corrupted,
            "details": failures
        }
        logger.info("Evidence integrity workflow completed: %d/%d valid", verified, total)
        return result

    def run_security_headers_batch_workflow(self, project_id: int, urls: list[str]) -> dict[str, Any]:
        """Run HTTP security header analysis across multiple authorized URLs."""
        results = []
        for u in urls:
            try:
                res = self.http_analyzer.analyze_headers(project_id, u)
                results.append(res)
            except Exception as e:
                results.append({"target_url": u, "status": "failed", "error": str(e)})

        return {
            "workflow": "security_headers_batch_analysis",
            "total_targets": len(urls),
            "results": results
        }
