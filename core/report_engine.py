"""
ZYRON Cybersecurity Framework - Central Report Generation Engine
Generates executive & technical security reports in Markdown, HTML, and JSON formats.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from core.database import DatabaseManager, get_db
from core.logger import get_logger

logger = get_logger("report_engine")


class ReportEngine:
    """Standardized report generation engine for Bug Bounty, Red Team, and Pentesting."""

    def __init__(self, db: DatabaseManager | None = None, reports_dir: Path | None = None) -> None:
        self.db = db or get_db()
        if reports_dir is None:
            project_root = Path(__file__).resolve().parent.parent
            self.reports_dir = project_root / "reports"
        else:
            self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        project_id: int,
        title: str,
        organization: str,
        module_name: str,
        executive_summary: str,
        findings: list[dict[str, Any]],
        scope_summary: list[dict[str, Any]] | None = None,
        report_format: str = "markdown"
    ) -> Path:
        """
        Generate a complete security report and persist it to disk and the database.
        Supported formats: 'markdown', 'html', 'json'.
        """
        now = datetime.now(timezone.utc)
        timestamp_str = now.strftime("%Y%m%d_%H%M%S")
        safe_title = "".join(c if c.isalnum() else "_" for c in title.lower())
        filename = f"{safe_title}_{timestamp_str}"

        # Severity breakdown
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for f in findings:
            sev = f.get("severity", "informational").lower()
            if sev in counts:
                counts[sev] += 1

        if report_format.lower() == "html":
            file_path = self.reports_dir / f"{filename}.html"
            content = self._render_html(
                title=title,
                organization=organization,
                module_name=module_name,
                date_str=now.strftime("%B %d, %Y"),
                executive_summary=executive_summary,
                counts=counts,
                findings=findings,
                scopes=scope_summary or []
            )
            file_path.write_text(content, encoding="utf-8")

        elif report_format.lower() == "json":
            file_path = self.reports_dir / f"{filename}.json"
            report_data = {
                "report_metadata": {
                    "framework": "ZYRON Cybersecurity Framework v0.1.0",
                    "title": title,
                    "organization": organization,
                    "module": module_name,
                    "generated_at": now.isoformat(),
                    "findings_summary": counts
                },
                "executive_summary": executive_summary,
                "scope": scope_summary or [],
                "findings": findings
            }
            file_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

        else:
            # Default to Markdown
            file_path = self.reports_dir / f"{filename}.md"
            content = self._render_markdown(
                title=title,
                organization=organization,
                module_name=module_name,
                date_str=now.strftime("%B %d, %Y"),
                executive_summary=executive_summary,
                counts=counts,
                findings=findings,
                scopes=scope_summary or []
            )
            file_path.write_text(content, encoding="utf-8")

        # Save to database
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO reports (project_id, title, report_type, file_path, summary, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (project_id, title, report_format.lower(), str(file_path.resolve()), executive_summary[:200], now.isoformat())
            )

        self.db.log_audit(
            event_type="REPORT_GENERATED",
            action="GENERATE_REPORT",
            details=f"Format: {report_format}, Total Findings: {len(findings)}",
            target=str(file_path),
            status="success"
        )
        logger.info("Generated %s report at %s", report_format.upper(), file_path)
        return file_path

    def _render_markdown(
        self,
        title: str,
        organization: str,
        module_name: str,
        date_str: str,
        executive_summary: str,
        counts: dict[str, int],
        findings: list[dict[str, Any]],
        scopes: list[dict[str, Any]]
    ) -> str:
        """Render high-quality Markdown security report."""
        lines = [
            f"# {title}",
            f"**Organization:** {organization}  ",
            f"**Framework:** ZYRON Cybersecurity Framework v0.1.0  ",
            f"**Domain:** {module_name}  ",
            f"**Date:** {date_str}  ",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            executive_summary,
            "",
            "### Vulnerability Severity Breakdown",
            "",
            "| Severity | Count |",
            "| :--- | :---: |",
            f"| **CRITICAL** | {counts['critical']} |",
            f"| **HIGH** | {counts['high']} |",
            f"| **MEDIUM** | {counts['medium']} |",
            f"| **LOW** | {counts['low']} |",
            f"| **INFORMATIONAL** | {counts['informational']} |",
            "",
            "## 2. Assessment Scope & Target Authorization",
            "",
            "The following assets were authorized within the documented rules of engagement:",
            ""
        ]

        if scopes:
            lines.extend([
                "| Target | Type | Policy | Description |",
                "| :--- | :--- | :--- | :--- |"
            ])
            for s in scopes:
                pol = "EXCLUDED" if s.get("is_excluded") else "AUTHORIZED"
                lines.append(f"| `{s.get('target_value', '')}` | {s.get('target_type', '')} | **{pol}** | {s.get('description', '')} |")
        else:
            lines.append("*No specific scope boundaries defined or recorded.*")

        lines.extend([
            "",
            "## 3. Detailed Technical Findings",
            ""
        ])

        if not findings:
            lines.append("*No security findings recorded for this assessment.*")
        else:
            for idx, f in enumerate(findings, start=1):
                sev = f.get("severity", "informational").upper()
                lines.extend([
                    f"### Finding #{idx}: {f.get('title', 'Untitled Finding')}",
                    f"- **Severity:** `{sev}`",
                    f"- **Validation Status:** `{f.get('validation_status', 'potential')}`",
                    f"- **Affected Asset:** `{f.get('affected_asset', 'N/A')}`",
                    f"- **CVSS Score:** {f.get('cvss_score', 'N/A')}",
                    "",
                    "#### Description",
                    f.get("description", "No description provided."),
                    "",
                    "#### Steps to Reproduce",
                    f.get("reproduction_steps", "N/A"),
                    "",
                    "#### Impact",
                    f.get("impact", "N/A"),
                    "",
                    "#### Remediation Guidance",
                    f.get("remediation", "Apply vendor security patches and input validation."),
                    "",
                    f"- **References:** {f.get('references_text', 'N/A')}",
                    "---",
                    ""
                ])

        lines.extend([
            "## 4. Methodology & Disclaimer",
            "",
            "This assessment was performed strictly within pre-authorized operational boundaries using the "
            "**ZYRON Cybersecurity Framework**. All active checks adhere to default-deny scope enforcement. "
            "Findings represent security posture at the time of assessment."
        ])
        return "\n".join(lines)

    def _render_html(
        self,
        title: str,
        organization: str,
        module_name: str,
        date_str: str,
        executive_summary: str,
        counts: dict[str, int],
        findings: list[dict[str, Any]],
        scopes: list[dict[str, Any]]
    ) -> str:
        """Render high-contrast, modern consulting HTML report with dark/light cybersecurity styling."""
        findings_html = []
        for idx, f in enumerate(findings, start=1):
            sev = f.get("severity", "informational").lower()
            findings_html.append(f"""
            <div class="finding-card sev-{sev}">
                <div class="finding-header">
                    <span class="badge badge-{sev}">{sev.upper()}</span>
                    <h3>#{idx}. {f.get('title', 'Untitled')}</h3>
                </div>
                <div class="finding-meta">
                    <strong>Asset:</strong> <code>{f.get('affected_asset', 'N/A')}</code> &bull;
                    <strong>Status:</strong> {f.get('validation_status', 'potential')} &bull;
                    <strong>CVSS:</strong> {f.get('cvss_score', 'N/A')}
                </div>
                <div class="finding-body">
                    <h4>Description</h4>
                    <p>{f.get('description', 'N/A')}</p>
                    <h4>Impact</h4>
                    <p>{f.get('impact', 'N/A')}</p>
                    <h4>Remediation</h4>
                    <p>{f.get('remediation', 'N/A')}</p>
                </div>
            </div>
            """)

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f141c; color: #e2e8f0; margin: 0; padding: 2rem; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #1a2230; padding: 2.5rem; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }}
        h1, h2, h3, h4 {{ color: #ffffff; }}
        h1 {{ border-bottom: 2px solid #3b82f6; padding-bottom: 0.5rem; }}
        .header-meta {{ color: #94a3b8; font-size: 0.95rem; margin-bottom: 2rem; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 1.5rem 0; }}
        .stat-box {{ padding: 1rem; text-align: center; border-radius: 6px; font-weight: bold; background: #242f42; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }}
        .badge-critical {{ background: #dc2626; color: #fff; }}
        .badge-high {{ background: #ea580c; color: #fff; }}
        .badge-medium {{ background: #eab308; color: #000; }}
        .badge-low {{ background: #3b82f6; color: #fff; }}
        .badge-informational {{ background: #64748b; color: #fff; }}
        .finding-card {{ background: #242f42; border-left: 5px solid #3b82f6; border-radius: 6px; padding: 1.2rem; margin-bottom: 1.5rem; }}
        .finding-card.sev-critical {{ border-left-color: #dc2626; }}
        .finding-card.sev-high {{ border-left-color: #ea580c; }}
        .finding-card.sev-medium {{ border-left-color: #eab308; }}
        .finding-card.sev-low {{ border-left-color: #3b82f6; }}
        .finding-card.sev-informational {{ border-left-color: #64748b; }}
        .finding-header {{ display: flex; align-items: center; gap: 10px; }}
        .finding-meta {{ color: #94a3b8; font-size: 0.9rem; margin-top: 0.3rem; }}
        code {{ background: #0f141c; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <div class="header-meta">
            <strong>Organization:</strong> {organization} | <strong>Domain:</strong> {module_name} | <strong>Date:</strong> {date_str}
        </div>
        <h2>1. Executive Summary</h2>
        <p>{executive_summary}</p>
        <div class="stats-grid">
            <div class="stat-box" style="border-top: 3px solid #dc2626;">Critical: {counts['critical']}</div>
            <div class="stat-box" style="border-top: 3px solid #ea580c;">High: {counts['high']}</div>
            <div class="stat-box" style="border-top: 3px solid #eab308;">Medium: {counts['medium']}</div>
            <div class="stat-box" style="border-top: 3px solid #3b82f6;">Low: {counts['low']}</div>
            <div class="stat-box" style="border-top: 3px solid #64748b;">Info: {counts['informational']}</div>
        </div>
        <h2>2. Technical Findings</h2>
        {''.join(findings_html) if findings_html else '<p>No findings recorded.</p>'}
    </div>
</body>
</html>
"""
        return html_template
