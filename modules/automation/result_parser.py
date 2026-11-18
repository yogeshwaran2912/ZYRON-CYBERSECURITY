"""
ZYRON - Cybersecurity Automation Result Parser
Parses JSON, CSV, and text assessment outputs with duplicate finding detection.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from core.exceptions import ValidationError
from core.logger import get_logger

logger = get_logger("automation.parser")


class ResultParser:
    """Parses structured and tabular assessment output and filters duplicates."""

    @staticmethod
    def parse_json(content_or_path: str | Path) -> Any:
        """Parse raw JSON string or JSON file safely."""
        path = Path(content_or_path)
        if path.is_file():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                raise ValidationError(f"Failed to parse JSON file: {e}") from e
        else:
            try:
                return json.loads(str(content_or_path))
            except Exception as e:
                raise ValidationError(f"Failed to parse JSON string: {e}") from e

    @staticmethod
    def parse_csv(content_or_path: str | Path) -> list[dict[str, str]]:
        """Parse raw CSV string or CSV file into list of row dictionaries."""
        path = Path(content_or_path)
        if path.is_file():
            try:
                with open(path, "r", encoding="utf-8", newline="") as f:
                    reader = csv.DictReader(f)
                    return list(reader)
            except Exception as e:
                raise ValidationError(f"Failed to parse CSV file: {e}") from e
        else:
            try:
                reader = csv.DictReader(io.StringIO(str(content_or_path)))
                return list(reader)
            except Exception as e:
                raise ValidationError(f"Failed to parse CSV string: {e}") from e

    @staticmethod
    def deduplicate_findings(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
        """
        Identify and filter out duplicate findings based on (affected_asset, title, severity).
        Returns: (deduplicated_list, duplicate_count)
        """
        seen_keys = set()
        unique_findings = []
        duplicate_count = 0

        for f in findings:
            asset = str(f.get("affected_asset", "")).strip().lower()
            title = str(f.get("title", "")).strip().lower()
            sev = str(f.get("severity", "")).strip().lower()
            key = (asset, title, sev)

            if key in seen_keys:
                duplicate_count += 1
            else:
                seen_keys.add(key)
                unique_findings.append(f)

        logger.info("Deduplication completed: %d unique findings, %d duplicates removed", len(unique_findings), duplicate_count)
        return unique_findings, duplicate_count
