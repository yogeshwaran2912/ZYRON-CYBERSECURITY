"""
ZYRON Cybersecurity Framework - Logging System
Provides structured application logging and security audit logging.
"""

from __future__ import annotations

import logging
import logging.config
from pathlib import Path
from typing import Any
import yaml

from core.exceptions import ConfigurationError

_INITIALIZED = False


def setup_logging(config_path: str | Path | None = None) -> None:
    """Initialize application logging configuration."""
    global _INITIALIZED
    if _INITIALIZED:
        return

    if config_path is None:
        base_dir = Path(__file__).resolve().parent.parent
        config_path = base_dir / "config" / "logging.yaml"
    else:
        config_path = Path(config_path)

    if config_path.is_file():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config_dict = yaml.safe_load(f)
            
            # Ensure log file path is relative to project root
            log_filename = config_dict.get("handlers", {}).get("file", {}).get("filename", "zyron.log")
            if not Path(log_filename).is_absolute():
                project_root = Path(__file__).resolve().parent.parent
                config_dict["handlers"]["file"]["filename"] = str(project_root / log_filename)
                
            logging.config.dictConfig(config_dict)
            _INITIALIZED = True
            return
        except Exception as e:
            # Fall back to programmatic standard logging if yaml parsing fails
            pass

    # Built-in robust fallback
    project_root = Path(__file__).resolve().parent.parent
    log_file = project_root / "zyron.log"

    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    root_logger = logging.getLogger("zyron")
    root_logger.setLevel(logging.DEBUG)
    if not root_logger.handlers:
        root_logger.addHandler(file_handler)

    _INITIALIZED = True


def get_logger(name: str = "zyron") -> logging.Logger:
    """Return a logger instance with the standard ZYRON hierarchy."""
    if not _INITIALIZED:
        setup_logging()
    return logging.getLogger(f"zyron.{name}" if not name.startswith("zyron") else name)
