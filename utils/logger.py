"""
utils/logger.py
===============
Structured logging for IntelliAssess AI.

Provides a single get_logger(name) factory used by every module.
Logs go to:
  - Console (INFO and above, clean format for the operator)
  - File     (DEBUG and above, detailed format for diagnostics)

Log directory is created automatically on first use.
"""

import logging
import sys
from pathlib import Path

from config.settings import LOG_DIR, LOG_FILENAME, LOG_LEVEL


def _ensure_log_dir() -> Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return LOG_DIR


# Module-level registry: one logger per named module, created once.
_loggers: dict[str, logging.Logger] = {}


def get_logger(name: str) -> logging.Logger:
    """
    Return a configured logger for the given module name.

    Usage:
        from utils.logger import get_logger
        log = get_logger(__name__)
        log.info("Session created: %s", session_id)

    The first call sets up handlers; subsequent calls return the cached instance.
    """
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # Capture everything; handlers filter by level.

    if not logger.handlers:
        _ensure_log_dir()

        # ── Console handler ─────────────────────────────────────────────
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))
        console_formatter = logging.Formatter(
            fmt="%(message)s"
        )
        console_handler.setFormatter(console_formatter)

        # ── File handler ─────────────────────────────────────────────────
        log_path = LOG_DIR / LOG_FILENAME
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)

        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

    _loggers[name] = logger
    return logger
