"""
config/settings.py
==================
Central configuration for IntelliAssess AI.

All paths, constants, model identifiers, and tunables live here.
No other module should hardcode these values.

Cross-platform: BASE_DIR is resolved relative to this file's location,
making the project portable across Windows (D:\\Assessments\\) and Linux/macOS
without changing any other module.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Base paths
# ---------------------------------------------------------------------------

# Root of the intelliassess_ai package
PACKAGE_ROOT: Path = Path(__file__).resolve().parent.parent

# Sessions directory — all active and archived sessions live here.
# On a production Windows deployment this could be overridden to D:\Assessments.
SESSIONS_ROOT: Path = PACKAGE_ROOT / "sessions"

SESSIONS_ACTIVE_DIR:   Path = SESSIONS_ROOT / "active"
SESSIONS_ARCHIVED_DIR: Path = SESSIONS_ROOT / "archived"

# ---------------------------------------------------------------------------
# Session folder structure (created inside each session directory)
# ---------------------------------------------------------------------------

SESSION_SUBDIRS: list[str] = [
    "incoming",     # Employee drops raw scan outputs here
    "processed",    # Successfully ingested files (auto-moved by watcher)
    "failed",       # Files that could not be classified + error log
    "reports",      # Generated assessment reports
]

SESSION_METADATA_FILENAME: str = "session.json"

# ---------------------------------------------------------------------------
# Session status values — canonical strings used across all modules
# ---------------------------------------------------------------------------

class SessionStatus:
    ACTIVE:           str = "ACTIVE"
    COMPLETE:         str = "COMPLETE"
    REPORT_GENERATED: str = "REPORT_GENERATED"
    ARCHIVED:         str = "ARCHIVED"

# ---------------------------------------------------------------------------
# Context collection options — used by metadata_collector (Phase 3)
# Defined here so future phases can reference the canonical option sets.
# ---------------------------------------------------------------------------

EXPOSURE_OPTIONS: dict[str, str] = {
    "1": "public",
    "2": "internal",
    "3": "dmz",
    "4": "cloud",
}

ENVIRONMENT_OPTIONS: dict[str, str] = {
    "1": "production",
    "2": "staging",
    "3": "development",
}

SECTOR_OPTIONS: dict[str, str] = {
    "1": "banking",
    "2": "healthcare",
    "3": "government",
    "4": "education",
    "5": "saas",
    "6": "manufacturing",
}

# ---------------------------------------------------------------------------
# Display / UX constants
# ---------------------------------------------------------------------------

PLATFORM_NAME:    str = "IntelliAssess AI"
PLATFORM_VERSION: str = "1.0.0"
PLATFORM_PHASE:   str = "Phase 2A — Watch Folder Detection"

BANNER: str = f"""
{'=' * 52}
        {PLATFORM_NAME}
  Multi-Client Assessment & Compliance Platform
{'=' * 52}
  {PLATFORM_PHASE}
{'=' * 52}
"""

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_DIR: Path = PACKAGE_ROOT / "logs"
LOG_FILENAME: str = "intelliassess.log"
LOG_LEVEL: str = "INFO"  # DEBUG | INFO | WARNING | ERROR

# ---------------------------------------------------------------------------
# Watcher & Ingestion — Phase 2A
# ---------------------------------------------------------------------------

# How often (seconds) to poll a file's size during stabilization.
# Lower = faster detection but more I/O. 0.5s is suitable for local filesystems.
WATCHER_STABILIZATION_POLL_S: float = 0.5

# Number of consecutive size-equal polls required before the file is
# considered fully written. 3 × 0.5s = 1.5s minimum stable window.
WATCHER_STABILIZATION_STABLE_COUNT: int = 3

# Maximum seconds to wait for a file to stabilize before giving up.
# Files that exceed this timeout are moved to failed/ with a timeout note.
WATCHER_STABILIZATION_TIMEOUT_S: float = 120.0

# File suffixes that the watcher ignores — incomplete downloads, temp writes.
WATCHER_IGNORE_SUFFIXES: tuple[str, ...] = (
    ".tmp",
    ".part",
    ".crdownload",
    ".download",
    ".swp",
)

# Filename prefixes that the watcher ignores — hidden/system files.
WATCHER_IGNORE_PREFIXES: tuple[str, ...] = (
    ".",   # hidden files (Unix)
    "~",   # temp files (Office, vim)
)
