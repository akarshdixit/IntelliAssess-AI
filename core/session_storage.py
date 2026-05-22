"""
core/session_storage.py
========================
Thin persistence layer for session.json read/write operations.

Design principle:
  All JSON I/O for session metadata is centralized here.
  No other module reads or writes session.json directly.
  This makes the persistence mechanism swappable (e.g., SQLite in a future phase)
  without touching any business logic.

Public API:
  save(session, session_dir)  → bool
  load(session_dir)           → Session | None
  load_by_id(session_id)      → Session | None
  list_sessions(base_dir)     → list[Session]
"""

import json
from pathlib import Path
from typing import Optional

from config.settings import (
    SESSION_METADATA_FILENAME,
    SESSIONS_ACTIVE_DIR,
    SESSIONS_ARCHIVED_DIR,
)
from models.session import Session
from utils.file_utils import read_text_safe, write_text_safe
from utils.logger import get_logger

log = get_logger(__name__)


def save(session: Session, session_dir: Path) -> bool:
    """
    Serialize session to session.json inside session_dir.

    Uses atomic write (write .tmp → rename) to prevent corruption.
    Returns True on success, False on failure.
    """
    metadata_path = session_dir / SESSION_METADATA_FILENAME
    payload = json.dumps(session.to_dict(), indent=2, ensure_ascii=False)
    success = write_text_safe(metadata_path, payload)
    if success:
        log.debug("Session saved: %s → %s", session.session_id, metadata_path)
    else:
        log.error("Failed to save session: %s", session.session_id)
    return success


def load(session_dir: Path) -> Optional[Session]:
    """
    Deserialize session.json from session_dir.

    Returns a Session instance on success, None if the file is missing or corrupt.
    """
    metadata_path = session_dir / SESSION_METADATA_FILENAME
    raw = read_text_safe(metadata_path)
    if raw is None:
        log.warning("Session metadata not found: %s", metadata_path)
        return None
    try:
        data = json.loads(raw)
        session = Session.from_dict(data)
        log.debug("Session loaded: %s", session.session_id)
        return session
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        log.error("Corrupt session metadata at %s: %s", metadata_path, exc)
        return None


def load_by_id(session_id: str) -> Optional[Session]:
    """
    Load a session by its session_id from either active/ or archived/ directories.

    Searches active first, then archived.
    Returns None if not found.
    """
    for base_dir in (SESSIONS_ACTIVE_DIR, SESSIONS_ARCHIVED_DIR):
        candidate = base_dir / session_id
        if candidate.is_dir():
            return load(candidate)
    log.debug("Session not found by ID: %s", session_id)
    return None


def get_session_dir(session_id: str) -> Optional[Path]:
    """
    Return the directory Path for a session_id, searching active then archived.
    Returns None if not found.
    """
    for base_dir in (SESSIONS_ACTIVE_DIR, SESSIONS_ARCHIVED_DIR):
        candidate = base_dir / session_id
        if candidate.is_dir() and (candidate / SESSION_METADATA_FILENAME).exists():
            return candidate
    return None


def list_sessions(base_dir: Path) -> list[Session]:
    """
    Return all valid sessions found under base_dir, sorted by created_at descending.

    Silently skips directories with missing or corrupt session.json.
    """
    sessions: list[Session] = []
    if not base_dir.is_dir():
        return sessions

    for entry in sorted(base_dir.iterdir()):
        if entry.is_dir():
            session = load(entry)
            if session:
                sessions.append(session)

    # Sort by created_at descending (most recent first)
    sessions.sort(key=lambda s: s.created_at, reverse=True)
    return sessions
