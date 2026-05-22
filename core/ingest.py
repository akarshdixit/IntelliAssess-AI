"""
core/ingest.py
==============
Ingestion pipeline for IntelliAssess AI — Phase 3-2.

Responsibility: PROCESS a detected file safely.

  Given a file path that the watcher has detected, this module:
    1. Stabilizes the file (waits until writes are complete)
    2. Checks for duplicates (prevents double-ingestion)
    3. Moves the file to processed/
    4. [Phase 2B-2] Classifies file via intelligence.file_classifier
    5. [Phase 2C-1] Extracts targets via intelligence.target_extractor
    6. [Phase 3-2]  Parses file via parsers.registry.parse_file()
    7. Updates session.json (files_detected, tools_detected, targets, parse metadata)

Design principles:
  - This module is the ONLY place that touches the processed/ and failed/ dirs.
  - It never renders to the console directly — all output goes through the logger.
  - It is called from core/watcher.py on a worker thread (not the main thread).
  - It is safe to call concurrently for different files in the same session.
  - Session metadata updates use load → mutate → save to avoid race conditions.

Phase 3-2 integration (this version):
  After extract_targets(), parse_file(dst_path, tool_type, nmap_subtype) is
  called. The ParsedScanData result is logged and its summary (asset count,
  finding count, parse errors) is stored in the processing_log entry for
  this file. ParsedScanData is NOT yet persisted to session.json — structured
  persistence of findings and assets is a Phase 4 concern (analyzer.py).

Phase 4 integration point:
  analyzer.py will consume ParsedScanData here. The stub is labelled below.
"""

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config.settings import (
    SESSION_METADATA_FILENAME,
    WATCHER_STABILIZATION_POLL_S,
    WATCHER_STABILIZATION_STABLE_COUNT,
    WATCHER_STABILIZATION_TIMEOUT_S,
)
from core import session_storage as storage
from intelligence.file_classifier import NmapSubtype, ToolType, classify_with_subtype
from parsers.registry import parse_file
from intelligence.target_extractor import ExtractedTarget, extract_targets
from utils.file_utils import safe_move
from utils.logger import get_logger

log = get_logger(__name__)

# Per-session lock registry — prevents concurrent session.json writes from
# two simultaneously-ingested files corrupting the metadata.
_session_locks: dict[str, threading.Lock] = {}
_registry_lock = threading.Lock()


def _get_session_lock(session_id: str) -> threading.Lock:
    """Return (creating if needed) the metadata write-lock for a session."""
    with _registry_lock:
        if session_id not in _session_locks:
            _session_locks[session_id] = threading.Lock()
        return _session_locks[session_id]


# ---------------------------------------------------------------------------
# Public entry point — called by watcher.py worker threads
# ---------------------------------------------------------------------------

def handle_file(file_path: Path, session_dir: Path) -> bool:
    """
    Full ingestion pipeline for a single detected file.

    Steps:
      1. Stabilize  — wait until file writes are complete
      2. Deduplicate — skip if already in processed/
      3. Move       — transfer from incoming/ to processed/
      4. Classify   — content-based tool + Nmap subtype detection (Phase 2B-2)
      5. Extract    — deterministic target extraction (Phase 2C-1)
      6. Parse      — structured scan data extraction (Phase 3-2)
      7. Update     — persist tool_type, targets, parse summary in session.json

    Returns True on successful ingestion, False on any failure or skip.
    Called from watcher.py on a dedicated worker thread per file.
    """
    session_id    = session_dir.name
    processed_dir = session_dir / "processed"
    failed_dir    = session_dir / "failed"

    log.info("[%s] Ingestion started: %s", session_id, file_path.name)

    # ── 1. Stabilize ──────────────────────────────────────────────────────
    if not _stabilize(file_path):
        log.warning(
            "[%s] Stabilization timeout for: %s — moving to failed/",
            session_id, file_path.name,
        )
        _move_to_failed(file_path, failed_dir, reason="stabilization_timeout")
        return False

    # Verify file still exists after stabilization (could be deleted by user)
    if not file_path.exists():
        log.warning(
            "[%s] File disappeared after stabilization: %s",
            session_id, file_path.name,
        )
        return False

    # ── 2. Deduplicate ────────────────────────────────────────────────────
    if _is_duplicate(file_path, processed_dir):
        log.info(
            "[%s] Duplicate skipped: %s already in processed/",
            session_id, file_path.name,
        )
        return False

    # ── 3. Move to processed/ ─────────────────────────────────────────────
    dst_path = _move_to_processed(file_path, processed_dir)
    if dst_path is None:
        log.error(
            "[%s] Failed to move %s to processed/",
            session_id, file_path.name,
        )
        _move_to_failed(file_path, failed_dir, reason="move_failed")
        return False

    log.info("[%s] File ingested: %s → processed/", session_id, file_path.name)

    # ── 4. Phase 2B-2: content-based classification + subtype detection ───
    tool_type, nmap_subtype, confidence = classify_with_subtype(dst_path)

    if nmap_subtype is not None:
        log.info(
            "[%s] Classified: %s / %s (confidence=%.2f) — %s",
            session_id, tool_type.value, nmap_subtype.value,
            confidence, dst_path.name,
        )
    else:
        log.info(
            "[%s] Classified: %s (confidence=%.2f) — %s",
            session_id, tool_type.value, confidence, dst_path.name,
        )

    # ── 5. Phase 2C-1: deterministic target extraction ────────────────────
    # extract_targets() returns an empty list (never raises) for UNKNOWN
    # tool types or unreadable files — safe to call unconditionally.
    extracted = extract_targets(dst_path, tool_type, nmap_subtype)

    # ── 6. Phase 3-2: structured scan data parsing ────────────────────────
    # parse_file() returns a ParsedScanData (never raises). Returns an empty
    # result with parse_errors for unregistered tool types — safe to call
    # unconditionally. ParsedScanData is NOT yet persisted to session.json;
    # its summary metadata is stored in the processing_log audit entry below.
    parsed = parse_file(dst_path, tool_type, nmap_subtype)

    if parsed.has_errors:
        for err in parsed.parse_errors:
            log.debug("[%s] parse_error: %s", session_id, err)

    # ── Phase 4 stub: AI analysis ─────────────────────────────────────────
    # analyzer.run(parsed, session_dir)  # Phase 4

    # ── 7. Update session metadata ─────────────────────────────────────────
    _update_session(
        session_dir, dst_path,
        tool_type, confidence, nmap_subtype,
        extracted_targets=extracted,
        parsed_summary={
            "assets":        len(parsed.assets),
            "findings":      len(parsed.findings),
            "parse_errors":  len(parsed.parse_errors),
            "parse_ms":      round(parsed.parse_duration_ms, 1),
            "primary_target": parsed.primary_target,
        },
    )

    return True


# ---------------------------------------------------------------------------
# Stabilization — wait until file writes are complete
# ---------------------------------------------------------------------------

def _stabilize(file_path: Path) -> bool:
    """
    Poll file size until it is stable for WATCHER_STABILIZATION_STABLE_COUNT
    consecutive checks, or until WATCHER_STABILIZATION_TIMEOUT_S elapses.

    Returns True if stabilized, False if timeout exceeded.

    Rationale: scan tools (nmap -oN, sslscan) write output incrementally.
    Processing a partially-written file would corrupt future parsing.
    """
    deadline     = time.monotonic() + WATCHER_STABILIZATION_TIMEOUT_S
    stable_count = 0
    last_size    = -1

    while time.monotonic() < deadline:
        try:
            current_size = file_path.stat().st_size
        except FileNotFoundError:
            return False  # File deleted mid-stabilization

        if current_size == last_size and current_size >= 0:
            stable_count += 1
            if stable_count >= WATCHER_STABILIZATION_STABLE_COUNT:
                log.debug(
                    "Stabilized: %s (%d bytes, %d consecutive stable checks)",
                    file_path.name, current_size, stable_count,
                )
                return True
        else:
            stable_count = 0
            last_size = current_size

        time.sleep(WATCHER_STABILIZATION_POLL_S)

    return False  # timeout


# ---------------------------------------------------------------------------
# Duplicate prevention
# ---------------------------------------------------------------------------

def _is_duplicate(file_path: Path, processed_dir: Path) -> bool:
    """
    Return True if a file with the same name already exists in processed/.

    Filename-based check is sufficient for Phase 2A. Phase 6 can add
    hash-based dedup for edge cases where two different files share a name.
    """
    candidate = processed_dir / file_path.name
    if candidate.exists():
        log.debug("Duplicate check: %s found in processed/", file_path.name)
        return True
    return False


# ---------------------------------------------------------------------------
# File movement
# ---------------------------------------------------------------------------

def _move_to_processed(file_path: Path, processed_dir: Path) -> Optional[Path]:
    """
    Move file_path into processed_dir.
    Returns the destination Path on success, None on failure.
    """
    return safe_move(file_path, processed_dir, overwrite=False)


def _move_to_failed(file_path: Path, failed_dir: Path, reason: str) -> None:
    """
    Move file_path into failed_dir and write a companion error note.
    Creates <filename>.error.txt alongside the moved file.
    """
    dst = safe_move(file_path, failed_dir, overwrite=True)
    if dst:
        note_path = failed_dir / f"{file_path.name}.error.txt"
        timestamp = datetime.now(timezone.utc).isoformat()
        note_path.write_text(
            f"File: {file_path.name}\n"
            f"Reason: {reason}\n"
            f"Timestamp: {timestamp}\n",
            encoding="utf-8",
        )
        log.info("Moved to failed/: %s (reason: %s)", file_path.name, reason)


# ---------------------------------------------------------------------------
# Session metadata update
# ---------------------------------------------------------------------------

def _update_session(
    session_dir: Path,
    ingested_file: Path,
    tool_type: ToolType = ToolType.UNKNOWN,
    confidence: float = 0.0,
    nmap_subtype: Optional[NmapSubtype] = None,
    extracted_targets: Optional[list[ExtractedTarget]] = None,
    parsed_summary: Optional[dict] = None,
) -> None:
    """
    Update session.json after a successful file ingestion.

    Mutations (all within a per-session threading.Lock):
      - files_detected  ← incremented by 1
      - tools_detected  ← tool_type.value appended if not already present
      - targets         ← new normalized target values appended (dedup by value)
      - processing_log  ← audit entry appended with extraction + parse metadata

    Uses load → mutate → save pattern (atomic within the lock).

    Args:
        session_dir:        Root directory of the session.
        ingested_file:      Path to the file in processed/ (for logging).
        tool_type:          Classified ToolType of the ingested file.
        confidence:         Classification confidence score.
        nmap_subtype:       Nmap output format subtype (None for non-Nmap).
        extracted_targets:  Targets extracted by target_extractor (Phase 2C-1).
        parsed_summary:     Summary dict from ParsedScanData (Phase 3-2).
                            Keys: assets, findings, parse_errors, parse_ms,
                            primary_target. None if parser not yet available.
    """
    session_id   = session_dir.name
    session_lock = _get_session_lock(session_id)

    # Values captured inside the lock for use in post-lock console output
    files_count: int        = 0
    target_list: list[str]  = []
    tool_list:   list[str]  = []
    new_targets: int        = 0

    with session_lock:
        session = storage.load(session_dir)
        if session is None:
            log.error(
                "Cannot update session metadata — session.json not found: %s",
                session_dir,
            )
            return

        # ── files_detected ────────────────────────────────────────────────
        session.files_detected += 1

        # ── tools_detected (Phase 2C-1: fixes Phase 2B-2 gap) ────────────
        # Tool type was previously only stored in processing_log, never
        # added to the session.tools_detected list. Fixed here.
        tool_name = tool_type.value
        if tool_name != ToolType.UNKNOWN.value and tool_name not in session.tools_detected:
            session.tools_detected.append(tool_name)

        # ── targets (Phase 2C-1) ──────────────────────────────────────────
        if extracted_targets:
            for t in extracted_targets:
                if t.value and t.value not in session.targets:
                    session.targets.append(t.value)
                    new_targets += 1

        # ── processing_log audit entry ────────────────────────────────────
        log_entry: dict = {
            "event":          "file_ingested",
            "filename":       ingested_file.name,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "phase":          "3-2",
            "tool_type":      tool_type.value,
            "nmap_subtype":   nmap_subtype.value if nmap_subtype is not None else None,
            "confidence":     round(confidence, 3),
            "targets_found":  new_targets,
        }
        # Phase 3-2: include parse summary in audit trail when available
        if parsed_summary:
            log_entry["parse_assets"]       = parsed_summary.get("assets", 0)
            log_entry["parse_findings"]     = parsed_summary.get("findings", 0)
            log_entry["parse_errors"]       = parsed_summary.get("parse_errors", 0)
            log_entry["parse_ms"]           = parsed_summary.get("parse_ms", 0.0)
        session.processing_log.append(log_entry)

        storage.save(session, session_dir)

        # Capture values for post-lock output (avoid re-loading session)
        files_count = session.files_detected
        target_list = list(session.targets)
        tool_list   = list(session.tools_detected)

    log.debug(
        "[%s] Session updated: files=%d, targets=%d, tools=%s",
        session_id, files_count, len(target_list), tool_list,
    )

    # Console feedback — visible to the employee while working
    print(f"\n  [+] File ingested:  {ingested_file.name}")
    print(f"      Tool:           {tool_type.value}")
    print(f"      Files detected: {files_count}")
    if target_list:
        print(f"      Targets:        {', '.join(target_list)}")
    if new_targets:
        print(f"      New targets:    +{new_targets}")
    if parsed_summary and (parsed_summary.get("assets", 0) or parsed_summary.get("findings", 0)):
        print(
            f"      Parsed:         "
            f"{parsed_summary.get('assets', 0)} asset(s), "
            f"{parsed_summary.get('findings', 0)} finding(s)"
        )
