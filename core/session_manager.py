"""
core/session_manager.py
========================
Session lifecycle management — business logic and orchestration only.

Responsibility: own the session domain. Nothing else.

  - Session identity construction (IDs, timestamps)
  - Session folder initialization
  - Session creation (domain object + persistence)
  - Session resumption (load + refresh)
  - Session completion (state transition + full pipeline orchestration)
  - Session archival (state mutation + filesystem move)

What this module does NOT own:
  - Menu rendering → ui/menu.py
  - Session display → ui/session_views.py
  - Input prompts  → ui/menu.py
  - JSON I/O       → core/session_storage.py
  - Parsing logic  → intelligence/parsers/
  - AI enrichment  → ai/analyzer.py
  - DOCX assembly  → reporting/reporter.py

Phase integration status:
  - Phase 2A-2 (watcher):  COMPLETE — watcher lifecycle fully integrated.
  - Phase 4-4 (context):   COMPLETE — metadata_collector.collect() replaces hardcoded stub.
  - Phase 4-3 (pipeline):  COMPLETE — complete_session() runs the full
    parse → enrich → report pipeline via _aggregate_parsed_data().
  - Phase 5   (compliance): DEFERRED — compliance_engine stub preserved for future phase.

Design contract for complete_session():
  1. Stop the watcher (no new files mid-pipeline).
  2. Aggregate ParsedScanData from processed/ via _aggregate_parsed_data().
  3. Run AI enrichment via analyzer.run() — always succeeds (graceful degradation built in).
  4. Generate DOCX via generate_docx() — always succeeds (graceful degradation built in).
  5. Update session metadata: REPORT_GENERATED status, report_path, timestamps.
  6. Persist final session.json.

Graceful-failure contract:
  Every stage in complete_session() is individually failure-tolerant.
  The pipeline never halts on a single file's parse failure, Gemini
  unavailability, or a partial report. The session reaches a stable
  persisted state regardless of intermediate errors.
"""

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config.settings import (
    SESSION_SUBDIRS,
    SESSIONS_ACTIVE_DIR,
    SESSIONS_ARCHIVED_DIR,
    SessionStatus,
)
from core import session_storage as storage
from core import watcher
from models.session import Session
from ui import session_views as views
from utils.file_utils import ensure_dirs
from utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Domain helpers — session identity and folder management
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string (no microseconds)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _make_session_id(label: str) -> str:
    """
    Construct a unique, filesystem-safe session ID from a label and timestamp.

    Format: <SANITIZED_LABEL>_<YYYYMMDD>_<HHMM>
    Example: APTECH_20260520_1430

    Non-alphanumeric characters (except underscore) are replaced.
    """
    clean_label = "".join(
        c if (c.isalnum() or c == "_") else "_"
        for c in label.upper().strip()
    ).strip("_") or "SESSION"

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return f"{clean_label}_{timestamp}"


def _build_session_dir(session_id: str) -> Path:
    """Return the full path for a new active session directory."""
    return SESSIONS_ACTIVE_DIR / session_id


def _initialize_session_folder(session_dir: Path) -> None:
    """Create the session directory and all required subdirectories."""
    subdirs = [session_dir / sub for sub in SESSION_SUBDIRS]
    ensure_dirs(session_dir, *subdirs)
    log.debug("Session folder initialized: %s", session_dir)


# ---------------------------------------------------------------------------
# Watcher lifecycle helpers — Phase 2A-2
# ---------------------------------------------------------------------------

def _start_watcher(session_id: str, session_dir: Path) -> None:
    """
    Start (or reuse) the folder watcher for a session directory.

    Watcher startup failure is non-fatal: the session remains usable and
    the employee can still drop files manually. A clear warning is logged
    so the operator knows file auto-detection is unavailable for this session
    until it is resumed (which will retry the watcher start).

    Called from create_session() and resume_session() only.
    watcher.start() is idempotent — if a watcher is already active for
    this session_id it is returned without creating a duplicate Observer.
    """
    w = watcher.start(session_dir)
    if w is None:
        log.warning(
            "[%s] Watcher failed to start — file auto-detection unavailable. "
            "Resume the session to retry. Manual drops to processed/ still work.",
            session_id,
        )
    else:
        log.debug("[%s] Watcher active", session_id)


# ---------------------------------------------------------------------------
# Session creation
# ---------------------------------------------------------------------------

def create_session(client_label: str) -> Optional[Session]:
    """
    Create a new assessment session from a client label.

    Builds a unique session ID, initializes the folder structure,
    persists session.json, starts the folder watcher, and returns
    the Session object.

    Returns None on collision or persistence failure.
    Watcher startup failure is non-fatal: the session is still returned
    and the employee can drop files manually; watcher retries on resume.
    The caller (ui/menu.py) owns label validation and display.
    """
    session_id  = _make_session_id(client_label)
    session_dir = _build_session_dir(session_id)

    # Guard: session ID collision (same label, same minute)
    if session_dir.exists():
        log.warning("Session ID collision: %s", session_id)
        print(f"\n  [!] Session ID already exists: {session_id}")
        print("  This can occur if two sessions are created within the same minute.")
        print("  Please wait a moment and try again.")
        return None

    _initialize_session_folder(session_dir)

    now = _now_iso()
    session = Session(
        session_id=     session_id,
        client_label=   client_label,
        session_status= SessionStatus.ACTIVE,
        created_at=     now,
        updated_at=     now,
    )

    if not storage.save(session, session_dir):
        print(f"\n  [!] Failed to write session metadata. Check permissions: {session_dir}")
        return None

    # ── Phase 2A-2: start session watcher ────────────────────────────
    _start_watcher(session_id, session_dir)

    views.render_session_created(session_id, session_dir)
    log.info("Session created: %s (label=%r)", session_id, client_label)
    return session


# ---------------------------------------------------------------------------
# Session resumption
# ---------------------------------------------------------------------------

def resume_session(session_id: str) -> Optional[Session]:
    """
    Load and refresh an existing session by ID.

    Updates updated_at timestamp on resume and restarts the folder watcher.
    Returns the refreshed Session, or None if not found.

    Watcher startup is idempotent — if a watcher is already active for
    this session_id it is reused without creating a duplicate observer.
    Startup failure is non-fatal; the session is still returned.
    """
    session_dir = storage.get_session_dir(session_id)
    if session_dir is None:
        log.warning("Resume: session directory not found for %s", session_id)
        print(f"\n  [!] Could not locate session directory for: {session_id}")
        return None

    session = storage.load(session_dir)
    if session is None:
        return None

    session.updated_at = _now_iso()
    storage.save(session, session_dir)

    # ── Phase 2A-2: restart session watcher ──────────────────────────
    _start_watcher(session_id, session_dir)

    views.render_session_resumed(session.session_id, session.session_status)
    log.info("Session resumed: %s", session_id)
    return session


# ---------------------------------------------------------------------------
# Finalization helpers — Phase 4-3
# ---------------------------------------------------------------------------

def _aggregate_parsed_data(session_dir: Path) -> list:
    """
    Re-classify and re-parse every file in processed/ for final report generation.

    This is deliberately a re-parse (not reading cached state) because:
      - Files arrive asynchronously during an assessment; at completion time
        we want one deterministic, synchronous parse of the complete file set.
      - Avoids dependency on any cached per-file state from ingest threads.
      - registry.parse_file() is idempotent and side-effect-free.

    Returns:
        list[ParsedScanData] — one entry per successfully classified file.
        Returns an empty list if processed/ is missing or empty — callers
        handle this gracefully (analyzer.run and generate_docx both accept []).

    Graceful-failure contract:
        Never raises. Per-file errors are logged and skipped. Other files
        continue to be processed regardless of any single file's failure.
    """
    # Lazy imports — keeps session_manager.py decoupled from intelligence/
    # parsers at module load time. No circular import risk; avoids loading
    # the full parse stack for every session_manager import.
    from intelligence.file_classifier import ToolType, classify_with_subtype
    from parsers.registry import parse_file

    processed_dir = session_dir / "processed"
    results: list = []

    if not processed_dir.is_dir():
        log.warning(
            "_aggregate_parsed_data: processed/ not found — %s",
            session_dir,
        )
        return results

    candidate_files = sorted(
        f for f in processed_dir.iterdir()
        if f.is_file() and not f.name.endswith(".error.txt")
    )

    if not candidate_files:
        log.info("_aggregate_parsed_data: no files in processed/ for %s", session_dir.name)
        return results

    log.info(
        "_aggregate_parsed_data: processing %d file(s) from processed/",
        len(candidate_files),
    )

    for file_path in candidate_files:
        try:
            tool_type, nmap_subtype, confidence = classify_with_subtype(file_path)

            if tool_type is ToolType.UNKNOWN:
                log.debug(
                    "_aggregate_parsed_data: skipping UNKNOWN tool type: %s",
                    file_path.name,
                )
                continue

            parsed = parse_file(file_path, tool_type, nmap_subtype)

            if parsed.has_errors:
                for err in parsed.parse_errors:
                    log.debug(
                        "_aggregate_parsed_data: parse_error [%s]: %s",
                        file_path.name, err,
                    )

            results.append(parsed)
            log.info(
                "_aggregate_parsed_data: [%s] tool=%s findings=%d assets=%d",
                file_path.name,
                tool_type.value,
                len(parsed.findings),
                len(parsed.assets),
            )

        except Exception as exc:
            # Defensive catch: a parser bug or IO error on one file must not
            # abort the entire finalization pipeline.
            log.error(
                "_aggregate_parsed_data: unexpected error for %s: %s",
                file_path.name, exc,
                exc_info=True,
            )
            continue

    log.info(
        "_aggregate_parsed_data: aggregation complete — %d ParsedScanData object(s)",
        len(results),
    )
    return results


# ---------------------------------------------------------------------------
# Session completion
# ---------------------------------------------------------------------------

def complete_session(session: Session, session_dir: Path) -> None:
    """
    Transition a session through COMPLETE and run the full assessment pipeline.

    Orchestration sequence (Phase 4-3):
      1. Collect context interactively (Phase 4-4 — metadata_collector)
      2. Transition → COMPLETE + persist (safe recovery point before pipeline)
      3. Stop watcher            (no new files during finalization)
      4. Aggregate ParsedScanData from processed/
      5. Run Gemini AI enrichment → EnrichedReport
      6. Generate DOCX report    → reports/security_report.docx
      7. Update session metadata → REPORT_GENERATED + report_path
      8. Persist final session.json

    Graceful-failure contract:
      Each stage is individually failure-tolerant. Even if Gemini is
      unavailable or a parser returns partial data, the DOCX is still
      generated and the session reaches a persisted REPORT_GENERATED state.
      If the DOCX file cannot be confirmed on disk, the session retains
      COMPLETE status so the operator can retry without data loss.

    The calling flow (ui/menu.py) obtains employee confirmation before
    calling this function. This function owns only state transitions and
    pipeline orchestration — no UI rendering, no prompting.
    """
    # Lazy imports — the AI and reporting stacks are only loaded at report
    # generation time, not at every session_manager import.
    from ai import analyzer
    from reporting import generate_docx

    # ── 1. Interactive context collection (Phase 4-4) ─────────────────────
    # Replaces the Phase 3 hardcoded-defaults stub.
    # metadata_collector.collect() prompts the operator for exposure,
    # environment, sector, and optional company details, then writes the
    # collected values into session.context in-place.
    # collect() never raises — safe defaults are applied internally if
    # the operator skips every prompt or if an unexpected error occurs.
    from core import metadata_collector
    metadata_collector.collect(session)

    # ── 2. Transition → COMPLETE and persist (safe recovery point) ────────
    # Persisting COMPLETE before the pipeline ensures that if the process
    # crashes mid-pipeline, the session is still in a recoverable state.
    # The final save at step 7 will upgrade this to REPORT_GENERATED.
    session.session_status = SessionStatus.COMPLETE
    session.updated_at     = _now_iso()
    storage.save(session, session_dir)
    log.info("[%s] State → COMPLETE (pre-pipeline save)", session.session_id)

    # ── 3. Stop watcher ───────────────────────────────────────────────────
    # Critical ordering: watcher must be stopped before aggregation so that
    # no new files are ingested while we are reading processed/.
    watcher.stop(session.session_id)

    # ── 4. Aggregate ParsedScanData from processed/ ───────────────────────
    print()
    print("  [*] Parsing processed scan files...")
    parsed_data_list = _aggregate_parsed_data(session_dir)

    file_count = len(parsed_data_list)
    if file_count == 0:
        print("  [!] No parseable files found in processed/.")
        print("      The report will be generated with no findings data.")
    else:
        total_findings = sum(len(p.findings) for p in parsed_data_list)
        total_assets   = sum(len(p.assets)   for p in parsed_data_list)
        print(
            f"  [+] Parsed {file_count} file(s) — "
            f"{total_findings} finding(s), {total_assets} asset(s)."
        )

    # ── 5. AI enrichment ─────────────────────────────────────────────────
    # analyzer.run() never raises — graceful degradation is built into the
    # AI layer. If Gemini is unavailable, EnrichedReport has enriched=False
    # and the reporter uses statistical fallback sections instead.
    print()
    print("  [*] Running AI enrichment pipeline...")
    try:
        enriched = analyzer.run(parsed_data_list, session.context)
        if enriched.enrichment_complete:
            print("  [+] AI enrichment: complete.")
        else:
            err_count = len(enriched.enrichment_errors)
            if err_count:
                print(
                    f"  [!] AI enrichment: partial ({err_count} error(s) — "
                    "Gemini unavailable or quota exceeded)."
                )
            else:
                print("  [!] AI enrichment: unavailable — report uses statistical fallback.")
    except Exception as exc:
        # Belt-and-suspenders: analyzer.run() is documented to never raise,
        # but we catch defensively so a bug there never kills the pipeline.
        log.error(
            "[%s] Unexpected error in analyzer.run(): %s",
            session.session_id, exc,
            exc_info=True,
        )
        from ai.models import AIExecutiveSummary, EnrichedReport as _ER
        enriched = _ER(
            executive_summary   = AIExecutiveSummary(),
            enrichment_complete = False,
            enrichment_errors   = [f"Unexpected analyzer error: {exc}"],
            primary_targets     = list(session.targets),
            session_context     = session.context,
        )
        print("  [!] AI enrichment: unexpected error — report uses statistical fallback.")

    # ── 6. DOCX generation ────────────────────────────────────────────────
    # generate_docx() never raises — graceful degradation is built into the
    # reporting layer. The reports/ subdirectory is guaranteed to exist
    # (created by _initialize_session_folder at session creation time).
    print()
    print("  [*] Generating DOCX report...")
    reports_dir  = session_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)   # Idempotent safety guard
    output_path  = reports_dir / "security_report.docx"

    try:
        report_path = generate_docx(parsed_data_list, enriched, session, output_path)
    except Exception as exc:
        # Belt-and-suspenders: generate_docx() is documented to never raise.
        log.error(
            "[%s] Unexpected error in generate_docx(): %s",
            session.session_id, exc,
            exc_info=True,
        )
        report_path = output_path   # Fallback: record intended path even if save failed

    report_confirmed = report_path.exists()

    if report_confirmed:
        report_size_kb = report_path.stat().st_size // 1024
        print(f"  [+] Report saved: {report_path}  ({report_size_kb} KB)")
        log.info("[%s] DOCX report saved → %s", session.session_id, report_path)
    else:
        print("  [!] Report file could not be confirmed on disk — check logs.")
        log.error(
            "[%s] DOCX report not found at expected path: %s",
            session.session_id, report_path,
        )

    # ── 7. Update session metadata ────────────────────────────────────────
    # Upgrade status to REPORT_GENERATED only when the file is confirmed.
    # If not confirmed, session remains COMPLETE so the operator can retry.
    if report_confirmed:
        session.session_status  = SessionStatus.REPORT_GENERATED
        session.report_generated = True
        session.report_path      = str(report_path)
    # else: session_status stays COMPLETE (already saved at step 2)

    session.updated_at = _now_iso()
    storage.save(session, session_dir)

    log.info(
        "[%s] Finalization complete — status=%s enriched=%s report=%s",
        session.session_id,
        session.session_status,
        enriched.enrichment_complete,
        report_confirmed,
    )

    # ── Phase 5 stub: compliance engine (deferred) ────────────────────────
    # compliance_engine.run(session, parsed_data_list)  # Phase 5

    views.render_completion_result(session.session_id)


# ---------------------------------------------------------------------------
# Session archival
# ---------------------------------------------------------------------------

def archive_session(session: Session) -> bool:
    """
    Archive a single session: update metadata, move directory to archived/.

    Returns True on success, False if the source directory is missing
    or the session is already archived.
    """
    src_dir = SESSIONS_ACTIVE_DIR / session.session_id
    dst_dir = SESSIONS_ARCHIVED_DIR / session.session_id

    if not src_dir.is_dir():
        log.warning("Archive: source directory not found: %s", src_dir)
        return False

    if dst_dir.exists():
        print(f"  [!] Already archived: {session.session_id}")
        return False

    SESSIONS_ARCHIVED_DIR.mkdir(parents=True, exist_ok=True)

    # ── Phase 2A-2: stop watcher before moving session directory ──────
    # ORDERING IS CRITICAL: watcher must be stopped before shutil.move().
    # An active watchdog observer on a directory that is subsequently moved
    # will raise filesystem errors on some platforms (Windows especially).
    watcher.stop(session.session_id)

    session.session_status = SessionStatus.ARCHIVED
    session.archived       = True
    session.updated_at     = _now_iso()
    storage.save(session, src_dir)

    shutil.move(str(src_dir), str(dst_dir))
    print(f"  [+] Archived: {session.session_id} \u2192 {dst_dir}")
    log.info("Session archived: %s", session.session_id)
    return True
