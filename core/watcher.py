"""
core/watcher.py
===============
Filesystem watcher for IntelliAssess AI — Phase 2A-1 (Hardened).

Responsibility: DETECT new files in a session's incoming/ directory and
delegate each one to core/ingest.handle_file() on a worker thread.

This module is a SENSOR, not a PROCESSOR.
  - It watches. It filters. It delegates.
  - All stabilization, deduplication, movement, and metadata updates
    are owned exclusively by core/ingest.py.
  - Zero ingestion logic belongs here.

Design principles:
  - One watchdog Observer per session (SessionWatcher wraps it).
  - Module-level registry keyed by session_id — no singletons, no globals.
  - In-flight set per handler prevents duplicate watchdog events (on_created
    + on_modified can both fire for a single file write) from spawning two
    concurrent ingest workers for the same file.
  - All worker threads are daemon threads — program exit is never blocked.
  - Every shared data structure is protected by its own threading.Lock.
  - recursive=False on the observer schedule — incoming/ is flat by design.
  - All startup and shutdown paths are wrapped defensively — watchdog failures
    never crash the platform; they log clearly and fail safely.
  - No direct print() calls — all console output is routed through the logger
    at INFO level so the operator sees it without hardcoded UI coupling.

Hardening changelog (vs Phase 2A-1 initial):
  [H1] Graceful watchdog startup failure:
         Observer.schedule() and Observer.start() are wrapped in try/except.
         On failure, state is rolled back cleanly and False is returned.
  [H2] Improved shutdown robustness:
         observer.stop() and observer.join() are individually wrapped.
         stop_all() iterates a snapshot and absorbs per-watcher exceptions.
  [H3] UI leakage removed:
         All print() calls replaced with log.info() — the console handler
         in utils/logger.py surfaces INFO to stdout, preserving operator
         visibility without coupling watcher to the UI layer.
  [H4] Defensive lifecycle guards:
         _active and _started flags are checked at every entry point.
         Double-stop is always a safe no-op.
         Observer is only joined if it was successfully started.

Public API:
  start(session_dir)        → SessionWatcher | None
  stop(session_id)          → bool
  stop_all()                → None
  is_active(session_id)     → bool
  list_active()             → list[str]

Integration contract:
  - start() is called from core/session_manager.create_session() and
    resume_session() at the Phase 2 stub sites.
  - stop() is called from session_manager.complete_session() and
    archive_session() (Phase 2A-2 integration step).
  - The only external call this module makes is:
      core.ingest.handle_file(file_path, session_dir)
    One function. One responsibility. No other coupling.
"""

import threading
from pathlib import Path
from typing import Optional

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from config.settings import (
    WATCHER_IGNORE_PREFIXES,
    WATCHER_IGNORE_SUFFIXES,
)
from core import ingest
from utils.logger import get_logger

log = get_logger(__name__)

# Max seconds to wait for an observer thread to exit during stop().
# After this window, a warning is logged and shutdown continues regardless.
_OBSERVER_JOIN_TIMEOUT_S: float = 5.0


# ---------------------------------------------------------------------------
# Module-level watcher registry
# Keyed by session_id. Entries are added on start(), removed on stop().
# ---------------------------------------------------------------------------

_registry: dict[str, "SessionWatcher"] = {}
_registry_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Filesystem event handler — one instance per SessionWatcher
# ---------------------------------------------------------------------------

class _IncomingFileHandler(FileSystemEventHandler):
    """
    Watchdog FileSystemEventHandler scoped to a single session's incoming/.

    Filtering pipeline (applied in order, early-exit on first rejection):
      1. Directory events   → always ignored
      2. Path locality      → only files directly inside incoming/ (no subdirs)
      3. Filename suffix    → reject WATCHER_IGNORE_SUFFIXES (.tmp, .part, ...)
      4. Filename prefix    → reject WATCHER_IGNORE_PREFIXES (., ~)
      5. In-flight guard    → reject files already being processed

    If all filters pass, a daemon worker thread is spawned that calls
    ingest.handle_file(file_path, session_dir). The thread removes the
    filename from the in-flight set in its finally block, so a legitimate
    re-appearance of the same filename later is correctly re-detected.
    """

    def __init__(self, session_dir: Path) -> None:
        super().__init__()
        self._session_dir  = session_dir
        self._session_id   = session_dir.name
        self._incoming_dir = session_dir / "incoming"

        # Filenames currently being processed by a worker thread.
        # Prevents duplicate watchdog events (on_created + on_modified)
        # from spawning two concurrent ingest workers for the same file.
        self._in_flight: set[str] = set()
        self._in_flight_lock      = threading.Lock()

    # ── Watchdog event entry points ────────────────────────────────────────

    def on_created(self, event: FileSystemEvent) -> None:
        """Fires when a new file appears in incoming/."""
        if not event.is_directory:
            self._handle_event(Path(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        """
        Fires when an existing file is written to.

        Many scan tools (nmap -oN, sslscan) trigger both on_created and
        on_modified during a single write. The in-flight guard absorbs the
        duplicate without any special-casing here.
        """
        if not event.is_directory:
            self._handle_event(Path(event.src_path))

    # ── Filtering and dispatch ─────────────────────────────────────────────

    def _handle_event(self, file_path: Path) -> None:
        """
        Apply the full filter pipeline. On pass, spawn a daemon worker thread.
        """
        # Filter 1: Only files directly inside incoming/ (not in subdirectories).
        # The watcher is scheduled with recursive=False — this is a safety net.
        if file_path.parent != self._incoming_dir:
            return

        name = file_path.name

        # Filter 2 & 3: Suffix and prefix ignore lists from settings.
        if self._should_ignore(name):
            log.debug("[%s] Ignored (filter): %s", self._session_id, name)
            return

        # Filter 4: In-flight guard — skip if a worker is already processing
        # this filename. Release happens in the worker's finally block.
        with self._in_flight_lock:
            if name in self._in_flight:
                log.debug(
                    "[%s] In-flight duplicate skipped: %s", self._session_id, name
                )
                return
            self._in_flight.add(name)

        # [H3] log.info instead of print() — console handler surfaces this to
        # the operator without coupling watcher to the UI rendering layer.
        log.info("[%s] New file detected: %s", self._session_id, name)

        # Spawn a daemon worker — the observer thread is never blocked.
        worker = threading.Thread(
            target=self._process_file,
            args=(file_path,),
            name=f"ingest-{self._session_id}-{name}",
            daemon=True,
        )
        worker.start()

    def _process_file(self, file_path: Path) -> None:
        """
        Worker thread body.

        Delegates entirely to ingest.handle_file(). Releases the in-flight
        guard in the finally block regardless of outcome, so a legitimate
        re-appearance of the same filename later is not silently swallowed.
        """
        try:
            ingest.handle_file(file_path, self._session_dir)
        except Exception as exc:
            # Surface unexpected ingest errors without crashing the worker
            # or poisoning the in-flight set permanently.
            log.error(
                "[%s] Unexpected ingest error for %s: %s",
                self._session_id, file_path.name, exc,
                exc_info=True,
            )
        finally:
            with self._in_flight_lock:
                self._in_flight.discard(file_path.name)

    # ── Filter predicate ───────────────────────────────────────────────────

    @staticmethod
    def _should_ignore(filename: str) -> bool:
        """
        Return True if the filename matches any ignore suffix or prefix.

        Suffix check is case-insensitive (.TMP == .tmp).
        Prefix check is case-sensitive — dot and tilde prefixes are universal.
        """
        lower = filename.lower()
        for suffix in WATCHER_IGNORE_SUFFIXES:
            if lower.endswith(suffix):
                return True
        for prefix in WATCHER_IGNORE_PREFIXES:
            if filename.startswith(prefix):
                return True
        return False


# ---------------------------------------------------------------------------
# SessionWatcher — one per active session
# ---------------------------------------------------------------------------

class SessionWatcher:
    """
    Manages a single watchdog Observer for one session's incoming/ directory.

    Lifecycle:
      __init__  → Observer allocated (not yet started)
      start()   → Observer thread running; incoming/ being monitored
      stop()    → Observer stopped and joined; watcher inactive

    The Observer runs on its own internal daemon thread (watchdog-managed).
    _IncomingFileHandler spawns additional daemon threads — one per file.

    All state mutations are protected by a threading.Lock.

    Hardening notes:
      - start() wraps both Observer.schedule() and Observer.start() in
        try/except; on any failure the observer is discarded and replaced
        with a fresh instance so the SessionWatcher remains in a clean
        (not-started) state and can be retried if needed.
      - stop() wraps both observer.stop() and observer.join() individually
        so a failure in one path does not prevent the other from running.
      - _started tracks whether Observer.start() succeeded so stop() never
        calls join() on an observer that was never started.
      - _active is set to False before the join() call so that any re-entrant
        stop() calls during shutdown return immediately.
    """

    def __init__(self, session_dir: Path) -> None:
        self._session_dir  = session_dir
        self._session_id   = session_dir.name
        self._incoming_dir = session_dir / "incoming"
        self._handler      = _IncomingFileHandler(session_dir)
        self._observer: Observer = Observer()
        self._active       = False
        # [H4] Separate flag: tracks whether Observer.start() actually ran.
        # stop() only calls join() when this is True, preventing a hang
        # on an observer that was scheduled but never started.
        self._started      = False
        self._lock         = threading.Lock()

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> bool:
        """
        Schedule the observer on incoming/ and start the watchdog thread.

        Returns True on success.
        Returns False (logging the reason) if:
          - The watcher is already active.          [H4 idempotent guard]
          - incoming/ directory does not exist.
          - Observer.schedule() raises an exception. [H1]
          - Observer.start() raises an exception.   [H1]

        On any watchdog failure the Observer is discarded and replaced with
        a fresh instance, leaving this SessionWatcher in a clean, restartable
        state.
        """
        with self._lock:
            # [H4] Idempotent guard — double-start is always safe.
            if self._active:
                log.debug("[%s] Watcher already active — no-op", self._session_id)
                return False

            if not self._incoming_dir.is_dir():
                log.error(
                    "[%s] Cannot start watcher — incoming/ not found: %s",
                    self._session_id, self._incoming_dir,
                )
                return False

            # [H1] Wrap Observer.schedule() — can raise on bad paths or
            # watchdog internal errors (e.g. inotify limit exceeded on Linux).
            try:
                self._observer.schedule(
                    self._handler,
                    str(self._incoming_dir),
                    recursive=False,  # incoming/ is flat by design
                )
            except Exception as exc:
                log.error(
                    "[%s] Observer.schedule() failed for %s: %s",
                    self._session_id, self._incoming_dir, exc,
                    exc_info=True,
                )
                # Discard the failed observer; replace with a fresh instance
                # so a future retry starts from a clean state.
                self._observer = Observer()
                return False

            # [H1] Wrap Observer.start() — can raise if the observer thread
            # cannot be created (e.g. OS thread limit reached).
            try:
                self._observer.start()
            except Exception as exc:
                log.error(
                    "[%s] Observer.start() failed: %s",
                    self._session_id, exc,
                    exc_info=True,
                )
                # Unschedule to leave observer in a neutral state before
                # replacing it, avoiding resource leaks on some platforms.
                try:
                    self._observer.unschedule_all()
                except Exception:
                    pass
                self._observer = Observer()
                return False

            self._started = True
            self._active  = True

        # [H3] log.info instead of print() — visible to operator via console
        # handler without any direct UI coupling in this module.
        log.info("[%s] Watcher started — monitoring: %s", self._session_id, self._incoming_dir)
        return True

    def stop(self) -> None:
        """
        Stop the observer and block until it has exited (up to timeout).

        Safe to call multiple times — always a no-op if already stopped. [H4]

        Shutdown sequence:
          1. Set _active = False inside the lock (re-entrant calls exit here).
          2. Release the lock before blocking operations (avoids deadlock).
          3. Call observer.stop() inside its own try/except.          [H2]
          4. Call observer.join(timeout) inside its own try/except.   [H2]
          5. Log a warning if the observer thread is still alive after timeout.
        """
        with self._lock:
            # [H4] Double-stop guard — always a clean no-op.
            if not self._active:
                return
            # Mark inactive first so any re-entrant stop() call during the
            # join() window below returns immediately without deadlocking.
            self._active = False

        # Only attempt shutdown if Observer.start() actually ran.  [H4]
        if not self._started:
            log.debug("[%s] Watcher stop — observer was never started, nothing to join", self._session_id)
            return

        # [H2] observer.stop() wrapped independently — a failure here must
        # not prevent the join() attempt below from running.
        try:
            self._observer.stop()
        except Exception as exc:
            log.warning(
                "[%s] observer.stop() raised an exception (continuing shutdown): %s",
                self._session_id, exc,
            )

        # [H2] observer.join() wrapped independently with timeout.
        try:
            self._observer.join(timeout=_OBSERVER_JOIN_TIMEOUT_S)
        except Exception as exc:
            log.warning(
                "[%s] observer.join() raised an exception: %s",
                self._session_id, exc,
            )

        # Warn if the thread is still alive after the timeout window.
        try:
            if self._observer.is_alive():
                log.warning(
                    "[%s] Observer thread still alive after %.1fs shutdown window — "
                    "it will be abandoned. This does not affect session integrity.",
                    self._session_id, _OBSERVER_JOIN_TIMEOUT_S,
                )
        except Exception:
            pass  # is_alive() itself cannot be allowed to break the shutdown path

        log.info("[%s] Watcher stopped", self._session_id)

    # ── State queries ──────────────────────────────────────────────────────

    @property
    def session_id(self) -> str:
        """The session_id this watcher is monitoring."""
        return self._session_id

    @property
    def is_active(self) -> bool:
        """True if the observer is running and monitoring incoming/."""
        with self._lock:
            return self._active

    def __repr__(self) -> str:
        return (
            f"SessionWatcher(session_id={self._session_id!r}, "
            f"active={self.is_active})"
        )


# ---------------------------------------------------------------------------
# Public module-level API
# Called by core/session_manager.py at Phase 2 stub sites.
# ---------------------------------------------------------------------------

def start(session_dir: Path) -> Optional[SessionWatcher]:
    """
    Create and start a SessionWatcher for the given session directory.

    If a watcher already exists and is active for this session_id, the
    existing watcher is returned without creating a duplicate observer.

    Returns the SessionWatcher on success, None if the observer could not
    start (e.g., incoming/ directory missing, or watchdog startup failure).

    Usage (session_manager.py Phase 2 stub site):
        import core.watcher as watcher
        watcher.start(session_dir)
    """
    session_id = session_dir.name

    with _registry_lock:
        existing = _registry.get(session_id)
        if existing is not None and existing.is_active:
            log.debug("[%s] Watcher reuse — already active", session_id)
            return existing

        w = SessionWatcher(session_dir)
        if not w.start():
            # start() logged the failure reason — caller gets None.
            return None

        _registry[session_id] = w

    return w


def stop(session_id: str) -> bool:
    """
    Stop and deregister the watcher for the given session_id.

    Pops the entry from the registry first so any concurrent start() call
    for the same session_id will create a fresh watcher rather than reusing
    a stopping one.

    Returns True if a watcher was found and stop() was called on it.
    Returns False if no watcher was registered for this session_id.

    Usage (session_manager.py complete_session / archive_session):
        import core.watcher as watcher
        watcher.stop(session.session_id)
    """
    with _registry_lock:
        w = _registry.pop(session_id, None)

    if w is None:
        log.debug("stop(): no registered watcher for session_id=%r", session_id)
        return False

    w.stop()
    return True


def stop_all() -> None:
    """
    Stop every registered watcher and clear the registry.

    Called on application exit or emergency shutdown.

    Implementation:
      - Takes a snapshot of current session_ids under the registry lock so
        the lock is not held during blocking stop() calls.
      - Each stop() is wrapped in its own try/except so one failed watcher
        shutdown never prevents the remaining watchers from being stopped. [H2]
      - After all watchers are processed, the registry is cleared of any
        entries that were not already popped by concurrent stop() calls.
    """
    # Snapshot under lock — don't hold the lock during blocking stop() calls.
    with _registry_lock:
        session_ids = list(_registry.keys())

    for sid in session_ids:
        try:
            stop(sid)
        except Exception as exc:
            # [H2] A failure in one watcher's shutdown must never abort
            # the cleanup of the remaining watchers.
            log.error(
                "stop_all(): unexpected error stopping watcher for %r: %s",
                sid, exc,
            )

    # Final cleanup: clear any residual entries left by concurrent activity.
    with _registry_lock:
        _registry.clear()

    log.info("All watchers stopped.")


def is_active(session_id: str) -> bool:
    """Return True if a watcher is currently running for session_id."""
    with _registry_lock:
        w = _registry.get(session_id)
    return w is not None and w.is_active


def list_active() -> list[str]:
    """Return a sorted list of session_ids with currently active watchers."""
    with _registry_lock:
        return sorted(sid for sid, w in _registry.items() if w.is_active)
