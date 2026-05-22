"""
main.py
=======
IntelliAssess AI — Entry Point

This module is intentionally thin. It:
  1. Bootstraps required directory structure
  2. Initializes the logger
  3. Delegates entirely to ui/menu.run_main_menu()
  4. Guarantees watcher.stop_all() on every exit path (Phase 2A-2)

Shutdown contract (Phase 2A-2):
  All active session watchers are stopped in a finally block that wraps
  the entire menu loop. This covers:
    - Normal exit (employee selects option 6)
    - KeyboardInterrupt / Ctrl+C (caught defensively here after menu returns)
    - Unexpected exceptions propagating out of the menu loop
  watcher.stop_all() is safe to call even when no watchers are active.

No business logic belongs here. If this file grows beyond ~65 lines,
something is wrong with the separation of concerns.

Usage:
    python main.py
"""

import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so absolute imports work correctly
# regardless of how the script is invoked (python main.py vs python -m main).
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

from config.settings import (
    SESSIONS_ACTIVE_DIR,
    SESSIONS_ARCHIVED_DIR,
    LOG_DIR,
)
from utils.file_utils import ensure_dirs
from utils.logger import get_logger

log = get_logger(__name__)


def _bootstrap() -> None:
    """Create all required top-level directories before any session logic runs."""
    ensure_dirs(
        SESSIONS_ACTIVE_DIR,
        SESSIONS_ARCHIVED_DIR,
        LOG_DIR,
    )
    log.debug("Bootstrap complete. Directories verified.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    _bootstrap()

    from ui.menu import run_main_menu
    from core import watcher

    try:
        run_main_menu()
    except KeyboardInterrupt:
        # Defensive outer catch — ui/menu.py handles KeyboardInterrupt at each
        # input() call and returns normally. This guard catches any edge case
        # where an interrupt fires outside the menu's inner try/except window
        # (e.g. during startup I/O or between menu iterations).
        print("\n\n  Interrupted. Shutting down...")
        log.info("KeyboardInterrupt received at application level.")
    finally:
        # Guaranteed cleanup on every exit path — normal, interrupted, or error.
        # Stops all active watchdog observers and joins their threads (up to
        # _OBSERVER_JOIN_TIMEOUT_S per watcher). Safe to call with zero watchers.
        log.info("Application shutdown: stopping all active watchers...")
        watcher.stop_all()


if __name__ == "__main__":
    main()
