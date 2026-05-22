"""
ui/menu.py
===========
Main menu loop and all interactive prompt handling.

Responsibility: render menus, capture employee input, delegate to
core/session_manager for all business logic.

Design principles:
  - No business logic. No persistence. No state mutation.
  - All decisions about WHAT to do are made in session_manager.
  - All decisions about HOW to display are made in session_views.
  - This module only decides WHEN to ask and WHICH function to call.
  - Adding a new menu option in a future phase means editing ONLY this file.

Phase 2 extension point:
  - The session action menu will gain a "View ingestion status" option.
    That addition touches only this file and session_views.py — zero
    changes to session_manager.py.

Phase 5 extension point:
  - Main menu option 3 (Generate Reports) will call reporter.run().
    One line change here; nothing else moves.
"""

import shutil
from pathlib import Path
from typing import Optional

from config.settings import (
    BANNER,
    SESSIONS_ACTIVE_DIR,
    SESSIONS_ARCHIVED_DIR,
    SessionStatus,
)
from core import session_manager as sm
from core import session_storage as storage
from models.session import Session
from ui import session_views as views
from utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------

def run_main_menu() -> None:
    """
    Main menu loop. Entry point called by main.py.
    Runs until the employee explicitly selects Exit.
    """
    print(BANNER)

    while True:
        views.header("Main Menu")
        print("  1.  Create New Assessment Session")
        print("  2.  Resume Existing Session")
        print("  3.  Generate Reports          [Phase 5 \u2014 pending]")
        print("  4.  View Sessions")
        print("  5.  Archive Completed Sessions")
        print("  6.  Exit")
        print()

        try:
            choice = input("  Select option: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n  Exiting. Goodbye.")
            break

        print()

        if choice == "1":
            _handle_create_session()

        elif choice == "2":
            _handle_resume_session()

        elif choice == "3":
            print("  [*] Report generation is implemented in Phase 5.")
            print("  [*] Complete a session first, then return here.")
            print()

        elif choice == "4":
            _handle_view_sessions()

        elif choice == "5":
            _handle_archive_sessions()

        elif choice == "6":
            print("  Exiting IntelliAssess AI. Goodbye.")
            print()
            break

        else:
            print(f"  [!] Invalid option: {choice!r}. Please select 1\u20136.")
            print()


# ---------------------------------------------------------------------------
# Menu action handlers
# These functions own: input prompts, validation, view calls.
# They delegate business operations to session_manager.
# ---------------------------------------------------------------------------

def _handle_create_session() -> None:
    """
    Prompt for a session label, call sm.create_session(), then open the
    session action menu if creation succeeded.
    """
    views.header("Create New Assessment Session")
    print()
    print("  Enter a client or session label.")
    print("  (This can be a pseudonym \u2014 it does not need to be the real client name)")
    print("  Examples:  APTECH  |  CLIENT_A  |  INTERNAL_REVIEW  |  BANK_01")
    print()

    try:
        raw_label = input("  Session label: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n\n  [!] Cancelled.")
        return

    if not raw_label:
        print("\n  [!] Session label cannot be empty. Returning to menu.")
        return

    session = sm.create_session(client_label=raw_label)
    if session:
        session_dir = storage.get_session_dir(session.session_id)
        if session_dir:
            run_session_action_menu(session, session_dir)


def _handle_resume_session() -> None:
    """
    List resumable sessions, prompt for selection, call sm.resume_session(),
    then open the session action menu.
    """
    views.header("Resume Existing Session")
    print()

    all_sessions = storage.list_sessions(SESSIONS_ACTIVE_DIR)
    resumable = [
        s for s in all_sessions
        if s.session_status in (SessionStatus.ACTIVE, SessionStatus.COMPLETE)
    ]

    if not resumable:
        print("  No active sessions found.")
        print("  Use option 1 to create a new session.")
        print()
        return

    print("  Active sessions:\n")
    views.render_session_pick_list(resumable)

    try:
        choice = input(f"  Select session [1\u2013{len(resumable)}] or Enter to cancel: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n\n  [!] Cancelled.")
        return

    if not choice:
        return

    try:
        idx = int(choice)
        if not (1 <= idx <= len(resumable)):
            raise ValueError
    except ValueError:
        print(f"\n  [!] Invalid selection: {choice!r}")
        return

    session = sm.resume_session(session_id=resumable[idx - 1].session_id)
    if session:
        session_dir = storage.get_session_dir(session.session_id)
        if session_dir:
            run_session_action_menu(session, session_dir)


def _handle_view_sessions() -> None:
    """Fetch all sessions from storage and hand to views for rendering."""
    views.header("View All Sessions")
    print()

    active_sessions   = storage.list_sessions(SESSIONS_ACTIVE_DIR)
    archived_sessions = storage.list_sessions(SESSIONS_ARCHIVED_DIR)

    if not active_sessions and not archived_sessions:
        print("  No sessions found.")
        print()
        return

    views.render_session_group("ACTIVE",   active_sessions)
    views.render_session_group("ARCHIVED", archived_sessions)


def _handle_archive_sessions() -> None:
    """
    List archivable sessions, prompt for selection, delegate archive
    operation to session_manager.
    """
    views.header("Archive Completed Sessions")
    print()

    all_active = storage.list_sessions(SESSIONS_ACTIVE_DIR)
    archivable = [
        s for s in all_active
        if s.session_status in (SessionStatus.COMPLETE, SessionStatus.REPORT_GENERATED)
    ]

    if not archivable:
        print("  No completed sessions available for archival.")
        print("  Sessions must be in COMPLETE or REPORT_GENERATED status.")
        print()
        return

    print("  Sessions eligible for archival:\n")
    views.render_archive_pick_list(archivable)

    try:
        choice = input("  Select: ").strip().upper()
    except (KeyboardInterrupt, EOFError):
        print("\n\n  [!] Cancelled.")
        return

    if choice in ("X", ""):
        print("\n  [*] Archival cancelled.")
        return

    targets_to_archive: list[Session] = []

    if choice == "A":
        targets_to_archive = archivable
    else:
        try:
            idx = int(choice)
            if not (1 <= idx <= len(archivable)):
                raise ValueError
            targets_to_archive = [archivable[idx - 1]]
        except ValueError:
            print(f"\n  [!] Invalid selection: {choice!r}")
            return

    for sess in targets_to_archive:
        sm.archive_session(sess)


# ---------------------------------------------------------------------------
# Session action menu
# ---------------------------------------------------------------------------

def run_session_action_menu(session: Session, session_dir: Path) -> None:
    """
    Context menu shown while the employee is working inside a session.

    Options (Phase 1):
      1. Mark session complete & generate report
      2. View session details
      3. Return to main menu

    Phase 2 extension point: add option for ingestion/watcher status.
    Phase 5 extension point: add option to view generated report path.
    """
    while True:
        # Refresh from disk each iteration. The watcher ingests files on
        # background worker threads and persists session.json via session_storage
        # (atomic tmp+rename write). The `session` passed in is a point-in-time
        # snapshot from create/resume time, so we re-read the single source of
        # truth before rendering or acting — otherwise the header and detail view
        # show stale counts (Files: 0) and completion would persist the stale
        # snapshot, clobbering the watcher's on-disk updates. On a rare load miss
        # we keep the previous snapshot rather than failing.
        refreshed = storage.load(session_dir)
        if refreshed is not None:
            session = refreshed

        views.render_session_action_header(session)
        print("  1.  Mark session complete & generate report")
        print("  2.  View session details")
        print("  3.  Return to main menu")
        print()

        try:
            choice = input("  Select option: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n  [!] Returning to main menu.")
            return

        if choice == "1":
            _handle_complete_session(session, session_dir)
            return

        elif choice == "2":
            views.render_session_detail(session)

        elif choice == "3":
            return

        else:
            print(f"\n  [!] Invalid option: {choice!r}")


def _handle_complete_session(session: Session, session_dir: Path) -> None:
    """
    Show completion confirmation panel, get employee confirmation,
    then delegate to sm.complete_session().
    """
    if session.session_status == SessionStatus.REPORT_GENERATED:
        print("\n  [*] Report already generated for this session.")
        print(f"      Report location: {session_dir / 'reports'}")
        return

    if session.session_status == SessionStatus.ARCHIVED:
        print("\n  [!] This session has been archived. Cannot modify.")
        return

    views.render_completion_confirmation_panel(session)

    try:
        confirm = input("  Proceed? (Y/N): ").strip().upper()
    except (KeyboardInterrupt, EOFError):
        print("\n\n  [!] Cancelled.")
        return

    if confirm != "Y":
        print("\n  [*] Completion cancelled. Session remains active.")
        return

    sm.complete_session(session, session_dir)
