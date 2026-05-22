"""
ui/session_views.py
====================
All formatted console display functions for session data.

Responsibility: know how to render Session objects to the console.
Nothing else.

Design principles:
  - Zero business logic. Pure presentation.
  - All functions accept Session objects (or lists of them) as arguments.
  - No imports from core/session_manager — no circular dependencies.
  - No calls to session_storage — display only, never persists.
  - Easily replaceable: swap this file for a rich/curses renderer in future
    without touching any business logic.

Used by:
  - ui/menu.py         (menus call these to render choices and details)
  - Future phases may call these directly when displaying report status
"""

from pathlib import Path
from typing import Optional

from models.session import Session


# ---------------------------------------------------------------------------
# Primitive rendering helpers
# ---------------------------------------------------------------------------

DIVIDER_CHAR_THIN  = "-"
DIVIDER_CHAR_THICK = "="
DIVIDER_WIDTH      = 52


def divider(char: str = DIVIDER_CHAR_THIN, width: int = DIVIDER_WIDTH) -> None:
    """Print a horizontal divider line."""
    print(char * width)


def header(title: str) -> None:
    """Print a titled section header between two thin dividers."""
    divider()
    print(f"  {title}")
    divider()


# ---------------------------------------------------------------------------
# Session pick-list (used in resume and archive flows)
# ---------------------------------------------------------------------------

def render_session_pick_list(sessions: list[Session]) -> None:
    """
    Render a numbered pick-list of sessions for employee selection.

    Displays: index, session_id, label, status, created date, targets, tools, files.
    Called from ui/menu.py resume and archive flows.
    """
    for idx, sess in enumerate(sessions, start=1):
        targets_str = ", ".join(sess.targets) if sess.targets else "\u2014"
        tools_str   = " | ".join(sess.tools_detected) if sess.tools_detected else "\u2014"
        print(f"  [{idx}]  {sess.session_id}")
        print(f"       Label:    {sess.client_label}")
        print(f"       Status:   {sess.session_status}")
        print(f"       Created:  {sess.created_at}")
        print(f"       Targets:  {targets_str}")
        print(f"       Tools:    {tools_str}")
        print(f"       Files:    {sess.files_detected}")
        print()


def render_archive_pick_list(sessions: list[Session]) -> None:
    """
    Render a compact numbered pick-list for the archival selection flow.
    Shows session_id and status only — brevity is appropriate here.
    """
    for idx, sess in enumerate(sessions, start=1):
        print(f"  [{idx}]  {sess.session_id}  ({sess.session_status})")
    print("  [A]  Archive all listed sessions")
    print("  [X]  Cancel")
    print()


# ---------------------------------------------------------------------------
# Session detail view
# ---------------------------------------------------------------------------

def render_session_detail(session: Session) -> None:
    """
    Render the full session metadata record to console.
    Shown when the employee selects 'View session details' from the action menu.
    """
    print()
    divider(DIVIDER_CHAR_THICK)
    print(f"  Session Details \u2014 {session.session_id}")
    divider()
    print(f"  ID:           {session.session_id}")
    print(f"  Label:        {session.client_label}")
    print(f"  Status:       {session.session_status}")
    print(f"  Created:      {session.created_at}")
    print(f"  Updated:      {session.updated_at}")
    print(f"  Files:        {session.files_detected}")
    print(f"  Targets:      {', '.join(session.targets) or '\u2014'}")
    print(f"  Tools:        {' | '.join(session.tools_detected) or '\u2014'}")
    print(f"  Report Gen.:  {session.report_generated}")
    print(f"  Archived:     {session.archived}")

    ctx = session.context
    if any(v is not None for v in ctx.values()):
        print()
        print("  Context:")
        for key, val in ctx.items():
            if val is not None:
                print(f"    {key:<16} {val}")

    divider(DIVIDER_CHAR_THICK)


# ---------------------------------------------------------------------------
# Session group list (used in view_sessions)
# ---------------------------------------------------------------------------

def render_session_group(group_label: str, sessions: list[Session]) -> None:
    """
    Render a labelled group of sessions (e.g. ACTIVE or ARCHIVED).
    Displays a compact summary row per session.
    """
    if not sessions:
        return
    print(f"  \u2500\u2500 {group_label} ({len(sessions)}) \u2500\u2500")
    print()
    for sess in sessions:
        targets_str = ", ".join(sess.targets) if sess.targets else "\u2014"
        print(f"  {sess.session_id}")
        print(f"    Status:   {sess.session_status}")
        print(f"    Label:    {sess.client_label}")
        print(f"    Created:  {sess.created_at}")
        print(f"    Targets:  {targets_str}")
        print(f"    Files:    {sess.files_detected}")
        print()


# ---------------------------------------------------------------------------
# Session action menu header (shown inside a live session context)
# ---------------------------------------------------------------------------

def render_session_action_header(session: Session) -> None:
    """
    Render the contextual header shown at the top of the session action menu.
    Provides a live status summary while the employee is working in a session.
    """
    print()
    header(f"Session: {session.session_id}")
    print(f"  Status:   {session.session_status}")
    print(f"  Targets:  {', '.join(session.targets) or '\u2014'}")
    print(f"  Files:    {session.files_detected}")
    print(f"  Tools:    {' | '.join(session.tools_detected) or '\u2014'}")
    print()


# ---------------------------------------------------------------------------
# Inline confirmation panels (used in completion and archival flows)
# ---------------------------------------------------------------------------

def render_completion_confirmation_panel(session: Session) -> None:
    """
    Render the confirmation panel shown before session completion.
    Summarizes what will be finalized and warns if no files have been ingested.
    """
    print()
    divider()
    print("  Complete session & generate report?")
    print(f"  Session: {session.session_id}")
    print(f"  Targets: {', '.join(session.targets) or '(none yet)'}")
    print(f"  Files:   {session.files_detected}")
    divider()

    if session.files_detected == 0:
        print()
        print("  [!] WARNING: No scan files have been ingested for this session.")
        print("      The generated report will be empty.")
        print("      Consider dropping scan outputs into the incoming/ folder first.")
        print()


def render_completion_result(session_id: str) -> None:
    """Render the success confirmation after a session is marked complete."""
    print()
    divider(DIVIDER_CHAR_THICK)
    print(f"  [+] Session marked COMPLETE: {session_id}")
    print("  [+] Use 'Archive Completed Sessions' when ready.")
    divider(DIVIDER_CHAR_THICK)
    print()


# ---------------------------------------------------------------------------
# Creation and resume result panels
# ---------------------------------------------------------------------------

def render_session_created(session_id: str, session_dir: Path) -> None:
    """Render the success confirmation after a new session is created."""
    from config.settings import SessionStatus
    print()
    divider(DIVIDER_CHAR_THICK)
    print(f"  [+] Session created:  {session_id}")
    print(f"  [+] Session folder:   {session_dir}")
    print(f"  [+] Status:           {SessionStatus.ACTIVE}")
    print()
    print("  [*] Drop scan outputs into:")
    print(f"      {session_dir / 'incoming'}")
    print()
    print("  [*] File watcher: PENDING (Phase 2 \u2014 not yet active)")
    divider(DIVIDER_CHAR_THICK)
    print()


def render_session_resumed(session_id: str, status: str) -> None:
    """Render the confirmation after a session is successfully resumed."""
    print()
    divider(DIVIDER_CHAR_THICK)
    print(f"  [+] Session resumed:  {session_id}")
    print(f"  [+] Status:           {status}")
    print("  [*] File watcher:     PENDING (Phase 2 \u2014 not yet active)")
    divider(DIVIDER_CHAR_THICK)
    print()
