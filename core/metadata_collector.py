"""
core/metadata_collector.py
===========================
Lightweight interactive assessment-context collection — Phase 4-4.

Responsibility: prompt the operator for assessment context and write
structured values into session.context. Nothing else.

  - NO business logic
  - NO session persistence  (that is session_manager.py's job)
  - NO AI calls             (that is analyzer.py's job)
  - NO report logic         (that is reporter.py's job)

Design principles:
  - All option sets are imported from config/settings.py — single source of truth.
  - Numbered menu picks prevent freetext typos on required enum fields.
  - Enter to skip on any field — sensible defaults are applied silently.
  - Optional freetext section is gated behind a Y/N prompt to keep the
    happy-path workflow fast (≈10 seconds total).
  - All input() calls are wrapped in try/except (KeyboardInterrupt, EOFError)
    so Ctrl+C mid-collection falls back to defaults without crashing.
  - collect() always returns — it never raises. Partial collection is valid.
  - Already-set context values are preserved (allows future re-collection).

Integration point:
  Called from core/session_manager.py → complete_session(), replacing the
  hardcoded defaults stub at step 1 of the orchestration sequence.

  Usage:
      from core import metadata_collector
      metadata_collector.collect(session)

  After collect() returns, session.context is populated with whatever
  the operator provided, falling back to sensible defaults for skipped
  required fields. The caller (session_manager) then persists the session.

Operator experience:
  Phase A — Required context:  Exposure, Environment, Sector  (~15 seconds)
  Phase B — Optional details:  Company name, scope notes, infra notes  (skippable)

  Total fast-path: ~5 seconds (all defaults accepted).
  Total full-path: ~30 seconds (all fields provided).
"""

from __future__ import annotations

from config.settings import (
    EXPOSURE_OPTIONS,
    ENVIRONMENT_OPTIONS,
    SECTOR_OPTIONS,
)
from models.session import Session
from utils.logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Internal display helpers
# ---------------------------------------------------------------------------

_DIVIDER = "-" * 52


def _section(title: str) -> None:
    """Print a titled section separator matching the existing UI style."""
    print()
    print(_DIVIDER)
    print(f"  {title}")
    print(_DIVIDER)


def _print_menu(options: dict[str, str], default_key: str | None = None) -> None:
    """
    Render a numbered option list.

    Args:
        options:     Ordered dict of key → display label.
        default_key: If provided, marks that option as the default choice.
    """
    for key, label in options.items():
        marker = " (default)" if key == default_key else ""
        print(f"  [{key}] {label.capitalize()}{marker}")
    print()


def _pick(
    options:     dict[str, str],
    default_key: str | None = None,
) -> str:
    """
    Prompt for a numbered menu pick.

    Accepts: a valid key string from `options`.
    Fallback: if Enter is pressed or an invalid key is entered, returns the
              value mapped to `default_key` (or the first option's value).

    Returns:
        The selected option value (e.g. "public", "production").
    """
    valid_keys = set(options.keys())
    fallback_key = default_key or next(iter(options))

    try:
        raw = input("  Select: ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        raw = ""

    if raw in valid_keys:
        return options[raw]

    # Silently apply default — no warning needed, defaults are intentional.
    return options[fallback_key]


def _freetext(prompt: str, max_chars: int = 120) -> str | None:
    """
    Prompt for an optional freetext field.

    Returns None if the operator presses Enter (field intentionally skipped).
    Truncates to max_chars to prevent bloated session.json entries.
    """
    try:
        raw = input(f"  {prompt} (Enter to skip): ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return None

    if not raw:
        return None

    if len(raw) > max_chars:
        raw = raw[:max_chars]
        log.debug("metadata_collector: freetext truncated to %d chars", max_chars)

    return raw


# ---------------------------------------------------------------------------
# Phase A — Required context  (exposure, environment, sector)
# ---------------------------------------------------------------------------

def _collect_required(session: Session) -> None:
    """
    Collect the three required context fields via numbered menus.

    Fields: exposure, environment, sector.

    All three have sensible defaults so the operator can press Enter
    on every prompt and proceed immediately. The defaults mirror the
    previous hardcoded stub behaviour so existing workflows are unchanged
    when the operator skips everything.

    Defaults:
      exposure    → "public"      (key "1")
      environment → "production"  (key "1")
      sector      → None          (Enter on sector = unspecified)
    """
    _section("Assessment Context  —  Required")
    print("  Press Enter to accept the default for any field.")
    print()

    # ── Exposure ─────────────────────────────────────────────────────────
    print("  Exposure type:")
    _print_menu(EXPOSURE_OPTIONS, default_key="1")
    exposure = _pick(EXPOSURE_OPTIONS, default_key="1")
    session.context["exposure"] = exposure
    log.debug("metadata_collector: exposure = %r", exposure)

    # ── Environment ───────────────────────────────────────────────────────
    print("  Environment:")
    _print_menu(ENVIRONMENT_OPTIONS, default_key="1")
    environment = _pick(ENVIRONMENT_OPTIONS, default_key="1")
    session.context["environment"] = environment
    log.debug("metadata_collector: environment = %r", environment)

    # ── Sector ────────────────────────────────────────────────────────────
    # Sector is structurally optional — a generic assessment with no sector
    # context is valid. Enter = None, which Gemini prompts handle gracefully.
    print("  Industry sector:")
    print("  (Enter to skip — leave unspecified for generic assessments)")
    _print_menu(SECTOR_OPTIONS)
    sector_raw = None
    valid_sector_keys = set(SECTOR_OPTIONS.keys())
    try:
        raw = input("  Select: ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        raw = ""

    if raw in valid_sector_keys:
        sector_raw = SECTOR_OPTIONS[raw]

    session.context["sector"] = sector_raw
    log.debug("metadata_collector: sector = %r", sector_raw)


# ---------------------------------------------------------------------------
# Phase B — Optional company metadata
# ---------------------------------------------------------------------------

def _collect_optional(session: Session) -> None:
    """
    Optionally collect company and scope metadata behind a Y/N gate.

    If the operator declines the gate prompt, no further prompts are shown
    and the session proceeds immediately. This keeps the fast path fast.

    Fields collected: company_name, scope_notes, infra_notes.
    (asset_owner is available in the Session model but deferred to avoid
    over-prompting; can be added here in a future micro-phase.)
    """
    _section("Company Details  —  Optional")
    print("  Would you like to provide additional company details?")
    print("  These improve the quality of executive summaries and narratives.")
    print()

    try:
        gate = input("  Provide details? [Y/N]: ").strip().upper()
    except (KeyboardInterrupt, EOFError):
        print()
        gate = "N"

    if gate != "Y":
        print()
        print("  [*] Company details skipped.")
        return

    print()

    # ── Company name ──────────────────────────────────────────────────────
    company = _freetext("Company name")
    if company:
        session.context["company_name"] = company

    # ── Scope notes ───────────────────────────────────────────────────────
    scope = _freetext("Assessment scope notes")
    if scope:
        session.context["scope_notes"] = scope

    # ── Infrastructure notes ──────────────────────────────────────────────
    infra = _freetext("Infrastructure notes")
    if infra:
        session.context["infra_notes"] = infra

    log.debug(
        "metadata_collector: optional fields — company=%r scope=%r infra=%r",
        session.context.get("company_name"),
        session.context.get("scope_notes"),
        session.context.get("infra_notes"),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect(session: Session) -> None:
    """
    Collect assessment context from the operator and populate session.context.

    Orchestration:
      Phase A — Required context  (exposure, environment, sector)
      Phase B — Optional details  (company name, scope, infra notes) — gated

    Design contract:
      - Never raises. All exceptions are caught internally; partial context
        is always valid and the pipeline continues regardless.
      - Already-populated fields in session.context are overwritten only if
        the operator provides a new value. Fields the operator skips retain
        their previous value (supporting future resume-and-re-collect flows).
      - Caller (session_manager.complete_session) is responsible for
        persisting the session after this function returns.

    Args:
        session: Live Session object. session.context is mutated in-place.
    """
    log.info("[%s] metadata_collector.collect() — starting", session.session_id)

    try:
        _collect_required(session)
    except Exception as exc:
        # Defensive catch — _collect_required should never raise, but if it
        # does (e.g. unexpected terminal condition), apply safe defaults and
        # continue. The pipeline must not die at the context-collection stage.
        log.error(
            "[%s] metadata_collector: required collection failed (%s) — "
            "applying safe defaults.",
            session.session_id, exc,
            exc_info=True,
        )
        session.context.setdefault("exposure",    "public")
        session.context.setdefault("environment", "production")
        session.context.setdefault("sector",      None)

    try:
        _collect_optional(session)
    except Exception as exc:
        # Optional collection failure is completely non-fatal.
        log.warning(
            "[%s] metadata_collector: optional collection failed (%s) — skipping.",
            session.session_id, exc,
        )

    log.info(
        "[%s] metadata_collector.collect() — complete. "
        "exposure=%r environment=%r sector=%r company=%r",
        session.session_id,
        session.context.get("exposure"),
        session.context.get("environment"),
        session.context.get("sector"),
        session.context.get("company_name"),
    )
