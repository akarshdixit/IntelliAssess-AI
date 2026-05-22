"""
intelligence/risk_adjustment.py
================================
Lightweight deterministic contextual severity adjustment — Phase 5-1.

Responsibility: apply deterministic uplift to raw finding severities based
on assessment context (exposure, environment, sector).

  - NO CVSS calculation
  - NO probabilistic scoring
  - NO exploit modelling
  - NO AI involvement

This module implements a simple additive uplift model. Context factors that
increase organisational risk each add one step on the severity ladder.
The result is bounded — a finding can never exceed CRITICAL.

The key insight driving the design:
    Open SSH on a development server (internal, dev, no regulated sector) is
    LOW severity. Open SSH on the same port on a production banking server
    with public exposure is a materially different risk — it should surface
    as HIGH or CRITICAL. Context-awareness is achieved with three integer
    additions and a ceiling, not a complex engine.

Uplift rules (each contributing +1):
    exposure    = "public"              → +1 (publicly reachable attack surface)
    environment = "production"          → +1 (live systems, real data)
    sector      ∈ high-scrutiny set    → +1 (regulated, high-value target)

High-scrutiny sectors: banking, finance, financial, healthcare, government

Maximum possible uplift: +3

Severity ladder (ordinal):
    0 = INFO
    1 = LOW
    2 = MEDIUM
    3 = HIGH
    4 = CRITICAL

Usage:
    from intelligence.risk_adjustment import adjust, adjustment_delta, describe_adjustments

    # Adjusted severity string
    adjusted = adjust("MEDIUM", session.context)    # → "CRITICAL" (banking+public+prod)

    # How many steps were added (0 = no change)
    delta = adjustment_delta("MEDIUM", session.context)   # → 2

    # Human-readable reasons (for report annotation)
    reasons = describe_adjustments(session.context)
    # → ["Public-facing exposure (+1 severity)",
    #    "Production environment (+1 severity)",
    #    "Banking sector — heightened regulatory scrutiny (+1 severity)"]

Design contract:
    All public functions are pure. They never raise and never mutate any input.
    They are called at report render time only — upstream data structures
    (EnrichedReport, ParsedScanData) are never modified.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Severity ordinal scale
# ---------------------------------------------------------------------------

# The five-step severity ladder used throughout IntelliAssess AI.
# Order is intentional: index 0 is lowest, index 4 is highest.
_SEVERITY_LADDER: list[str] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

_SEVERITY_INDEX: dict[str, int] = {sev: idx for idx, sev in enumerate(_SEVERITY_LADDER)}

# ---------------------------------------------------------------------------
# High-scrutiny sector set
# ---------------------------------------------------------------------------

# Sectors that attract heightened adversarial interest and regulatory burden.
# A finding in one of these sectors carries more organisational risk than
# the same finding in a generic commercial context.
_HIGH_SCRUTINY_SECTORS: frozenset[str] = frozenset([
    "banking",
    "finance",
    "financial",
    "healthcare",
    "government",
])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def adjust(severity: str, context: dict) -> str:
    """
    Apply deterministic contextual uplift to a finding severity.

    Args:
        severity: Raw severity string. One of: CRITICAL|HIGH|MEDIUM|LOW|INFO.
                  Case-insensitive. Unknown values treated as INFO.
        context:  Session context dict. Expected keys (all optional):
                    "exposure"    — "public" | "internal" | "dmz" | "cloud"
                    "environment" — "production" | "staging" | "development"
                    "sector"      — "banking" | "healthcare" | "government" | ...

    Returns:
        Adjusted severity string. Always one of: CRITICAL|HIGH|MEDIUM|LOW|INFO.
        Bounded at CRITICAL — never exceeds the top of the ladder.
        Returns INFO if severity is empty or unrecognised.

    Design contract:
        Pure function. Never raises. Context may be None or {}.
    """
    if not severity:
        return "INFO"

    normalized = severity.strip().upper()
    if normalized not in _SEVERITY_INDEX:
        # Unknown severity — treat conservatively as INFO
        return "INFO"

    base_index     = _SEVERITY_INDEX[normalized]
    uplift         = _compute_uplift(context or {})
    adjusted_index = min(base_index + uplift, len(_SEVERITY_LADDER) - 1)

    return _SEVERITY_LADDER[adjusted_index]


def adjustment_delta(severity: str, context: dict) -> int:
    """
    Return the number of severity steps added to a finding given a context.

    Args:
        severity: Raw severity string (case-insensitive).
        context:  Session context dict.

    Returns:
        Integer ≥ 0 representing the uplift applied.
        Returns 0 when:
          - No context factors are active, OR
          - The severity is already CRITICAL (ceiling reached), OR
          - The severity is unrecognised.

    Useful for callers that want to annotate a finding as "context-adjusted"
    without calling adjust() a second time.
    """
    normalized = (severity or "").strip().upper()
    if normalized not in _SEVERITY_INDEX:
        return 0

    base_index     = _SEVERITY_INDEX[normalized]
    uplift         = _compute_uplift(context or {})
    adjusted_index = min(base_index + uplift, len(_SEVERITY_LADDER) - 1)

    # Delta is the actual change, not the raw uplift (ceiling effect).
    return adjusted_index - base_index


def describe_adjustments(context: dict) -> list[str]:
    """
    Return human-readable descriptions of active uplift factors.

    Args:
        context: Session context dict.

    Returns:
        List of strings, one per active uplift factor, suitable for
        inclusion in report annotation text.
        Returns empty list if no uplift factors are active.

    Example:
        ["Public-facing exposure (+1 severity)",
         "Production environment (+1 severity)",
         "Banking sector — heightened regulatory scrutiny (+1 severity)"]
    """
    reasons: list[str] = []
    ctx = context or {}

    exposure = (ctx.get("exposure") or "").strip().lower()
    if exposure == "public":
        reasons.append("Public-facing exposure (+1 severity)")

    environment = (ctx.get("environment") or "").strip().lower()
    if environment == "production":
        reasons.append("Production environment (+1 severity)")

    sector = (ctx.get("sector") or "").strip().lower()
    if sector in _HIGH_SCRUTINY_SECTORS:
        reasons.append(
            f"{sector.title()} sector — heightened regulatory scrutiny (+1 severity)"
        )

    return reasons


def is_high_scrutiny_context(context: dict) -> bool:
    """
    Return True if ANY uplift factor is active in the given context.

    A convenience predicate for the reporter to decide whether to render
    contextual risk annotation at all.
    """
    return _compute_uplift(context or {}) > 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compute_uplift(context: dict) -> int:
    """
    Compute total severity uplift from context fields.

    Each qualifying condition contributes +1.
    Maximum return value: 3 (all three factors active simultaneously).
    Minimum return value: 0 (no factors active).

    Args:
        context: Already-normalised context dict (caller guarantees non-None).

    Returns:
        Integer uplift amount, used for index arithmetic in adjust().
    """
    uplift = 0

    # Factor 1: Public exposure
    # A publicly reachable service is accessible to the entire internet,
    # dramatically increasing the realistic threat population.
    exposure = (context.get("exposure") or "").strip().lower()
    if exposure == "public":
        uplift += 1

    # Factor 2: Production environment
    # Production systems process real data and have real operational impact.
    # A compromise in production has immediate business consequences.
    environment = (context.get("environment") or "").strip().lower()
    if environment == "production":
        uplift += 1

    # Factor 3: Regulated / high-value sector
    # Organisations in banking, healthcare, and government are attractive
    # targets for motivated adversaries and face regulatory penalties for
    # security failures. A finding in these sectors has higher material impact.
    sector = (context.get("sector") or "").strip().lower()
    if sector in _HIGH_SCRUTINY_SECTORS:
        uplift += 1

    return uplift
