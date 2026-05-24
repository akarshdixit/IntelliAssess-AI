"""
intelligence/finding_groups.py
==============================
Deterministic, presentational correlation of findings into security themes —
Phase 1D-A.

Responsibility: map each finding_type to a strategic theme so the reporter can
render related findings together ("TLS Configuration Weaknesses") instead of as
a long list of independent items. This is the lightweight correlation layer the
platform needs — NOT a graph engine, NOT a clustering model. It is a static,
auditable taxonomy plus a pure grouping function.

Design principles:
  - Pure module: no I/O, no network, no AI, no mutation of inputs.
  - Presentational only: every individual finding is preserved intact; grouping
    never merges, drops, or rewrites evidence, compliance, or remediation.
  - Total coverage: every catalog finding_type maps to a theme, and any unknown
    type falls through to a catch-all so a finding can never disappear.
  - Deterministic ordering: themes are ordered by the worst severity they
    contain (most severe theme first), with a stable static rank as tiebreaker,
    so the same input always produces the same report layout.

Used by: reporting/reporter.py (_build_technical_findings).
"""

from __future__ import annotations

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Theme definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FindingGroup:
    """A presentational theme that correlates related finding types."""
    group_id: str
    title:    str
    order:    int   # static tiebreaker rank (lower = earlier)
    summary:  str   # one-line analyst framing rendered as the theme intro


# Catch-all theme for any finding_type not explicitly mapped below.
_OTHER_ID = "OTHER"

# Theme registry. The `order` field is a stable tiebreaker only — runtime
# ordering is driven primarily by the worst severity present in each theme.
_GROUPS: dict[str, FindingGroup] = {
    "TRANSPORT_SECURITY": FindingGroup(
        group_id="TRANSPORT_SECURITY",
        title="Transport Security Weaknesses",
        order=1,
        summary=(
            "Weaknesses that allow assessment traffic to traverse the network "
            "without enforced encryption, exposing credentials and session data "
            "to interception and downgrade attacks."
        ),
    ),
    "TLS_CONFIGURATION": FindingGroup(
        group_id="TLS_CONFIGURATION",
        title="TLS Configuration Weaknesses",
        order=2,
        summary=(
            "Deficiencies in the TLS stack — deprecated protocols, weak cipher "
            "suites, and certificate trust issues — that undermine the strength "
            "of otherwise-encrypted channels."
        ),
    ),
    "BROWSER_CONTROLS": FindingGroup(
        group_id="BROWSER_CONTROLS",
        title="Missing Browser Security Controls",
        order=3,
        summary=(
            "Absent HTTP response headers that instruct the browser to enforce "
            "client-side protections against clickjacking, content injection, "
            "and MIME-type confusion."
        ),
    ),
    "INFORMATION_DISCLOSURE": FindingGroup(
        group_id="INFORMATION_DISCLOSURE",
        title="Information Disclosure",
        order=4,
        summary=(
            "Service and version details leaked to unauthenticated clients, "
            "lowering the effort required for an attacker to fingerprint the "
            "stack and target known vulnerabilities."
        ),
    ),
    "EXPOSED_SERVICES": FindingGroup(
        group_id="EXPOSED_SERVICES",
        title="Exposed and Insecure Services",
        order=5,
        summary=(
            "Network services reachable at the assessment boundary that are "
            "either inherently insecure or expand the attack surface beyond "
            "what the application requires."
        ),
    ),
    "OUTDATED_SOFTWARE": FindingGroup(
        group_id="OUTDATED_SOFTWARE",
        title="Outdated and End-of-Life Software",
        order=6,
        summary=(
            "Operating systems and service software running versions that are "
            "outdated or beyond vendor support, where security patches may no "
            "longer be available."
        ),
    ),
    _OTHER_ID: FindingGroup(
        group_id=_OTHER_ID,
        title="Additional Findings",
        order=99,
        summary=(
            "Findings that do not fall into the primary thematic clusters above "
            "but remain relevant to the overall security posture."
        ),
    ),
}

# finding_type → theme id. Every catalog type (Phase 1B-A taxonomy) is covered.
_TYPE_TO_GROUP: dict[str, str] = {
    # Transport security
    "HTTP_ONLY":                       "TRANSPORT_SECURITY",
    "HTTPS_MISSING":                   "TRANSPORT_SECURITY",
    "MISSING_HSTS":                    "TRANSPORT_SECURITY",
    # TLS configuration
    "WEAK_TLS":                        "TLS_CONFIGURATION",
    "WEAK_CIPHER":                     "TLS_CONFIGURATION",
    "EXPIRED_CERT":                    "TLS_CONFIGURATION",
    "SELF_SIGNED_CERT":                "TLS_CONFIGURATION",
    "SHORT_KEY_LENGTH":                "TLS_CONFIGURATION",
    # Browser security controls
    "MISSING_CSP":                     "BROWSER_CONTROLS",
    "MISSING_X_FRAME_OPTIONS":         "BROWSER_CONTROLS",
    "MISSING_X_CONTENT_TYPE_OPTIONS":  "BROWSER_CONTROLS",
    "MISSING_REFERRER_POLICY":         "BROWSER_CONTROLS",
    "MISSING_PERMISSIONS_POLICY":      "BROWSER_CONTROLS",
    "MISSING_X_XSS_PROTECTION":        "BROWSER_CONTROLS",
    # Information disclosure
    "VERSION_DISCLOSURE":              "INFORMATION_DISCLOSURE",
    "SERVICE_VERSION_DISCLOSURE":      "INFORMATION_DISCLOSURE",
    # Exposed / insecure services
    "FTP_EXPOSED":                     "EXPOSED_SERVICES",
    "TELNET_EXPOSED":                  "EXPOSED_SERVICES",
    "SMBV1_ENABLED":                   "EXPOSED_SERVICES",
    "OPEN_PORT":                       "EXPOSED_SERVICES",
    # Outdated / EOL software
    "OUTDATED_SERVICE":                "OUTDATED_SOFTWARE",
    "EOL_OPERATING_SYSTEM":            "OUTDATED_SOFTWARE",
    # Note: positive types (e.g. TLS_ENABLED) are not security findings and are
    # never passed to this module; they route to Positive Observations upstream.
}

_SEV_RANK: dict[str, int] = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def group_id_for(finding_type: str) -> str:
    """Return the theme id for a finding_type (catch-all if unmapped)."""
    return _TYPE_TO_GROUP.get(finding_type or "", _OTHER_ID)


def group_findings(findings: list) -> list[tuple[FindingGroup, list]]:
    """
    Correlate findings into ordered themes.

    Args:
        findings: an iterable of finding objects exposing `.finding_type` and
                  `.severity_label` (AIFindingSummary instances in practice).
                  The list is NOT mutated.

    Returns:
        An ordered list of (FindingGroup, [findings]) tuples. Themes are ordered
        by the worst severity they contain (most severe first), then by the
        theme's static rank. Findings within a theme are ordered by severity
        (most severe first). Every input finding appears in exactly one theme.
    """
    buckets: dict[str, list] = {}
    for f in findings:
        gid = group_id_for(getattr(f, "finding_type", "") or "")
        buckets.setdefault(gid, []).append(f)

    def _sev(f) -> int:
        return _SEV_RANK.get((getattr(f, "severity_label", "INFO") or "INFO").upper(), 99)

    def _group_key(gid: str):
        worst = min((_sev(f) for f in buckets[gid]), default=99)
        return (worst, _GROUPS[gid].order)

    ordered: list[tuple[FindingGroup, list]] = []
    for gid in sorted(buckets, key=_group_key):
        members = sorted(buckets[gid], key=_sev)
        ordered.append((_GROUPS[gid], members))
    return ordered


def all_groups() -> list[FindingGroup]:
    """Return all defined themes (for documentation / introspection)."""
    return sorted(_GROUPS.values(), key=lambda g: g.order)
