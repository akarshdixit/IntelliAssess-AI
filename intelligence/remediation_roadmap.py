"""
intelligence/remediation_roadmap.py
===================================
Deterministic remediation prioritization engine — Phase 1D-B.

Responsibility: turn a set of findings into a consulting-grade remediation
roadmap — a small number of de-duplicated remediation OBJECTIVES, each placed
into one of three delivery horizons (Immediate / Short-Term / Strategic) by a
transparent, deterministic rule. This answers the question the finding list
cannot: "what should the client fix first?"

This module is the AUTHORITATIVE owner of prioritization, sequencing, and
categorization. It is:
  - Deterministic: same findings + same context → identical roadmap, always.
  - Offline: no AI, no network, no LLM reasoning, no I/O.
  - Non-mutating: finding objects are read via getattr only.
  - Total: every finding maps to exactly one objective (catch-all guarantees it).

Placement model (the core design decision)
-------------------------------------------
Two independent axes drive the horizon:

  1. Urgency  — derived from the *context-adjusted* severity of the finding(s)
     behind an objective (CRITICAL/HIGH → Immediate, MEDIUM → Short-Term,
     LOW/INFO → Strategic). The same adjuster used for finding badges is passed
     in, so the roadmap and the findings agree.

  2. Effort floor — the earliest horizon in which an objective can *realistically*
     be delivered. Disabling a TLS protocol is a same-day config change (floor =
     Immediate); replacing an end-of-life operating system is not (floor =
     Strategic), no matter how severe it is.

  final_horizon = the LATER of (urgency_horizon, effort_floor)

This lets high severity pull quick wins forward without ever pretending that an
inherently long programme (OS modernization, governance) can be done in a week.

De-duplication
--------------
Many findings collapse into one objective. Four TLS findings (weak protocol,
RC4, DES, short key) produce a SINGLE "Modernize TLS configuration" objective,
not four near-identical bullets. This is the primary readability win.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Horizons
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Horizon:
    horizon_id: str
    title:      str
    window:     str
    framing:    str


IMMEDIATE = Horizon(
    "IMMEDIATE", "Immediate Actions", "0–7 days",
    "Actions that address the highest-urgency exposure and can be delivered "
    "quickly. These should be prioritised ahead of all other remediation work.",
)
SHORT_TERM = Horizon(
    "SHORT_TERM", "Short-Term Hardening", "7–30 days",
    "Hardening measures planned into the next patch or release cycle. Each "
    "reduces attack surface but requires testing or coordinated rollout.",
)
STRATEGIC = Horizon(
    "STRATEGIC", "Strategic Improvements", "30–90 days",
    "Programme-level improvements and governance that raise the baseline "
    "security posture and prevent recurrence over the longer term.",
)

_HORIZON_SEQUENCE = [IMMEDIATE, SHORT_TERM, STRATEGIC]
_HORIZON_RANK = {h.horizon_id: i for i, h in enumerate(_HORIZON_SEQUENCE)}

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _severity_horizon(severity: str) -> str:
    """Map a (possibly adjusted) severity to its urgency horizon."""
    sev = (severity or "INFO").upper()
    if sev in ("CRITICAL", "HIGH"):
        return "IMMEDIATE"
    if sev == "MEDIUM":
        return "SHORT_TERM"
    return "STRATEGIC"


def _later_of(horizon_a: str, horizon_b: str) -> str:
    """Return whichever horizon sits later in the delivery sequence."""
    return horizon_a if _HORIZON_RANK[horizon_a] >= _HORIZON_RANK[horizon_b] else horizon_b


# ---------------------------------------------------------------------------
# Remediation objective catalog (deterministic consolidation map)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Objective:
    objective_id: str
    title:        str
    detail:       str
    effort_floor: str            # horizon_id — earliest realistic delivery
    order:        int            # stable within-horizon tiebreaker
    finding_types: frozenset     # finding types this objective consolidates


# Order is the static within-horizon tiebreaker; primary sort is by severity.
_OBJECTIVES: list[_Objective] = [
    _Objective(
        "OBJ_TLS_MODERNIZE",
        "Modernise TLS configuration and remove legacy protocols and ciphers",
        "Disable TLS 1.0/1.1, remove RC4, DES, and 3DES cipher suites, and "
        "require keys of at least 2048-bit RSA (or 256-bit ECC); offer only "
        "forward-secret AEAD suites.",
        "IMMEDIATE", 10,
        frozenset({"WEAK_TLS", "WEAK_CIPHER", "SHORT_KEY_LENGTH"}),
    ),
    _Objective(
        "OBJ_CERT_TRUST",
        "Restore certificate trust",
        "Replace expired and self-signed certificates with certificates issued "
        "by a trusted certificate authority.",
        "IMMEDIATE", 20,
        frozenset({"EXPIRED_CERT", "SELF_SIGNED_CERT"}),
    ),
    _Objective(
        "OBJ_HTTPS_ENFORCE",
        "Enforce encrypted transport (HTTPS)",
        "Serve all content over HTTPS and issue 301 redirects from any cleartext "
        "HTTP listener so credentials and session data are never sent in clear.",
        "IMMEDIATE", 30,
        frozenset({"HTTP_ONLY", "HTTPS_MISSING"}),
    ),
    _Objective(
        "OBJ_LEGACY_SERVICES",
        "Decommission insecure legacy services",
        "Disable FTP, Telnet, and SMBv1, or replace them with secure equivalents "
        "(SFTP/FTPS, SSH, SMBv3).",
        "IMMEDIATE", 40,
        frozenset({"FTP_EXPOSED", "TELNET_EXPOSED", "SMBV1_ENABLED"}),
    ),
    _Objective(
        "OBJ_HSTS",
        "Deploy HTTP Strict Transport Security (HSTS)",
        "Once HTTPS is enforced, add a Strict-Transport-Security header with an "
        "appropriate max-age to prevent protocol downgrade and SSL-stripping.",
        "SHORT_TERM", 50,
        frozenset({"MISSING_HSTS"}),
    ),
    _Objective(
        "OBJ_SEC_HEADERS",
        "Establish a baseline of HTTP security response headers",
        "Deploy Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, "
        "Referrer-Policy, and Permissions-Policy consistently across all web "
        "responses.",
        "SHORT_TERM", 60,
        frozenset({
            "MISSING_CSP", "MISSING_X_FRAME_OPTIONS", "MISSING_X_CONTENT_TYPE_OPTIONS",
            "MISSING_REFERRER_POLICY", "MISSING_PERMISSIONS_POLICY",
            "MISSING_X_XSS_PROTECTION",
        }),
    ),
    _Objective(
        "OBJ_INFO_DISCLOSURE",
        "Reduce service and version disclosure",
        "Suppress or genericise server and version banners to limit "
        "fingerprinting and lower the value of automated reconnaissance.",
        "SHORT_TERM", 70,
        frozenset({"VERSION_DISCLOSURE", "SERVICE_VERSION_DISCLOSURE"}),
    ),
    _Objective(
        "OBJ_ATTACK_SURFACE",
        "Reduce external attack surface",
        "Review exposed ports and restrict reachable services to those that are "
        "operationally required at the network boundary.",
        "STRATEGIC", 80,
        frozenset({"OPEN_PORT"}),
    ),
    _Objective(
        "OBJ_SOFTWARE_LIFECYCLE",
        "Modernise end-of-life operating systems and outdated software",
        "Plan migration of end-of-life operating systems and upgrade outdated "
        "service software to vendor-supported releases on a managed schedule.",
        "STRATEGIC", 90,
        frozenset({"OUTDATED_SERVICE", "EOL_OPERATING_SYSTEM"}),
    ),
]

# Catch-all objective for any finding type not mapped above (total coverage).
_CATCHALL = _Objective(
    "OBJ_REVIEW_OTHER",
    "Review and remediate additional findings",
    "Address the remaining findings detailed in the Technical Findings section "
    "according to their individual severity and remediation guidance.",
    "SHORT_TERM", 95,
    frozenset(),
)

# finding_type → objective (first objective whose set contains the type).
_TYPE_TO_OBJECTIVE: dict[str, _Objective] = {}
for _obj in _OBJECTIVES:
    for _ft in _obj.finding_types:
        _TYPE_TO_OBJECTIVE[_ft] = _obj


# ---------------------------------------------------------------------------
# Derived governance objectives (deterministic, gated on real findings)
# ---------------------------------------------------------------------------
# These are standard consulting closing recommendations. They are NOT invented:
# each is emitted only when the findings that justify it are present, so the
# roadmap never hallucinates work that the assessment did not motivate.

@dataclass(frozen=True)
class _GovernanceObjective:
    objective_id: str
    title:        str
    detail:       str
    order:        int
    requires_any: frozenset   # emit only if at least one of these types is present
                              # (empty set = emit whenever there is any finding)


_GOVERNANCE: list[_GovernanceObjective] = [
    _GovernanceObjective(
        "GOV_CERT_LIFECYCLE",
        "Automate certificate lifecycle management",
        "Introduce automated certificate issuance and renewal (e.g. ACME) with "
        "expiry monitoring to prevent recurrence of certificate trust failures.",
        110,
        frozenset({"EXPIRED_CERT", "SELF_SIGNED_CERT", "SHORT_KEY_LENGTH"}),
    ),
    _GovernanceObjective(
        "GOV_BASELINE_MONITORING",
        "Establish security baseline governance and continuous exposure monitoring",
        "Define a hardening baseline (TLS, headers, exposed services) and monitor "
        "for drift so regressions are detected before the next assessment cycle.",
        120,
        frozenset(),   # any findings present
    ),
]


# ---------------------------------------------------------------------------
# Output structures
# ---------------------------------------------------------------------------

@dataclass
class RoadmapAction:
    """One consolidated, de-duplicated remediation objective placed in a horizon."""
    title:              str
    detail:             str
    finding_count:      int = 0
    worst_severity:     str = "INFO"
    frameworks:         list = field(default_factory=list)
    contributing_types: list = field(default_factory=list)
    governance:         bool = False
    _order:             int = 0


@dataclass
class Roadmap:
    """The full roadmap: an ordered list of (Horizon, [RoadmapAction])."""
    horizons: list = field(default_factory=list)

    def is_empty(self) -> bool:
        return not any(actions for _, actions in self.horizons)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_roadmap(findings, *, severity_adjuster=None, context=None) -> Roadmap:
    """
    Build a deterministic remediation roadmap from findings.

    Args:
        findings:          iterable of finding objects exposing finding_type,
                           severity_label (or severity_hint), and optionally
                           compliance_refs. Not mutated.
        severity_adjuster: optional callable (severity, context) -> severity used
                           to apply contextual uplift consistently with the
                           finding badges. Defaults to identity.
        context:           session context dict passed to severity_adjuster.

    Returns:
        Roadmap with horizons in fixed Immediate → Short-Term → Strategic order.
    """
    context = context or {}

    def _adjust(sev: str) -> str:
        if severity_adjuster is None:
            return (sev or "INFO").upper()
        try:
            return (severity_adjuster(sev, context) or sev or "INFO").upper()
        except Exception:
            return (sev or "INFO").upper()

    # ── 1. Bucket findings into objectives (consolidation / dedup) ─────────
    buckets: dict[str, dict] = {}          # objective_id → aggregate
    objective_by_id: dict[str, _Objective] = {}
    present_types: set[str] = set()

    for f in findings:
        ftype = (getattr(f, "finding_type", "") or "").upper()
        present_types.add(ftype)
        raw_sev = getattr(f, "severity_label", None) or getattr(f, "severity_hint", "INFO")
        adj_sev = _adjust(raw_sev)

        obj = _TYPE_TO_OBJECTIVE.get(ftype, _CATCHALL)
        objective_by_id[obj.objective_id] = obj
        agg = buckets.setdefault(obj.objective_id, {
            "count": 0, "worst": "INFO", "frameworks": set(), "types": set(),
        })
        agg["count"] += 1
        if _SEV_RANK.get(adj_sev, 4) < _SEV_RANK.get(agg["worst"], 4):
            agg["worst"] = adj_sev
        agg["types"].add(ftype)
        refs = getattr(f, "compliance_refs", None) or {}
        if isinstance(refs, dict):
            agg["frameworks"].update(refs.keys())

    # ── 2. Turn buckets into placed actions ────────────────────────────────
    horizon_actions: dict[str, list] = {h.horizon_id: [] for h in _HORIZON_SEQUENCE}

    for obj_id, agg in buckets.items():
        obj = objective_by_id[obj_id]
        worst = agg["worst"]
        horizon = _later_of(_severity_horizon(worst), obj.effort_floor)
        horizon_actions[horizon].append(RoadmapAction(
            title              = obj.title,
            detail             = obj.detail,
            finding_count      = agg["count"],
            worst_severity     = worst,
            frameworks         = sorted(agg["frameworks"]),
            contributing_types = sorted(agg["types"]),
            governance         = False,
            _order             = obj.order,
        ))

    # ── 3. Append deterministic governance objectives (Strategic) ──────────
    has_any = any(present_types)
    for gov in _GOVERNANCE:
        emit = bool(present_types & gov.requires_any) if gov.requires_any else has_any
        if emit:
            horizon_actions["STRATEGIC"].append(RoadmapAction(
                title       = gov.title,
                detail      = gov.detail,
                governance  = True,
                _order      = gov.order,
            ))

    # ── 4. Order within each horizon: severity first, then static order ────
    horizons: list = []
    for h in _HORIZON_SEQUENCE:
        actions = sorted(
            horizon_actions[h.horizon_id],
            key=lambda a: (_SEV_RANK.get(a.worst_severity, 4), a._order),
        )
        horizons.append((h, actions))

    return Roadmap(horizons=horizons)
