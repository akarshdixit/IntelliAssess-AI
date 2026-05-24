"""
ai/analyzer.py
===============
AI enrichment orchestrator for IntelliAssess AI — Phase 4-1.

Responsibility: consume ParsedScanData, orchestrate Gemini enrichment calls,
and return a structured EnrichedReport ready for the Phase 4-2 reporter.

  - Consumes ParsedScanData from the parser layer
  - Builds prompts via ai/prompt_builder.py
  - Calls Gemini via ai/gemini_client.py
  - Parses JSON responses into ai/models.py dataclasses
  - Returns EnrichedReport (never raises)

Architecture position:
  parsers → ParsedScanData → analyzer.py → EnrichedReport → future reporter.py

Design principles:
  - Single entry point: run(parsed_data_list, context) → EnrichedReport
  - Graceful degradation: every Gemini failure produces an unenriched
    fallback object with enriched=False. The platform never stops.
  - Finding deduplication: findings with the same finding_type across
    multiple ParsedScanData objects are enriched ONCE (one prompt per type),
    not once per occurrence. This avoids N API calls for N identical findings.
  - Positive findings (TLS_ENABLED, INFO severity) are routed to the
    positive_observations list in the executive summary, not enriched individually.
  - JSON parsing is defensive: strips markdown fences, validates keys,
    falls back to empty strings on malformed responses.
  - All enrichment errors are collected in EnrichedReport.enrichment_errors
    so the reporter can include a diagnostic note if needed.

Finding enrichment strategy:
  - CRITICAL/HIGH/MEDIUM/LOW findings → full enrichment (narrative + remediation)
  - INFO findings → extracted as positive observations for exec summary only
  - Duplicate finding_types → enriched once, mapped to all targets
  - Max findings enriched: ENRICHMENT_FINDING_LIMIT (default 20)
    Prevents runaway API spend on large scans. Prioritizes by severity.

Phase 4-2 integration:
  reporter.py will call:
    enriched = analyzer.run(parsed_list, context)
    # Use enriched.executive_summary, enriched.finding_summaries, etc.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from ai.gemini_client import GeminiClient
from ai.models import (
    AIExecutiveSummary,
    AIFindingSummary,
    AIRemediation,
    EnrichedReport,
)
from ai.prompt_builder import (
    build_executive_summary_prompt,
    build_finding_enrichment_prompt,
    build_remediation_prompt,
)
from utils.logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Maximum number of findings to send to Gemini for individual enrichment.
# Findings are prioritized by severity before the limit is applied.
# Findings beyond the limit get enriched=False with their raw detail as fallback.
ENRICHMENT_FINDING_LIMIT: int = 20

# Severity priority order for finding selection when limit is applied.
_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}

# Finding types that represent positive security controls — routed to
# positive_observations rather than individual enrichment.
_POSITIVE_FINDING_TYPES: frozenset[str] = frozenset([
    "TLS_ENABLED",
    # Future positive types can be added here as parsers produce them.
])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run(
    parsed_data_list: list,   # list[ParsedScanData] — avoiding circular import
    context:          dict,
) -> EnrichedReport:
    """
    Orchestrate full AI enrichment for a list of ParsedScanData objects.

    This is the single function called by Phase 4-2's reporter.py. It accepts
    all ParsedScanData from a session (one per ingested file) and returns one
    EnrichedReport covering the complete assessment.

    Args:
        parsed_data_list: All ParsedScanData objects for the session.
                          May be an empty list — returns a minimal EnrichedReport.
        context:          Session context dict (exposure, environment, sector, etc.)
                          From session.context in session.json.

    Returns:
        EnrichedReport — always valid, never None, never raises.

    Graceful-failure contract:
        If Gemini is unavailable, all enrichment fields will have enriched=False
        and raw detail strings as fallback text. The EnrichedReport is still
        complete and usable by the reporter.
    """
    log.info("Analyzer: starting enrichment for %d parsed file(s)", len(parsed_data_list))

    client = GeminiClient()
    client.initialize()   # Attempt SDK init; failure logged internally

    errors: list[str] = []

    # ── 1. Collect all findings across all parsed data ─────────────────────
    all_findings = _collect_findings(parsed_data_list)
    all_targets  = _collect_targets(parsed_data_list)
    all_tools    = _collect_tools(parsed_data_list)

    log.info(
        "Analyzer: %d total findings from %d target(s), tools: %s",
        len(all_findings), len(all_targets), ", ".join(all_tools) or "none",
    )

    # ── 2. Separate positive findings from security findings ───────────────
    positive_findings = [f for f in all_findings if f["finding_type"] in _POSITIVE_FINDING_TYPES]
    security_findings = [f for f in all_findings if f["finding_type"] not in _POSITIVE_FINDING_TYPES]

    # ── 3. Deduplicate and prioritize findings for enrichment ──────────────
    findings_to_enrich = _select_findings_for_enrichment(security_findings)

    log.info(
        "Analyzer: %d security findings → %d selected for enrichment (limit=%d)",
        len(security_findings), len(findings_to_enrich), ENRICHMENT_FINDING_LIMIT,
    )

    # ── 4. Enrich each selected finding ───────────────────────────────────
    finding_summaries: list[AIFindingSummary] = []
    remediations:      list[AIRemediation]    = []
    enriched_types:    set[str]               = set()   # track types already remediated

    for finding in findings_to_enrich:
        # ── Finding narrative + business impact ────────────────────────────
        summary = _enrich_finding(client, finding, context, errors)
        finding_summaries.append(summary)

        # ── Remediation — one per finding_type (not one per instance) ─────
        ftype = finding["finding_type"]
        if ftype not in enriched_types:
            remediation = _enrich_remediation(client, finding, context, errors)
            remediations.append(remediation)
            enriched_types.add(ftype)

    # ── 5. Build unenriched fallback summaries for omitted findings ────────
    omitted = [
        f for f in security_findings
        if f not in findings_to_enrich
    ]
    for finding in omitted:
        finding_summaries.append(_make_fallback_summary(finding))

    # ── 6. Build positive observations list for exec summary ──────────────
    positive_notes = _extract_positive_notes(positive_findings)

    # ── 7. Build executive summary ─────────────────────────────────────────
    severity_counts = _count_severities(all_findings)
    finding_types   = sorted({f["finding_type"] for f in security_findings})

    executive_summary = _enrich_executive_summary(
        client         = client,
        targets        = all_targets,
        finding_types  = finding_types,
        severity_counts= severity_counts,
        tool_names     = all_tools,
        positive_notes = positive_notes,
        context        = context,
        errors         = errors,
    )

    # ── 8. Assemble EnrichedReport ─────────────────────────────────────────
    enrichment_complete = (
        client.is_available
        and len(errors) == 0
        and len(finding_summaries) > 0
    )

    report = EnrichedReport(
        executive_summary   = executive_summary,
        finding_summaries   = finding_summaries,
        remediations        = remediations,
        session_context     = context,
        enrichment_complete = enrichment_complete,
        enrichment_errors   = errors,
        primary_targets     = all_targets,
    )

    log.info("Analyzer: %s", report.summary())
    return report


# ---------------------------------------------------------------------------
# Finding collection helpers
# ---------------------------------------------------------------------------

def _collect_findings(parsed_data_list: list) -> list[dict]:
    """
    Flatten all ParsedFinding objects across all ParsedScanData into dicts.

    Returns a flat list of finding dicts with normalized keys. Dicts are used
    (not ParsedFinding dataclasses) to keep the analyzer decoupled from the
    parser model import at the module level (avoids potential circular imports
    in large projects).
    """
    findings: list[dict] = []
    for parsed in parsed_data_list:
        for f in parsed.findings:
            findings.append({
                "finding_type":  getattr(f, "finding_type", "UNKNOWN"),
                "target":        getattr(f, "target", ""),
                "port":          getattr(f, "port", None),
                "protocol":      getattr(f, "protocol", None),
                "service":       getattr(f, "service", None),
                "detail":        getattr(f, "detail", None) or "",
                "severity_hint": getattr(f, "severity_hint", None) or "INFO",
                "raw_evidence":  getattr(f, "raw_evidence", None) or "",
                "source_tool":   getattr(f, "source_tool", ""),
                # ── Phase 1C: preserve deterministic catalog metadata ──────
                # These are attached by intelligence/finding_catalog.build_finding()
                # and are AUTHORITATIVE. They must survive the analyzer intact so
                # the reporter can render real titles, remediation, and compliance
                # references — with full quality even when Gemini is unavailable.
                "finding_id":      getattr(f, "finding_id", "") or "",
                "title":           getattr(f, "title", "") or "",
                "remediation":     getattr(f, "remediation", "") or "",
                "compliance_refs": getattr(f, "compliance_refs", None) or {},
                "confidence":      getattr(f, "confidence", 1.0),
            })
    return findings


def _collect_targets(parsed_data_list: list) -> list[str]:
    """Return deduplicated list of primary targets across all ParsedScanData."""
    seen:    set[str]  = set()
    targets: list[str] = []
    for parsed in parsed_data_list:
        if parsed.primary_target and parsed.primary_target not in seen:
            seen.add(parsed.primary_target)
            targets.append(parsed.primary_target)
        for asset in parsed.assets:
            if asset.value and asset.value not in seen:
                seen.add(asset.value)
                targets.append(asset.value)
    return targets


def _collect_tools(parsed_data_list: list) -> list[str]:
    """Return deduplicated list of tool names across all ParsedScanData."""
    seen:  set[str]  = set()
    tools: list[str] = []
    for parsed in parsed_data_list:
        tool = parsed.tool_type
        if tool and tool != "UNKNOWN" and tool not in seen:
            seen.add(tool)
            tools.append(tool)
    return tools


def _count_severities(findings: list[dict]) -> dict[str, int]:
    """Count findings by severity_hint."""
    counts: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity_hint") or "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Finding selection and prioritization
# ---------------------------------------------------------------------------

def _select_findings_for_enrichment(security_findings: list[dict]) -> list[dict]:
    """
    Select and deduplicate findings for Gemini enrichment.

    Strategy:
      1. Sort by severity priority (CRITICAL first)
      2. Deduplicate by finding_type — keep the highest-severity instance
         of each type (first occurrence after sorting = highest severity).
         Rationale: Gemini enrichment is type-level. If five hosts all have
         MISSING_HSTS, one enrichment prompt covers all of them.
      3. Apply ENRICHMENT_FINDING_LIMIT to the deduplicated list.

    Returns the findings selected for Gemini enrichment, in priority order.
    """
    # Sort by severity priority then by finding_type for determinism
    sorted_findings = sorted(
        security_findings,
        key=lambda f: (
            _SEVERITY_ORDER.get((f.get("severity_hint") or "INFO").upper(), 99),
            f.get("finding_type", ""),
        ),
    )

    # Deduplicate by finding_type — first occurrence = highest severity
    seen_types:    set[str]   = set()
    deduplicated:  list[dict] = []
    for f in sorted_findings:
        ftype = f.get("finding_type", "")
        if ftype not in seen_types:
            seen_types.add(ftype)
            deduplicated.append(f)

    # Apply limit
    return deduplicated[:ENRICHMENT_FINDING_LIMIT]


# ---------------------------------------------------------------------------
# Individual finding enrichment
# ---------------------------------------------------------------------------

def _enrich_finding(
    client:  GeminiClient,
    finding: dict,
    context: dict,
    errors:  list[str],
) -> AIFindingSummary:
    """
    Enrich one finding with Gemini narrative + business impact.

    Returns an AIFindingSummary with enriched=True on success,
    enriched=False with raw detail as fallback on failure.
    """
    finding_type  = finding["finding_type"]
    target        = finding["target"]
    port          = finding.get("port")

    # Build prompt
    prompt = build_finding_enrichment_prompt(
        finding_type  = finding_type,
        target        = target,
        port          = port,
        service       = finding.get("service"),
        detail        = finding.get("detail"),
        severity_hint = finding.get("severity_hint"),
        raw_evidence  = finding.get("raw_evidence"),
        context       = context,
    )

    # Call Gemini
    response_text = client.complete(prompt, max_tokens=512)

    if response_text is None:
        log.debug("Analyzer: finding enrichment failed for %s — using fallback", finding_type)
        return _make_fallback_summary(finding)

    # Parse JSON response
    parsed = _parse_json_response(response_text, finding_type)
    if parsed is None:
        errors.append(f"finding_enrichment[{finding_type}]: JSON parse failed")
        return _make_fallback_summary(finding)

    return AIFindingSummary(
        finding_type       = finding_type,
        target             = target,
        port               = port,
        analyst_narrative  = parsed.get("analyst_narrative", ""),
        business_impact    = parsed.get("business_impact", ""),
        # Phase 1C: severity is deterministic (catalog), NOT AI-supplied.
        # The catalog severity is authoritative; any model-suggested
        # severity_label in the response is treated as advisory and ignored
        # so AI can never silently up/down-grade a deterministic finding.
        severity_label     = finding.get("severity_hint", "INFO"),
        enriched           = True,
        raw_finding_detail = finding.get("detail", ""),
        **_deterministic_summary_fields(finding),
    )


def _enrich_remediation(
    client:  GeminiClient,
    finding: dict,
    context: dict,
    errors:  list[str],
) -> AIRemediation:
    """
    Enrich one finding type with Gemini remediation guidance.

    Returns an AIRemediation with enriched=True on success,
    enriched=False with empty lists on failure.
    """
    finding_type = finding["finding_type"]
    target       = finding["target"]

    prompt = build_remediation_prompt(
        finding_type  = finding_type,
        target        = target,
        port          = finding.get("port"),
        service       = finding.get("service"),
        detail        = finding.get("detail"),
        severity_hint = finding.get("severity_hint"),
        context       = context,
    )

    response_text = client.complete(prompt, max_tokens=512)

    if response_text is None:
        log.debug("Analyzer: remediation enrichment failed for %s", finding_type)
        return AIRemediation(finding_type=finding_type, target=target, enriched=False)

    parsed = _parse_json_response(response_text, finding_type)
    if parsed is None:
        errors.append(f"remediation[{finding_type}]: JSON parse failed")
        return AIRemediation(finding_type=finding_type, target=target, enriched=False)

    return AIRemediation(
        finding_type       = finding_type,
        target             = target,
        immediate_actions  = _safe_list(parsed.get("immediate_actions")),
        short_term_actions = _safe_list(parsed.get("short_term_actions")),
        commands           = _safe_list(parsed.get("commands")),
        references         = _safe_list(parsed.get("references")),
        enriched           = True,
    )


# ---------------------------------------------------------------------------
# Executive summary enrichment
# ---------------------------------------------------------------------------

def _enrich_executive_summary(
    client:          GeminiClient,
    targets:         list[str],
    finding_types:   list[str],
    severity_counts: dict[str, int],
    tool_names:      list[str],
    positive_notes:  list[str],
    context:         dict,
    errors:          list[str],
) -> AIExecutiveSummary:
    """
    Build and enrich the executive summary.

    Returns AIExecutiveSummary with enriched=True on success,
    or a data-table-style fallback with enriched=False.
    """
    total_findings = sum(severity_counts.values())

    prompt = build_executive_summary_prompt(
        targets         = targets,
        finding_types   = finding_types,
        severity_counts = severity_counts,
        tool_names      = tool_names,
        positive_notes  = positive_notes,
        context         = context,
    )

    response_text = client.complete(prompt, max_tokens=768)

    if response_text is None:
        log.info("Analyzer: executive summary enrichment unavailable — using fallback")
        return _make_fallback_executive_summary(
            targets        = targets,
            severity_counts= severity_counts,
            positive_notes = positive_notes,
            total_findings = total_findings,
        )

    parsed = _parse_json_response(response_text, "executive_summary")
    if parsed is None:
        errors.append("executive_summary: JSON parse failed")
        return _make_fallback_executive_summary(
            targets        = targets,
            severity_counts= severity_counts,
            positive_notes = positive_notes,
            total_findings = total_findings,
        )

    return AIExecutiveSummary(
        overview_paragraph      = parsed.get("overview_paragraph", ""),
        risk_posture            = parsed.get("risk_posture", "UNKNOWN"),
        key_findings            = _safe_list(parsed.get("key_findings")),
        positive_observations   = _safe_list(parsed.get("positive_observations")),
        priority_recommendation = parsed.get("priority_recommendation", ""),
        enriched                = True,
        targets_assessed        = targets,
        total_findings          = total_findings,
    )


# ---------------------------------------------------------------------------
# Fallback constructors — used when Gemini is unavailable
# ---------------------------------------------------------------------------

def _deterministic_summary_fields(finding: dict) -> dict:
    """
    Phase 1C: return the deterministic catalog metadata kwargs that must be
    copied verbatim onto every AIFindingSummary.

    These come from intelligence/finding_catalog.build_finding() and are
    AUTHORITATIVE. They are never sourced from, nor overwritten by, AI output —
    the AI layer only adds analyst_narrative / business_impact. Centralized here
    so the enriched and fallback constructors can never drift apart.
    """
    return {
        "finding_id":      finding.get("finding_id", "") or "",
        "title":           finding.get("title", "") or "",
        "remediation":     finding.get("remediation", "") or "",
        "compliance_refs": finding.get("compliance_refs", {}) or {},
        "confidence":      finding.get("confidence", 1.0),
    }


def _make_fallback_summary(finding: dict) -> AIFindingSummary:
    """
    Construct an unenriched AIFindingSummary from raw finding data.

    Used when Gemini is unavailable or a call fails. Phase 1C: even unenriched,
    the summary now carries the full deterministic catalog metadata (title,
    remediation, compliance_refs), so the reporter renders a complete,
    professional finding offline — no boilerplate reconstruction.
    """
    return AIFindingSummary(
        finding_type       = finding.get("finding_type", "UNKNOWN"),
        target             = finding.get("target", ""),
        port               = finding.get("port"),
        analyst_narrative  = "",
        business_impact    = "",
        severity_label     = finding.get("severity_hint", "INFO"),
        enriched           = False,
        raw_finding_detail = finding.get("detail", ""),
        **_deterministic_summary_fields(finding),
    )


def _make_fallback_executive_summary(
    targets:         list[str],
    severity_counts: dict[str, int],
    positive_notes:  list[str],
    total_findings:  int,
) -> AIExecutiveSummary:
    """
    Construct a minimal data-table executive summary without AI narrative.

    The reporter renders this as a structured data summary rather than
    an analyst narrative paragraph when enriched=False.
    """
    # Determine overall risk from severity distribution
    risk = "LOW"
    if severity_counts.get("CRITICAL", 0) > 0:
        risk = "CRITICAL"
    elif severity_counts.get("HIGH", 0) > 0:
        risk = "HIGH"
    elif severity_counts.get("MEDIUM", 0) > 0:
        risk = "MEDIUM"
    elif total_findings == 0:
        risk = "POSITIVE"

    return AIExecutiveSummary(
        overview_paragraph      = "",   # Reporter generates data table instead
        risk_posture            = risk,
        key_findings            = [],
        positive_observations   = positive_notes,
        priority_recommendation = "",
        enriched                = False,
        targets_assessed        = targets,
        total_findings          = total_findings,
    )


# ---------------------------------------------------------------------------
# Positive finding extraction
# ---------------------------------------------------------------------------

def _extract_positive_notes(positive_findings: list[dict]) -> list[str]:
    """
    Extract human-readable positive observation strings from positive findings.

    These are passed to the executive summary as positive_observations.
    """
    notes: list[str] = []
    seen:  set[str]  = set()

    for f in positive_findings:
        note = f.get("detail") or f.get("finding_type", "")
        if note and note not in seen:
            seen.add(note)
            notes.append(note)

    return notes


# ---------------------------------------------------------------------------
# JSON response parsing
# ---------------------------------------------------------------------------

def _parse_json_response(text: str, context_label: str) -> Optional[dict]:
    """
    Parse a JSON response from Gemini into a dict.

    Defensively handles:
      - Markdown fences (```json ... ```) that Gemini sometimes adds
        despite being instructed not to.
      - Leading/trailing whitespace.
      - BOM characters.
      - Responses with text before/after the JSON object.

    Returns the parsed dict on success, None on parse failure.

    Args:
        text:          Raw response text from Gemini.
        context_label: Label for log messages (e.g. "VERSION_DISCLOSURE").
    """
    if not text:
        return None

    # Strip BOM and surrounding whitespace
    cleaned = text.strip().lstrip("\ufeff")

    # Strip markdown code fences (```json ... ``` or ``` ... ```)
    fence_pattern = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)
    fence_match   = fence_pattern.search(cleaned)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    # If no fences, try to extract the outermost JSON object by brace matching
    if not cleaned.startswith("{"):
        brace_start = cleaned.find("{")
        if brace_start != -1:
            cleaned = cleaned[brace_start:]

    # Trim trailing content after the last closing brace
    brace_end = cleaned.rfind("}")
    if brace_end != -1:
        cleaned = cleaned[: brace_end + 1]

    try:
        result = json.loads(cleaned)
        if isinstance(result, dict):
            return result
        log.warning(
            "Analyzer: JSON parsed but not a dict for %s (got %s)",
            context_label, type(result).__name__,
        )
        return None
    except json.JSONDecodeError as exc:
        log.warning(
            "Analyzer: JSON parse error for %s: %s | preview: %r",
            context_label, exc, cleaned[:200],
        )
        return None


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _safe_list(value) -> list[str]:
    """
    Safely extract a list of strings from a parsed JSON value.

    Handles None, non-list types, and list items that aren't strings.
    Returns an empty list rather than raising.
    """
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None]
