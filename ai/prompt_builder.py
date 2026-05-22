"""
ai/prompt_builder.py
=====================
Structured prompt construction for IntelliAssess AI Gemini enrichment — Phase 4-1.

Responsibility: build well-structured, focused prompts from ParsedFinding
and ParsedAsset data. Nothing else.

  - NO API calls (that is gemini_client.py's job)
  - NO response parsing (that is analyzer.py's job)
  - NO session persistence

Design principles:
  - Each prompt is self-contained: Gemini receives exactly the context it
    needs for one enrichment task, no more.
  - Prompts request JSON output to enable structured parsing by analyzer.py.
  - JSON schema is embedded in each prompt so Gemini knows the expected shape.
  - Prompts are tightly scoped: finding enrichment ≠ executive summary.
    Each function produces a prompt for exactly one enrichment type.
  - Context (exposure, sector, environment) is injected when available so
    Gemini produces context-aware output (banking vs education, etc.).
  - All prompt functions are pure: given the same inputs they always produce
    the same prompt. No side effects.

Prompt output format contract (used by analyzer.py to parse responses):
  All prompts instruct Gemini to return ONLY valid JSON.
  No markdown fences. No preamble. No explanation outside the JSON object.
  analyzer.py strips fences defensively in case Gemini ignores the instruction.

Prompt character budget:
  Prompts are kept concise. Gemini 2.0 Flash handles long context well, but
  shorter, focused prompts produce more reliable structured JSON output.
  Raw evidence is truncated to 500 chars to avoid bloating the prompt.
"""

from __future__ import annotations

from typing import Optional

# ParsedFinding imported for type hints only — no business logic used here.
# The import is from the parser models, not the analysis layer.


# ---------------------------------------------------------------------------
# Context formatting helper
# ---------------------------------------------------------------------------

def _format_context(context: dict) -> str:
    """
    Format session context dict into a readable string for prompt injection.

    Handles missing/None values gracefully — context is always optional.

    Args:
        context: Session context dict with keys exposure, environment, sector, etc.

    Returns:
        Multi-line string describing the assessment context.
        Returns "Not specified." if context is empty or all values are None.
    """
    if not context:
        return "Not specified."

    lines = []
    field_labels = {
        "exposure":     "Exposure",
        "environment":  "Environment",
        "sector":       "Industry sector",
        "company_name": "Company",
        "asset_owner":  "Asset owner",
        "scope_notes":  "Scope notes",
    }

    for key, label in field_labels.items():
        val = context.get(key)
        if val:
            lines.append(f"  {label}: {val}")

    return "\n".join(lines) if lines else "Not specified."


def _truncate_evidence(evidence: Optional[str], max_chars: int = 500) -> str:
    """
    Truncate raw evidence to a reasonable prompt size.

    Raw scanner output can be very long. Truncating avoids bloating the
    prompt while preserving the most relevant lines (usually at the start).
    """
    if not evidence:
        return "(no raw evidence)"
    evidence = evidence.strip()
    if len(evidence) <= max_chars:
        return evidence
    return evidence[:max_chars] + f"\n... [truncated, {len(evidence) - max_chars} chars omitted]"


# ---------------------------------------------------------------------------
# Finding enrichment prompt
# ---------------------------------------------------------------------------

def build_finding_enrichment_prompt(
    finding_type:  str,
    target:        str,
    port:          Optional[int],
    service:       Optional[str],
    detail:        Optional[str],
    severity_hint: Optional[str],
    raw_evidence:  Optional[str],
    context:       dict,
) -> str:
    """
    Build a prompt requesting analyst narrative + business impact for one finding.

    The response is expected to be a JSON object matching AIFindingSummary fields.
    analyzer.py parses the JSON and constructs an AIFindingSummary from it.

    Args:
        finding_type:  e.g. "VERSION_DISCLOSURE", "MISSING_HSTS"
        target:        normalized hostname or IP
        port:          port number if applicable
        service:       service name (http, ssl, etc.)
        detail:        ParsedFinding.detail — raw parser-generated description
        severity_hint: CRITICAL|HIGH|MEDIUM|LOW|INFO from the parser
        raw_evidence:  verbatim scanner output line(s)
        context:       session context dict (exposure, sector, environment)

    Returns:
        Prompt string ready for gemini_client.complete()
    """
    port_str     = str(port) if port else "N/A"
    service_str  = service or "unknown"
    detail_str   = detail or "(no detail available)"
    severity_str = severity_hint or "UNKNOWN"
    evidence_str = _truncate_evidence(raw_evidence)
    context_str  = _format_context(context)

    return f"""You are a senior penetration tester and security analyst writing a professional security assessment report.

Analyze the following security finding and produce a JSON response with analyst-quality narrative.

FINDING DETAILS:
  Type:       {finding_type}
  Target:     {target}
  Port:       {port_str}
  Service:    {service_str}
  Detail:     {detail_str}
  Severity:   {severity_str}

RAW SCANNER EVIDENCE:
{evidence_str}

ASSESSMENT CONTEXT:
{context_str}

INSTRUCTIONS:
- Write the analyst_narrative as a penetration tester would in a professional report.
  Explain WHY this finding is a security concern, not just WHAT was detected.
  Reference the specific version/detail when relevant. 2-4 sentences.
- Write the business_impact for a non-technical manager or executive audience.
  Focus on real-world consequences: data exposure, downtime, regulatory risk, reputational damage.
  2-3 sentences.
- Set severity_label to one of: CRITICAL, HIGH, MEDIUM, LOW, INFO.
  Use the provided severity as a starting point but adjust based on the context above.

RETURN ONLY valid JSON. No markdown. No explanation. No preamble.

{{
  "analyst_narrative": "string",
  "business_impact": "string",
  "severity_label": "string"
}}"""


# ---------------------------------------------------------------------------
# Remediation prompt
# ---------------------------------------------------------------------------

def build_remediation_prompt(
    finding_type:  str,
    target:        str,
    port:          Optional[int],
    service:       Optional[str],
    detail:        Optional[str],
    severity_hint: Optional[str],
    context:       dict,
) -> str:
    """
    Build a prompt requesting structured remediation guidance for one finding.

    The response is expected to be a JSON object matching AIRemediation fields.

    Args:
        finding_type:  canonical finding type string
        target:        target hostname or IP
        port:          port number if applicable
        service:       service name
        detail:        finding detail from parser
        severity_hint: severity level
        context:       session context dict

    Returns:
        Prompt string ready for gemini_client.complete()
    """
    port_str     = str(port) if port else "N/A"
    service_str  = service or "unknown"
    detail_str   = detail or "(no detail available)"
    severity_str = severity_hint or "UNKNOWN"
    context_str  = _format_context(context)

    return f"""You are a senior penetration tester writing remediation guidance for a security assessment report.

Produce specific, actionable remediation steps for the following security finding.

FINDING DETAILS:
  Type:       {finding_type}
  Target:     {target}
  Port:       {port_str}
  Service:    {service_str}
  Detail:     {detail_str}
  Severity:   {severity_str}

ASSESSMENT CONTEXT:
{context_str}

INSTRUCTIONS:
- immediate_actions: 2-3 steps that should be done within 24-72 hours.
  These are the most urgent changes to reduce risk immediately.
- short_term_actions: 2-4 steps for the next sprint/patch cycle.
  Sustainable improvements, not emergency patches.
- commands: actual copy-paste configuration commands or code snippets.
  Include the specific server/service context (nginx, Apache, Linux, etc.).
  Maximum 4 commands. Keep each on one line.
- references: 1-3 relevant standards or documentation references.
  Use short forms: "OWASP Top 10 A05", "CIS Benchmark nginx", "RFC 6797 (HSTS)".

RETURN ONLY valid JSON. No markdown. No explanation. No preamble.

{{
  "immediate_actions": ["string", ...],
  "short_term_actions": ["string", ...],
  "commands": ["string", ...],
  "references": ["string", ...]
}}"""


# ---------------------------------------------------------------------------
# Executive summary prompt
# ---------------------------------------------------------------------------

def build_executive_summary_prompt(
    targets:         list[str],
    finding_types:   list[str],
    severity_counts: dict[str, int],
    tool_names:      list[str],
    positive_notes:  list[str],
    context:         dict,
) -> str:
    """
    Build a prompt requesting an executive summary synthesizing all findings.

    Called once per session (not once per finding) after all individual
    finding enrichments are complete. Gemini synthesizes a cross-finding
    narrative suitable for the report's executive summary section.

    Args:
        targets:         list of assessed hostnames/IPs
        finding_types:   deduplicated list of finding types found
        severity_counts: {"CRITICAL": 2, "HIGH": 5, "MEDIUM": 3, ...}
        tool_names:      tools used: ["Nmap", "Httpx", "SSLScan"]
        positive_notes:  list of positive observations from parsers (TLS_ENABLED, etc.)
        context:         session context dict

    Returns:
        Prompt string ready for gemini_client.complete()
    """
    targets_str   = "\n".join(f"  - {t}" for t in targets) or "  (no targets)"
    findings_str  = "\n".join(f"  - {f}" for f in finding_types) or "  (none)"
    tools_str     = ", ".join(tool_names) or "not specified"
    context_str   = _format_context(context)

    # Format severity counts
    severity_lines = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = severity_counts.get(sev, 0)
        if count:
            severity_lines.append(f"  {sev}: {count}")
    severity_str = "\n".join(severity_lines) or "  (no findings)"

    # Positive observations
    positives_str = (
        "\n".join(f"  - {p}" for p in positive_notes)
        if positive_notes
        else "  (none recorded)"
    )

    return f"""You are a senior penetration tester writing the executive summary for a professional security assessment report.

Synthesize the following assessment data into an executive-level summary. Write for a non-technical business audience.

TARGETS ASSESSED:
{targets_str}

TOOLS USED: {tools_str}

FINDINGS BY SEVERITY:
{severity_str}

FINDING TYPES IDENTIFIED:
{findings_str}

POSITIVE SECURITY OBSERVATIONS:
{positives_str}

ASSESSMENT CONTEXT:
{context_str}

INSTRUCTIONS:
- overview_paragraph: 2-4 sentences. Describe what was assessed, the overall security posture, and one key concern.
  Write as a consultant would: professional, clear, no jargon.
- risk_posture: One word summarizing overall risk level. Must be one of: CRITICAL, HIGH, MEDIUM, LOW, POSITIVE.
- key_findings: 3-5 bullet-ready findings in plain English. Each a complete sentence.
  Prioritize the most impactful issues. No technical codes — translate finding types to plain language.
- positive_observations: 2-4 things the organization is doing right.
  Include at least one positive if positive observations exist above.
- priority_recommendation: One sentence. The single most important action to take first.

RETURN ONLY valid JSON. No markdown. No explanation. No preamble.

{{
  "overview_paragraph": "string",
  "risk_posture": "string",
  "key_findings": ["string", ...],
  "positive_observations": ["string", ...],
  "priority_recommendation": "string"
}}"""
