"""
ai/models.py
=============
Typed data containers for Gemini AI enrichment output — Phase 4-1.

Responsibility: define the canonical shapes for enriched AI output.
These are the objects that flow FROM the AI layer INTO the report generator (Phase 4-2).

Design principles:
  - Pure typed dataclasses — zero business logic.
  - All fields are JSON-serializable.
  - Optional fields with safe defaults so partial enrichment is valid.
  - `enriched` flag on every container: False = Gemini unavailable or failed,
    report generator falls back to raw ParsedFinding.detail in that case.
  - These are ENRICHMENT containers, not finding containers. They wrap and
    augment ParsedFinding — they do not replace it.

Relationship to parser models:
  ParsedFinding (parsers/models.py) → deterministic extraction
  AIFindingSummary                  → narrative enrichment of one finding
  AIExecutiveSummary                → cross-finding synthesis for exec audience
  AIRemediation                     → prioritized remediation guidance

Used by:
  ai/analyzer.py      — produces these from Gemini responses
  reporting/reporter.py — consumes these for DOCX section building
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# AIFindingSummary — enriched narrative for a single ParsedFinding
# ---------------------------------------------------------------------------

@dataclass
class AIFindingSummary:
    """
    AI-generated narrative enrichment for one ParsedFinding.

    Wraps a single finding with analyst-quality prose that the report
    generator uses in the Technical Findings section of the DOCX report.

    finding_type       : str           — mirrors ParsedFinding.finding_type
    target             : str           — mirrors ParsedFinding.target
    port               : Optional[int] — mirrors ParsedFinding.port
    analyst_narrative  : str           — human-readable analyst explanation.
    business_impact    : str           — non-technical business risk statement.
    severity_label     : str           — CRITICAL|HIGH|MEDIUM|LOW|INFO
    enriched           : bool          — True if Gemini produced this; False = fallback.
    raw_finding_detail : str           — original ParsedFinding.detail for fallback.
    """
    finding_type:       str
    target:             str
    port:               Optional[int]  = None
    analyst_narrative:  str            = ""
    business_impact:    str            = ""
    severity_label:     str            = "INFO"
    enriched:           bool           = False
    raw_finding_detail: str            = ""

    def to_dict(self) -> dict:
        return {
            "finding_type":       self.finding_type,
            "target":             self.target,
            "port":               self.port,
            "analyst_narrative":  self.analyst_narrative,
            "business_impact":    self.business_impact,
            "severity_label":     self.severity_label,
            "enriched":           self.enriched,
            "raw_finding_detail": self.raw_finding_detail,
        }


# ---------------------------------------------------------------------------
# AIRemediation — prioritized remediation guidance for a finding type
# ---------------------------------------------------------------------------

@dataclass
class AIRemediation:
    """
    AI-generated remediation guidance for a finding type.

    finding_type       : str        — finding this remediation applies to
    target             : str        — target this was generated for
    immediate_actions  : list[str]  — steps to take within 24-72 hours
    short_term_actions : list[str]  — steps for the next sprint/release cycle
    commands           : list[str]  — copy-paste technical commands/configs
    references         : list[str]  — relevant standards/docs referenced
    enriched           : bool       — False = Gemini unavailable; use fallback
    """
    finding_type:       str
    target:             str
    immediate_actions:  list[str]   = field(default_factory=list)
    short_term_actions: list[str]   = field(default_factory=list)
    commands:           list[str]   = field(default_factory=list)
    references:         list[str]   = field(default_factory=list)
    enriched:           bool        = False

    def to_dict(self) -> dict:
        return {
            "finding_type":       self.finding_type,
            "target":             self.target,
            "immediate_actions":  self.immediate_actions,
            "short_term_actions": self.short_term_actions,
            "commands":           self.commands,
            "references":         self.references,
            "enriched":           self.enriched,
        }


# ---------------------------------------------------------------------------
# AIExecutiveSummary — cross-finding synthesis for the executive audience
# ---------------------------------------------------------------------------

@dataclass
class AIExecutiveSummary:
    """
    AI-generated executive summary synthesizing all findings for a session.

    overview_paragraph      : str       — 2-4 sentence assessment overview.
    risk_posture            : str       — CRITICAL|HIGH|MEDIUM|LOW|POSITIVE|UNKNOWN
    key_findings            : list[str] — 3-5 bullet-ready key findings.
    positive_observations   : list[str] — security controls working correctly.
    priority_recommendation : str       — single most important action.
    enriched                : bool      — False = Gemini unavailable; use fallback.
    targets_assessed        : list[str] — list of target hostnames/IPs covered
    total_findings          : int       — total finding count across all parsed data
    """
    overview_paragraph:       str        = ""
    risk_posture:             str        = "UNKNOWN"
    key_findings:             list[str]  = field(default_factory=list)
    positive_observations:    list[str]  = field(default_factory=list)
    priority_recommendation:  str        = ""
    enriched:                 bool       = False
    targets_assessed:         list[str]  = field(default_factory=list)
    total_findings:           int        = 0

    def to_dict(self) -> dict:
        return {
            "overview_paragraph":      self.overview_paragraph,
            "risk_posture":            self.risk_posture,
            "key_findings":            self.key_findings,
            "positive_observations":   self.positive_observations,
            "priority_recommendation": self.priority_recommendation,
            "enriched":                self.enriched,
            "targets_assessed":        self.targets_assessed,
            "total_findings":          self.total_findings,
        }


# ---------------------------------------------------------------------------
# EnrichedReport — top-level container passed to reporter.py
# ---------------------------------------------------------------------------

@dataclass
class EnrichedReport:
    """
    Top-level enrichment container for a complete assessment session.

    This is the single object that reporting/reporter.py consumes.

    executive_summary   : AIExecutiveSummary
    finding_summaries   : list[AIFindingSummary]  — one per notable finding
    remediations        : list[AIRemediation]      — one per finding type
    session_context     : dict                     — exposure, environment, sector
    enrichment_complete : bool  — True if all Gemini calls succeeded.
    enrichment_errors   : list[str]  — error messages from failed Gemini calls
    primary_targets     : list[str]  — deduplicated targets across all parsed data
    """
    executive_summary:    AIExecutiveSummary
    finding_summaries:    list[AIFindingSummary] = field(default_factory=list)
    remediations:         list[AIRemediation]    = field(default_factory=list)
    session_context:      dict                   = field(default_factory=dict)
    enrichment_complete:  bool                   = False
    enrichment_errors:    list[str]              = field(default_factory=list)
    primary_targets:      list[str]              = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return len(self.enrichment_errors) > 0

    @property
    def finding_count(self) -> int:
        return len(self.finding_summaries)

    def get_remediation(self, finding_type: str) -> Optional[AIRemediation]:
        """Look up remediation by finding_type. Returns None if not found."""
        for r in self.remediations:
            if r.finding_type == finding_type:
                return r
        return None

    def to_dict(self) -> dict:
        return {
            "executive_summary":   self.executive_summary.to_dict(),
            "finding_summaries":   [f.to_dict() for f in self.finding_summaries],
            "remediations":        [r.to_dict() for r in self.remediations],
            "session_context":     self.session_context,
            "enrichment_complete": self.enrichment_complete,
            "enrichment_errors":   self.enrichment_errors,
            "primary_targets":     self.primary_targets,
        }

    def summary(self) -> str:
        """One-line summary for logging."""
        return (
            f"EnrichedReport: targets={len(self.primary_targets)} "
            f"findings={self.finding_count} "
            f"enriched={self.enrichment_complete} "
            f"errors={len(self.enrichment_errors)}"
        )
