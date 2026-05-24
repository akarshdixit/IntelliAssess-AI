"""
ai/models.py
============
Structured data models for the AI enrichment layer of IntelliAssess AI.

Responsibility: define the typed containers that ai/analyzer.py produces and
reporting/reporter.py consumes. These are pure dataclasses — zero I/O, zero
network, zero business logic — mirroring the design discipline of
parsers/models.py.

Architecture position:
  parsers → ParsedScanData → analyzer.run() → EnrichedReport → reporter

Phase 1C (semantic propagation) note:
  AIFindingSummary gained FIVE additive, safe-defaulted deterministic fields —
  finding_id, title, remediation, compliance_refs, confidence — so that the
  authoritative metadata attached by intelligence/finding_catalog.build_finding()
  survives intact through the analyzer and into the reporter. Previously the
  analyzer flattened findings into a minimal dict and the reporter was forced to
  reconstruct generic titles and boilerplate remediation. These fields are the
  carriers that let the reporter render the deterministic catalog's title,
  remediation, and compliance references directly — with full quality even when
  Gemini is unavailable. The additions are backward-compatible: every prior
  field is unchanged and every new field defaults to an empty value, so any code
  not yet wired to consume them is unaffected.

  AI enrichment remains strictly additive: Gemini populates analyst_narrative,
  business_impact, and the AIRemediation action lists. It never overwrites the
  deterministic finding_id / title / remediation / compliance_refs, and (as of
  Phase 1C) it no longer overrides the deterministic severity either — the
  catalog severity is authoritative; any AI-suggested severity is advisory only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# AIFindingSummary
# ---------------------------------------------------------------------------

@dataclass
class AIFindingSummary:
    """
    One finding, carrying both deterministic catalog metadata (authoritative)
    and optional AI-generated narrative (enhancement).

    Deterministic fields (from intelligence/finding_catalog.build_finding):
        finding_id, title, remediation, compliance_refs, confidence,
        severity_label (sourced from the catalog severity), raw_finding_detail.

    AI-enhancement fields (populated only when enriched=True):
        analyst_narrative, business_impact.

    The reporter prefers deterministic fields and treats AI text as an overlay,
    so an unenriched (offline) summary still renders a complete, professional
    finding.
    """
    finding_type:       str
    target:             str
    port:               Optional[int]      = None

    # ── AI enhancement (optional) ──────────────────────────────────────────
    analyst_narrative:  str                = ""
    business_impact:    str                = ""
    enriched:           bool               = False

    # ── Deterministic carry-through (authoritative) ────────────────────────
    severity_label:     str                = "INFO"
    raw_finding_detail: str                = ""
    finding_id:         str                = ""
    title:              str                = ""
    remediation:        str                = ""
    compliance_refs:    dict               = field(default_factory=dict)
    confidence:         float              = 1.0


# ---------------------------------------------------------------------------
# AIRemediation
# ---------------------------------------------------------------------------

@dataclass
class AIRemediation:
    """
    Structured AI-generated remediation guidance for one finding_type.

    This is purely an enhancement layer. When enriched=False (offline / failed
    enrichment) every list is empty and the reporter falls back to the
    deterministic per-finding remediation carried on AIFindingSummary.remediation.
    """
    finding_type:        str
    target:              str        = ""
    immediate_actions:   list[str]  = field(default_factory=list)
    short_term_actions:  list[str]  = field(default_factory=list)
    commands:            list[str]  = field(default_factory=list)
    references:          list[str]  = field(default_factory=list)
    enriched:            bool       = False


# ---------------------------------------------------------------------------
# AIExecutiveSummary
# ---------------------------------------------------------------------------

@dataclass
class AIExecutiveSummary:
    """
    The executive summary block.

    When enriched=True it carries an AI-written overview paragraph and key
    findings. When enriched=False the reporter renders a structured data-table
    summary instead, driven by risk_posture / total_findings / positive
    observations — all of which are computed deterministically.
    """
    overview_paragraph:      str        = ""
    risk_posture:            str        = "UNKNOWN"
    key_findings:            list[str]  = field(default_factory=list)
    positive_observations:   list[str]  = field(default_factory=list)
    priority_recommendation: str        = ""
    enriched:                bool       = False
    targets_assessed:        list[str]  = field(default_factory=list)
    total_findings:          int        = 0


# ---------------------------------------------------------------------------
# EnrichedReport
# ---------------------------------------------------------------------------

@dataclass
class EnrichedReport:
    """
    The complete enriched assessment, returned by analyzer.run() and consumed
    by reporting/reporter.generate_docx().

    Always valid: analyzer.run() guarantees a fully-populated EnrichedReport
    even when Gemini is entirely unavailable (every enriched flag False, but all
    deterministic data present).
    """
    executive_summary:   AIExecutiveSummary
    finding_summaries:   list[AIFindingSummary] = field(default_factory=list)
    remediations:        list[AIRemediation]    = field(default_factory=list)
    session_context:     dict                   = field(default_factory=dict)
    enrichment_complete: bool                   = False
    enrichment_errors:   list[str]              = field(default_factory=list)
    primary_targets:     list[str]              = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        """Total number of finding summaries in the report."""
        return len(self.finding_summaries)

    def get_remediation(self, finding_type: str) -> Optional[AIRemediation]:
        """
        Return the AIRemediation for a given finding_type, or None if no
        type-level remediation was produced (e.g. offline mode).

        Remediation is generated once per finding_type by the analyzer, so the
        first match is authoritative.
        """
        for r in self.remediations:
            if getattr(r, "finding_type", None) == finding_type:
                return r
        return None

    def summary(self) -> str:
        """One-line diagnostic summary for logging."""
        enriched_findings = sum(
            1 for f in self.finding_summaries if getattr(f, "enriched", False)
        )
        return (
            f"EnrichedReport(findings={self.finding_count}, "
            f"enriched={enriched_findings}, "
            f"remediations={len(self.remediations)}, "
            f"targets={len(self.primary_targets)}, "
            f"complete={self.enrichment_complete}, "
            f"errors={len(self.enrichment_errors)})"
        )
