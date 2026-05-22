"""
models/session.py
=================
Session dataclass — the canonical data shape for a single client engagement.

Design principles:
  - Pure typed container: zero business logic.
  - All fields are JSON-serializable (str, int, bool, list, dict, None).
  - Schema is forward-compatible: future phases (parsers, compliance, AI)
    write to the same structure without breaking existing sessions.
  - Optional/nullable fields are pre-declared so session.json always has a
    consistent schema regardless of assessment stage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Session:
    """
    Represents a single, isolated client assessment engagement.

    session_id      — Unique identifier: <LABEL>_<YYYYMMDD>_<HHMM>
    client_label    — Human-readable session label (may be pseudonym)
    session_status  — Current lifecycle state (see SessionStatus in settings.py)
    created_at      — ISO 8601 UTC timestamp of session creation
    updated_at      — ISO 8601 UTC timestamp of last modification
    files_detected  — Count of scan files successfully ingested (Phase 2)
    targets         — List of discovered target hostnames/IPs (Phase 2)
    tools_detected  — List of tools whose output was ingested (Phase 2)
    report_generated — Whether a report has been generated for this session
    report_path     — Absolute path to the generated DOCX report (Phase 4-3)
                      None until report generation completes.
    archived        — Whether the session has been moved to archive/
    context         — Assessment context collected before report generation
                      (exposure, environment, sector, company metadata)
    compliance_hits — Per-framework compliance concern references (Phase 5)
    processing_log  — Timestamped event log for this session's pipeline
    """

    # Core identity
    session_id:    str
    client_label:  str

    # Lifecycle
    session_status: str   = "ACTIVE"
    created_at:     str   = ""
    updated_at:     str   = ""

    # Ingestion tracking (populated by Phase 2 watcher/ingest)
    files_detected: int         = 0
    targets:        list[str]   = field(default_factory=list)
    tools_detected: list[str]   = field(default_factory=list)

    # Report state
    report_generated: bool          = False
    report_path:      Optional[str] = None    # Absolute path to DOCX — set by Phase 4-3
    archived:         bool          = False

    # Context (populated by metadata_collector in Phase 3)
    context: dict = field(default_factory=lambda: {
        "exposure":     None,   # public | internal | dmz | cloud
        "environment":  None,   # production | staging | development
        "sector":       None,   # banking | healthcare | government | ...
        "company_name": None,
        "asset_owner":  None,
        "scope_notes":  None,
        "infra_notes":  None,
    })

    # Compliance engine output (populated by Phase 5)
    compliance_hits: list[str] = field(default_factory=list)

    # Internal pipeline audit trail
    processing_log: list[dict] = field(default_factory=list)

    # -----------------------------------------------------------------------
    # Serialization helpers
    # -----------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialization."""
        return {
            "session_id":        self.session_id,
            "client_label":      self.client_label,
            "session_status":    self.session_status,
            "created_at":        self.created_at,
            "updated_at":        self.updated_at,
            "files_detected":    self.files_detected,
            "targets":           self.targets,
            "tools_detected":    self.tools_detected,
            "report_generated":  self.report_generated,
            "report_path":       self.report_path,
            "archived":          self.archived,
            "context":           self.context,
            "compliance_hits":   self.compliance_hits,
            "processing_log":    self.processing_log,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        """Reconstruct a Session from a deserialized JSON dict.

        Unknown keys are ignored so old session.json files remain loadable
        after schema additions in future phases.
        """
        return cls(
            session_id=       data.get("session_id",       ""),
            client_label=     data.get("client_label",     ""),
            session_status=   data.get("session_status",   "ACTIVE"),
            created_at=       data.get("created_at",       ""),
            updated_at=       data.get("updated_at",       ""),
            files_detected=   data.get("files_detected",   0),
            targets=          data.get("targets",          []),
            tools_detected=   data.get("tools_detected",   []),
            report_generated= data.get("report_generated", False),
            report_path=      data.get("report_path",      None),
            archived=         data.get("archived",         False),
            context=          data.get("context",          {}),
            compliance_hits=  data.get("compliance_hits",  []),
            processing_log=   data.get("processing_log",   []),
        )

    def __repr__(self) -> str:
        return (
            f"Session(id={self.session_id!r}, "
            f"label={self.client_label!r}, "
            f"status={self.session_status!r})"
        )
