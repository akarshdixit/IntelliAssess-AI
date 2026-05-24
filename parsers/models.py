"""
parsers/models.py
=================
Deterministic parser data models — the canonical typed containers produced
by the parser layer.

Responsibility: define the shapes that every concrete parser (NmapParser,
HttpxParser, SslscanParser, ...) populates and that ParsedScanData (parsers/base.py)
aggregates. These are DETERMINISTIC extraction containers — they carry only
what was literally observed in a scan artifact PLUS the deterministic security
metadata attached at finding-construction time (title, remediation, compliance).

Design principles:
  - Pure typed dataclasses — zero AI calls, zero network, zero CVE lookup.
  - Every field has a safe default (except identity fields) so a parser can
    populate only what its tool's output actually provides.
  - All fields are JSON-serializable; to_dict() drives ParsedScanData.to_dict()
    and ultimately session.json persistence of parsed evidence.

Phase A-1 (findings standardization) note:
  ParsedFinding gained five additive, safe-defaulted fields — finding_id,
  title, remediation, compliance_refs, confidence — so that ALL findings,
  regardless of which parser produces them, share one standardized schema.
  These are populated by the centralized finding factory in
  intelligence/finding_catalog.py. The additions are backward-compatible:
  every prior field is unchanged, and to_dict() is purely additive, so the
  analyzer (which reads findings via getattr) and the reporter are unaffected
  until they are wired to consume the new fields in a later micro-phase.

  This standardized schema is the explicit precondition for the eventual
  migration of finding generation into intelligence/findings_engine.py
  (Option C). Findings built today via the catalog will require zero shape
  changes when that engine is introduced.

Relationship to other model layers:
  parsers/models.py  → ParsedAsset / ParsedFinding / ParsedService (THIS module)
  intelligence/finding_catalog.py → FindingTemplate + build_finding() factory
                        (the standardized construction path for ParsedFinding)
  ai/models.py       → AIFindingSummary / AIRemediation / AIExecutiveSummary /
                        EnrichedReport — narrative enrichment that WRAPS, never
                        replaces, the deterministic findings below.
  models/session.py  → Session lifecycle/state container.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# ParsedService — a single observed service/port on an asset
# ---------------------------------------------------------------------------

@dataclass
class ParsedService:
    """
    One service observed on a host/endpoint.

    port         : int            — the port number (e.g. 443)
    protocol     : str            — transport protocol, lower-case (e.g. "tcp")
    state        : str            — port state, lower-case (e.g. "open", "filtered")
    service_name : str            — service label from the tool (e.g. "https", "ssh")
    version      : Optional[str]  — product/version banner string when available
                                    (e.g. "nginx 1.24.0"); None when not reported.
    extra_info   : str            — raw evidence line or any tool-specific extra
                                    detail preserved verbatim for traceability.
    """
    port:          int
    protocol:      str            = "tcp"
    state:         str            = "open"
    service_name:  str            = ""
    version:       Optional[str]  = None
    extra_info:    str            = ""

    def to_dict(self) -> dict:
        return {
            "port":         self.port,
            "protocol":     self.protocol,
            "state":        self.state,
            "service_name": self.service_name,
            "version":      self.version,
            "extra_info":   self.extra_info,
        }


# ---------------------------------------------------------------------------
# ParsedAsset — a host/endpoint discovered in a scan artifact
# ---------------------------------------------------------------------------

@dataclass
class ParsedAsset:
    """
    A single asset (host or endpoint) extracted from a scan output.

    value         : str                   — primary identifier (hostname or IP)
    asset_type    : str                   — "hostname" | "ipv4" | "ipv6" | "unknown"
    ip_addresses  : list[str]             — resolved/observed IPs
    hostnames     : list[str]             — additional hostnames / rDNS aliases
    services      : list[ParsedService]   — services observed on this asset
    hosting_hint  : Optional[str]         — best-effort hosting/stack hint (display only)
    os_name       : str                   — best-guess OS when reported (Nmap -O); "" if unknown
    os_confidence : str                   — qualitative confidence ("high"|"medium"|"low"|"")
    scan_metadata : dict                  — tool-specific extras not covered above

    Convenience:
      open_ports — sorted list of ports whose service state contains "open".
    """
    value:         str
    asset_type:    str                  = "unknown"
    ip_addresses:  list[str]            = field(default_factory=list)
    hostnames:     list[str]            = field(default_factory=list)
    services:      list[ParsedService]  = field(default_factory=list)
    hosting_hint:  Optional[str]        = None
    os_name:       str                  = ""
    os_confidence: str                  = ""
    scan_metadata: dict                 = field(default_factory=dict)

    @property
    def open_ports(self) -> list[int]:
        ports: list[int] = []
        for svc in self.services:
            if "open" in (svc.state or "").lower() and svc.port not in ports:
                ports.append(svc.port)
        return sorted(ports)

    def to_dict(self) -> dict:
        return {
            "value":         self.value,
            "asset_type":    self.asset_type,
            "ip_addresses":  self.ip_addresses,
            "hostnames":     self.hostnames,
            "services":      [s.to_dict() for s in self.services],
            "hosting_hint":  self.hosting_hint,
            "os_name":       self.os_name,
            "os_confidence": self.os_confidence,
            "scan_metadata": self.scan_metadata,
        }


# ---------------------------------------------------------------------------
# ParsedFinding — one deterministic security observation (standardized schema)
# ---------------------------------------------------------------------------

@dataclass
class ParsedFinding:
    """
    A single deterministic security observation produced by a parser, built
    through the centralized finding factory (intelligence/finding_catalog.py).

    Standardized schema — every finding from every parser shares these fields:

      finding_type    : str    — stable machine key for correlation / dedup /
                                  compliance lookup (e.g. "HTTP_ONLY",
                                  "SERVICE_VERSION_DISCLOSURE"). UPPER_SNAKE_CASE.
      target          : str    — the affected asset (host / IP / URL).
      port            : Optional[int] — associated port when applicable.
      protocol        : str    — transport protocol when applicable (e.g. "tcp").
      service         : str    — service label when applicable (e.g. "http").
      detail          : str    — human-readable technical description.
      severity_hint   : str    — CRITICAL|HIGH|MEDIUM|LOW|INFO (deterministic first-pass).
      raw_evidence    : str    — verbatim line/snippet supporting the finding.
      source_tool     : str    — ToolType.value of the producing parser.

    Phase A-1 additive fields (standardized finding metadata):

      finding_id      : str    — stable catalog identifier, distinct from
                                  finding_type, suitable for report/audit
                                  cross-referencing (e.g. "IAA-WEB-001").
      title           : str    — short human title (e.g. "Cleartext HTTP Service Exposed").
      remediation     : str    — deterministic baseline remediation guidance.
                                  AI enrichment may improve this; it is never
                                  required for the report to contain remediation.
      compliance_refs : dict   — {framework: [control_ref, ...]} from compliance.py.
                                  Empty dict when the finding type has no mapping.
      confidence      : str    — qualitative confidence in the finding itself
                                  ("high"|"medium"|"low"|""). Used for findings
                                  inferred from unreliable signals (e.g. OS guesses).

    AI enrichment wraps this object (see ai/models.AIFindingSummary) and never
    replaces it. The deterministic values above stand on their own offline.
    """
    finding_type:    str
    target:          str
    port:            Optional[int]  = None
    protocol:        str            = ""
    service:         str            = ""
    detail:          str            = ""
    severity_hint:   str            = "INFO"
    raw_evidence:    str            = ""
    source_tool:     str            = ""
    # ── Phase A-1 standardized finding metadata (additive) ─────────────────
    finding_id:      str            = ""
    title:           str            = ""
    remediation:     str            = ""
    compliance_refs: dict           = field(default_factory=dict)
    confidence:      str            = ""

    def to_dict(self) -> dict:
        return {
            "finding_type":    self.finding_type,
            "target":          self.target,
            "port":            self.port,
            "protocol":        self.protocol,
            "service":         self.service,
            "detail":          self.detail,
            "severity_hint":   self.severity_hint,
            "raw_evidence":    self.raw_evidence,
            "source_tool":     self.source_tool,
            "finding_id":      self.finding_id,
            "title":           self.title,
            "remediation":     self.remediation,
            "compliance_refs": self.compliance_refs,
            "confidence":      self.confidence,
        }
