"""
parsers/models.py
=================
Deterministic parser data models — the canonical typed containers produced
by the parser layer.

Responsibility: define the shapes that every concrete parser (NmapParser,
HttpxParser, SslscanParser, ...) populates and that ParsedScanData (parsers/base.py)
aggregates. These are DETERMINISTIC extraction containers — they carry only
what was literally observed in a scan artifact.

Design principles:
  - Pure typed dataclasses — zero business logic, zero severity scoring,
    zero CVE lookup, zero AI calls. Scoring/enrichment is the analyzer's job.
  - Every field has a safe default (except identity fields) so a parser can
    populate only what its tool's output actually provides.
  - All fields are JSON-serializable; to_dict() drives ParsedScanData.to_dict()
    and ultimately session.json persistence of parsed evidence.

Relationship to other model layers:
  parsers/models.py  → ParsedAsset / ParsedFinding / ParsedService (THIS module)
                        deterministic extraction (authoritative)
  ai/models.py       → AIFindingSummary / AIRemediation / AIExecutiveSummary /
                        EnrichedReport — narrative enrichment that WRAPS, never
                        replaces, the deterministic findings below.
  models/session.py  → Session lifecycle/state container.

These models are NOT AI models. AI enrichment augments them; it does not
substitute for them. Keep this boundary clean.

Used by:
  parsers/base.py        — ParsedScanData aggregates assets + findings
  parsers/nmap_parser.py — constructs ParsedAsset/ParsedService/ParsedFinding
  parsers/httpx_parser.py
  parsers/sslscan_parser.py
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
                                            chosen by the parser for readability.
    asset_type    : str                   — "hostname" | "ipv4" | "ipv6" | "unknown"
    ip_addresses  : list[str]             — resolved/observed IPs (excludes `value`
                                            when value is itself the primary form).
    hostnames     : list[str]             — additional hostnames / rDNS aliases.
    services      : list[ParsedService]   — services observed on this asset.
    hosting_hint  : Optional[str]         — best-effort hint about hosting/stack
                                            (e.g. a webserver banner). Display only.
    os_name       : str                   — best-guess operating system, when the
                                            tool reports OS detection (Nmap -O).
                                            Empty string when unknown.
    os_confidence : str                   — qualitative confidence for os_name
                                            ("high" | "medium" | "low" | "").
    scan_metadata : dict                  — tool-specific extras not covered above
                                            (e.g. httpx url/title/tech, sslscan SNI).

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
# ParsedFinding — one deterministic security observation
# ---------------------------------------------------------------------------

@dataclass
class ParsedFinding:
    """
    A single deterministic security observation produced by a parser.

    This is raw, factual evidence — NOT an analyzed/scored finding. The
    severity_hint is the parser's first-pass guess; the analysis layer may
    adjust it. AI enrichment wraps this object (see ai/models.AIFindingSummary)
    and never replaces it.

    finding_type  : str            — stable machine key (e.g. "VERSION_DISCLOSURE",
                                      "WEAK_TLS_VERSION", "HIGH_RISK_PORT"). Used
                                      for correlation, dedup, and remediation lookup.
    target        : str            — the asset this finding applies to (host/IP/URL).
    port          : Optional[int]  — associated port when applicable; None otherwise.
    protocol      : str            — transport protocol when applicable (e.g. "tcp").
    service       : str            — service label when applicable (e.g. "https").
    detail        : str            — human-readable description of the observation.
    severity_hint : str            — CRITICAL|HIGH|MEDIUM|LOW|INFO (first-pass).
    raw_evidence  : str            — verbatim line/snippet supporting the finding.
    source_tool   : str            — ToolType.value of the producing parser.
    """
    finding_type:  str
    target:        str
    port:          Optional[int]  = None
    protocol:      str            = ""
    service:       str            = ""
    detail:        str            = ""
    severity_hint: str            = "INFO"
    raw_evidence:  str            = ""
    source_tool:   str            = ""

    def to_dict(self) -> dict:
        return {
            "finding_type":  self.finding_type,
            "target":        self.target,
            "port":          self.port,
            "protocol":      self.protocol,
            "service":       self.service,
            "detail":        self.detail,
            "severity_hint": self.severity_hint,
            "raw_evidence":  self.raw_evidence,
            "source_tool":   self.source_tool,
        }
