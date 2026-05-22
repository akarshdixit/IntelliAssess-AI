"""
intelligence/parsers/base.py
=============================
BaseParser abstract class and ParsedScanData output contract — Phase 3-1.

Responsibility: define the contract that all parsers must fulfill and the
unified data shape they return.

Design principles:
  - BaseParser is an abstract interface. Subclasses implement parse().
  - ParsedScanData is the SINGLE output type for every parser, regardless
    of tool. Downstream consumers (analyzer, compliance engine, reporter)
    depend on this contract — never on individual parser implementations.
  - This module co-locates the output contract (ParsedScanData) with the
    abstract producer (BaseParser) so that any new parser implementor reads
    one file and understands both what they must implement and what shape
    their output must conform to.
  - Parse errors are non-fatal. Parsers accumulate errors in
    ParsedScanData.parse_errors and return a partial result rather than
    raising. The caller (registry.py dispatch) decides how to surface them.
  - No business logic here. No severity scoring. No CVE lookup. No AI calls.

To add a new tool parser:
  1. Subclass BaseParser in intelligence/parsers/<toolname>_parser.py
  2. Set tool_type (ToolType) and optionally supported_subtypes
  3. Implement parse()
  4. Import and call register() in intelligence/parsers/registry.py

That is the complete extension path — zero changes to base.py or registry.py.

Relationship to existing modules:
  - Receives: classified file path + tool type + nmap subtype (from ingest.py)
  - Consumes:  ToolType, NmapSubtype (from intelligence/file_classifier.py)
  - Produces:  ParsedScanData → consumed by future analyzer.py (Phase 4)
  - Does NOT call: extractor, watcher, session_storage, AI services
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from intelligence.file_classifier import NmapSubtype, ToolType
from parsers.models import ParsedAsset, ParsedFinding, ParsedService
from utils.logger import get_logger

log = get_logger(__name__)

# Max bytes read by parsers. Larger than the classifier sample (8 KB) and
# equal to the extractor sample (512 KB). Most scan outputs fit well within
# this; for unusually large multi-host Nmap runs, parsers will work on the
# truncated sample and note the truncation in parse_errors.
PARSER_READ_BYTES: int = 524_288  # 512 KB


# ---------------------------------------------------------------------------
# ParsedScanData — unified output contract for all parsers
# ---------------------------------------------------------------------------

@dataclass
class ParsedScanData:
    """
    The unified output of any parser, regardless of source tool.

    This is the data shape that flows from the parser layer into the
    analysis layer (Phase 4). Every field is optional or has a safe
    default so parsers can populate only what their tool's output provides.

    tool_type     : str                  — ToolType.value of producing parser
    nmap_subtype  : Optional[str]        — NmapSubtype.value for Nmap files; None otherwise
    primary_target: str                  — the main assessed target (hostname or IP)
                                           Populated from scan report header or URL.
                                           May be empty for outputs with no clear target line.
    assets        : list[ParsedAsset]    — all hosts/endpoints parsed from the output
    findings      : list[ParsedFinding]  — raw security observations from this scan
    http_headers  : dict                 — response headers keyed by header name (Httpx)
                                           Empty dict for non-HTTP tool outputs.
    ssl_info      : dict                 — SSL/TLS configuration extracted by SSLScan
                                           Keys: protocols, cipher_suites, cert, vulnerabilities
                                           Empty dict for non-SSL tool outputs.
    subdomains    : list[str]            — subdomains from Subfinder output
    tool_version  : Optional[str]        — version of the scan tool that produced the output
                                           e.g. "Nmap 7.80", "httpx 1.2.9"
    scan_metadata : dict                 — tool-specific extras not covered by other fields
                                           e.g. Nmap scan flags, timing, host count
    parse_errors  : list[str]            — non-fatal issues encountered during parsing.
                                           Parsers MUST accumulate errors here rather than
                                           raising, so partial results are preserved.
                                           Format: "<parser>: <description>"
    parse_duration_ms: float             — wall-clock time for the parse() call in ms.
                                           Set automatically by the registry dispatcher.

    Phase 4+ integration note:
      analyzer.py will consume ParsedScanData. The analyzer maps:
        assets    → Target dataclass instances (models/target.py)
        findings  → Finding dataclass instances (models/finding.py)
      ParsedScanData is an intermediate representation — it is NOT persisted
      directly to session.json. Only the enriched Finding/Target objects are.
    """
    tool_type:          str
    primary_target:     str                  = ""
    nmap_subtype:       Optional[str]        = None
    assets:             list[ParsedAsset]    = field(default_factory=list)
    findings:           list[ParsedFinding]  = field(default_factory=list)
    http_headers:       dict                 = field(default_factory=dict)
    ssl_info:           dict                 = field(default_factory=dict)
    subdomains:         list[str]            = field(default_factory=list)
    tool_version:       Optional[str]        = None
    scan_metadata:      dict                 = field(default_factory=dict)
    parse_errors:       list[str]            = field(default_factory=list)
    parse_duration_ms:  float                = 0.0

    # ── Convenience properties ─────────────────────────────────────────────

    @property
    def open_ports(self) -> list[int]:
        """Aggregate open ports across all assets. Useful for quick summaries."""
        ports: list[int] = []
        for asset in self.assets:
            for svc in asset.services:
                if svc.state == "open" and svc.port not in ports:
                    ports.append(svc.port)
        return sorted(ports)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def has_errors(self) -> bool:
        return len(self.parse_errors) > 0

    @property
    def finding_count_by_severity(self) -> dict[str, int]:
        """Quick severity histogram for summary display."""
        counts: dict[str, int] = {}
        for f in self.findings:
            hint = (f.severity_hint or "INFO").upper()
            counts[hint] = counts.get(hint, 0) + 1
        return counts

    # ── Serialization ──────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "tool_type":         self.tool_type,
            "primary_target":    self.primary_target,
            "nmap_subtype":      self.nmap_subtype,
            "assets":            [a.to_dict() for a in self.assets],
            "findings":          [f.to_dict() for f in self.findings],
            "http_headers":      self.http_headers,
            "ssl_info":          self.ssl_info,
            "subdomains":        self.subdomains,
            "tool_version":      self.tool_version,
            "scan_metadata":     self.scan_metadata,
            "parse_errors":      self.parse_errors,
            "parse_duration_ms": round(self.parse_duration_ms, 2),
        }

    def summary(self) -> str:
        """One-line summary for logging."""
        return (
            f"[{self.tool_type}] target={self.primary_target!r} "
            f"assets={len(self.assets)} findings={len(self.findings)} "
            f"errors={len(self.parse_errors)} "
            f"duration={self.parse_duration_ms:.1f}ms"
        )

    def __repr__(self) -> str:
        return f"ParsedScanData({self.summary()})"


# ---------------------------------------------------------------------------
# BaseParser — abstract interface for all tool parsers
# ---------------------------------------------------------------------------

class BaseParser(ABC):
    """
    Abstract base class for all scan tool parsers.

    Each concrete parser handles one ToolType. The parse() method is the
    single required implementation — it receives file content and returns
    a ParsedScanData instance.

    To implement a new parser:
      1. Subclass BaseParser
      2. Set tool_type (ToolType)
      3. Implement parse()
      4. Register it in intelligence/parsers/registry.py

    Shared helpers provided by this base class:
      _empty_result()   — returns an empty ParsedScanData with tool_type set
      _add_error()      — appends a parse_error string in standard format
      _read_content()   — reads file bytes with UTF-8/latin-1 fallback

    Parsers MUST:
      - Return ParsedScanData (never raise on parse errors)
      - Accumulate non-fatal issues in parse_errors
      - Not call AI services, session_storage, or the analysis layer
      - Not modify session.json directly

    Parsers MUST NOT:
      - Implement severity scoring (that is the analyzer's job)
      - Look up CVEs (that is cve_enricher.py's job, Phase 4)
      - Generate report narratives (that is the reporter's job)
      - Call the extractor (extraction already happened in ingest.py)
    """

    #: ToolType this parser handles. Must be overridden by subclasses.
    tool_type: ToolType = ToolType.UNKNOWN

    @abstractmethod
    def parse(
        self,
        content: str,
        file_path: Path,
        nmap_subtype: Optional[NmapSubtype] = None,
    ) -> ParsedScanData:
        """
        Parse the content of a classified scan file.

        This is the only method subclasses must implement.

        Args:
            content:      Full (or sampled) file content as a decoded string.
                          Content is already read by the registry dispatcher —
                          parsers receive the string directly.
            file_path:    Path to the file in processed/. Use for logging and
                          for raw_evidence references; do not re-read the file.
            nmap_subtype: Nmap format subtype (TEXT/XML/GREPABLE/UNKNOWN).
                          Passed only to NmapParser; all others receive None.

        Returns:
            ParsedScanData with as much information as could be extracted.
            Non-fatal parse issues are accumulated in ParsedScanData.parse_errors.
            Parsers must NEVER raise on malformed input — return a partial
            result and record the issue in parse_errors instead.

        Contract:
            - ParsedScanData.tool_type must equal self.tool_type.value
            - ParsedScanData.nmap_subtype must be set for Nmap parsers
            - All returned list fields must be lists (not None)
            - parse_duration_ms is set by the registry dispatcher, not here
        """
        raise NotImplementedError

    # ── Shared helpers — available to all subclasses ───────────────────────

    def _empty_result(
        self,
        primary_target: str = "",
        nmap_subtype: Optional[NmapSubtype] = None,
    ) -> ParsedScanData:
        """
        Return a blank ParsedScanData with tool_type and nmap_subtype set.

        Use as the base result to build on, or as the fallback return on
        total parse failure.

        Args:
            primary_target: The main assessed target, if determinable.
            nmap_subtype:   Nmap output format subtype; None for non-Nmap.
        """
        return ParsedScanData(
            tool_type=    self.tool_type.value,
            primary_target= primary_target,
            nmap_subtype= nmap_subtype.value if nmap_subtype is not None else None,
        )

    def _add_error(self, result: ParsedScanData, message: str) -> None:
        """
        Append a parse error to result.parse_errors in standard format.

        Format: "<ToolType>Parser: <message>"

        This centralizes error formatting so logs and reports are consistent
        across all parsers without each subclass reimplementing the prefix.

        Args:
            result:  The ParsedScanData being built by parse().
            message: Human-readable description of the non-fatal issue.
        """
        entry = f"{self.tool_type.value}Parser: {message}"
        result.parse_errors.append(entry)
        log.debug("parse_error added: %s", entry)

    def _read_content(self, file_path: Path) -> Optional[str]:
        """
        Read up to PARSER_READ_BYTES from file_path.

        Used by subclasses that need to re-read a file (e.g. multi-pass
        parsers). Most parsers should use the content string passed to
        parse() by the registry dispatcher and not call this directly.

        Tries UTF-8, falls back to latin-1 (byte-transparent, never raises
        UnicodeDecodeError). Returns None on OSError.
        """
        try:
            with file_path.open("rb") as fh:
                raw = fh.read(PARSER_READ_BYTES)
        except OSError as exc:
            log.error("%sParser._read_content: OSError: %s — %s", self.tool_type.value, file_path, exc)
            return None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
        # Normalize line endings (CRLF/CR -> LF), consistent with the registry
        # dispatch read path, so multi-pass parsers that re-read are unaffected
        # by Windows-style line endings.
        return text.replace("\r\n", "\n").replace("\r", "\n")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(tool_type={self.tool_type!r})"
