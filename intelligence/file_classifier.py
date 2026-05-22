"""
intelligence/file_classifier.py
================================
Content-based scan tool classification for IntelliAssess AI — Phase 2B-2.

Responsibility: identify WHICH security tool produced a given file,
and for Nmap outputs, WHICH output format was used.
Nothing else. No parsing. No extraction. No analysis.

Architecture: Registry Pattern
-------------------------------
Each supported tool type registers a Detector object at module load time.
Adding a new tool requires one new Detector subclass + one register() call.
Zero changes to the orchestration logic (classify()) are ever needed.

Detection strategy: Weighted Signature Matching
------------------------------------------------
Each Detector holds a list of SignatureRule objects. Each rule is a
regex pattern or literal string with an associated weight (importance).
A file's confidence score for a given tool =
    sum(weight for each matched rule) / sum(all rule weights)

This yields a float in [0.0, 1.0].

Phase 2B-2 addition: Nmap Subtype Detection
--------------------------------------------
After primary classification confirms ToolType.NMAP, a secondary pass
identifies which output format Nmap used: XML, plain-text, or grepable.

The NmapDetector now uses format-partitioned rule groups so that cross-format
signal dilution is eliminated. XML-only signals no longer depress confidence
when a plain-text file is scored (and vice versa). The overall score is the
maximum across all format groups.

New public API added (existing API unchanged):
  classify_with_subtype(file_path) -> tuple[ToolType, NmapSubtype | None, float]

The original classify() is fully backward-compatible — it still returns
tuple[ToolType, float] without subtype information.

Phase 2C integration note:
  classify() and classify_with_subtype() returns are consumed by
  target_extractor.py (Phase 2C). ToolType + NmapSubtype together form
  the parser-dispatch contract for the parsers/ package.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

# Number of bytes read from the start of a file for classification.
# All current tool types emit identifying markers in their first kilobytes.
# Large enough for most scan headers; small enough to be instantaneous.
SAMPLE_BYTES: int = 8_192

# Minimum confidence required to claim a specific tool type.
# Below this threshold → UNKNOWN is returned.
# 0.40 accepts partial matches (e.g., truncated or piped outputs)
# while preventing false positives between tool types.
MIN_CONFIDENCE_THRESHOLD: float = 0.40

# Minimum confidence required to claim a specific Nmap subtype.
# Set lower than the primary threshold — by the time subtype detection runs
# we already know the file is Nmap. A weaker signal is acceptable here
# because the worst outcome is NMAP_UNKNOWN (graceful degradation), not
# a false positive claiming the wrong tool entirely.
MIN_SUBTYPE_CONFIDENCE: float = 0.30


# ---------------------------------------------------------------------------
# ToolType enum — canonical tool identifiers
# ---------------------------------------------------------------------------

class ToolType(str, Enum):
    """
    Canonical identifiers for supported scan tool types.

    Inherits from str so ToolType values serialize to plain strings in JSON
    and session.json without special handling.

    ToolType.NMAP covers all Nmap output formats. Use NmapSubtype for
    format-level distinction when needed by parsers (Phase 2C+).
    """
    NMAP      = "NMAP"
    HTTPX     = "HTTPX"
    SSLSCAN   = "SSLSCAN"
    SUBFINDER = "SUBFINDER"
    UNKNOWN   = "UNKNOWN"


# ---------------------------------------------------------------------------
# NmapSubtype enum — Phase 2B-2
# ---------------------------------------------------------------------------

class NmapSubtype(str, Enum):
    """
    Output format subtypes for Nmap scan results.

    Inherits from str for JSON serialization consistency with ToolType.

    Values correspond to Nmap's -oN / -oX / -oG output format flags:

      TEXT     — human-readable plain-text output (-oN)
      XML      — machine-parseable XML output (-oX)
      GREPABLE — grep-friendly single-line output (-oG)
      UNKNOWN  — Nmap confirmed but format could not be determined
                 (e.g. truncated file, custom piped output)

    Future placeholders (NOT yet implemented — reserved for Phase 3+):
      The scan-mode distinction (aggressive vs service-scan vs vuln-scan)
      is detectable from flags in plain-text and XML headers, but is
      deferred until the parser layer (Phase 2C/3) actually needs it.
      Parser dispatch is entirely format-driven, not scan-mode-driven.
    """
    TEXT     = "NMAP_TEXT"
    XML      = "NMAP_XML"
    GREPABLE = "NMAP_GREPABLE"
    UNKNOWN  = "NMAP_UNKNOWN"


# ---------------------------------------------------------------------------
# Signature rule — atomic detection unit
# ---------------------------------------------------------------------------

@dataclass
class SignatureRule:
    """
    A single detection signal for a tool type.

    pattern     : str  — regex pattern or literal string to search for.
    weight      : float — contribution to the confidence score if matched.
                          Higher weight = more distinctive marker.
    is_regex    : bool  — if False, plain substring match (faster, no regex overhead).
    flags       : int   — re module flags applied when is_regex=True.
                          Defaults to re.IGNORECASE | re.MULTILINE.

    Weight guidelines:
      1.0 — unique marker that appears in this tool's output and no other
      0.7 — strong indicator but also appears in generic text occasionally
      0.4 — supporting evidence; corroborates other signals
      0.2 — weak signal; only meaningful when combined with others

    Example:
      SignatureRule("Nmap scan report for", weight=1.0, is_regex=False)
      SignatureRule(r"^\\d+/(tcp|udp)\\s+(open|closed|filtered)", weight=0.9)
    """
    pattern  : str
    weight   : float = 1.0
    is_regex : bool  = True
    flags    : int   = re.IGNORECASE | re.MULTILINE

    def matches(self, content: str) -> bool:
        """Return True if this rule's pattern is found in content."""
        if self.is_regex:
            return bool(re.search(self.pattern, content, self.flags))
        else:
            return self.pattern.lower() in content.lower()


# ---------------------------------------------------------------------------
# Detector base class — one subclass per tool type
# ---------------------------------------------------------------------------

class Detector:
    """
    Abstract detector for a single tool type.

    Subclasses declare their tool_type and rules list.
    The score() method is implemented here and is not overridden.

    To add a new tool:
      1. Subclass Detector.
      2. Set tool_type and rules.
      3. Call register(YourDetector()) at module level.

    No changes to classify() or the registry machinery are needed.
    """

    #: The ToolType this detector identifies. Must be set by subclasses.
    tool_type: ToolType = ToolType.UNKNOWN

    #: List of SignatureRules used to score a file's content.
    rules: list[SignatureRule] = []

    def score(self, content: str) -> float:
        """
        Score the content against this detector's signature rules.

        Returns a float in [0.0, 1.0]:
          0.0 — no rules matched
          1.0 — all rules matched (all weights satisfied)

        If rules list is empty, returns 0.0 (a misconfigured detector
        never claims a match).
        """
        if not self.rules:
            return 0.0

        total_weight   = sum(r.weight for r in self.rules)
        matched_weight = sum(r.weight for r in self.rules if r.matches(content))

        if total_weight == 0:
            return 0.0

        return matched_weight / total_weight

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(tool_type={self.tool_type!r}, rules={len(self.rules)})"


# ---------------------------------------------------------------------------
# Detector registry — module-level, populated at import time
# ---------------------------------------------------------------------------

_registry: list[Detector] = []


def register(detector: Detector) -> Detector:
    """
    Register a Detector instance in the classification registry.

    Usage:
        register(NmapDetector())

    Returns the detector so it can be used inline if needed.
    Registration order does not affect classification correctness
    (highest confidence wins), but earlier registration is evaluated first
    in the iteration, which can matter for performance on large registries.
    """
    _registry.append(detector)
    log.debug("Detector registered: %s", detector)
    return detector


# ---------------------------------------------------------------------------
# Concrete detectors — one per supported tool type
# ---------------------------------------------------------------------------

class NmapDetector(Detector):
    """
    Detector for Nmap scan outputs — all output formats.

    Phase 2B-2 improvement: format-partitioned rule groups.
    --------------------------------------------------------
    The original implementation mixed XML signals (e.g. <nmaprun>) with
    plain-text signals (e.g. PORT STATE SERVICE) in a single flat rules
    list. This caused confidence dilution: an XML file would miss all the
    text-specific rules, artificially lowering its score.

    Fix: rules are organised into three named groups (TEXT, XML, GREPABLE).
    The score() override returns the MAXIMUM group score rather than the
    average across all rules. This ensures that a file matching one format
    perfectly scores ~1.0 regardless of how poorly it scores for other
    formats.

    The tool-level rules list is retained for backward compatibility with
    the base Detector.score() — it contains all rules from all groups.
    Callers using the base score() still get correct behavior (the maximum
    group approach is only needed when the dilution problem is present).

    Phase 2B-2 adds a dedicated score_format() method that implements the
    group-maximum strategy. The primary classify() uses base score() which
    is sufficient for tool-level identification. The subtype detector uses
    score_format() for precise format scoring.
    """
    tool_type = ToolType.NMAP

    # ── Format-specific rule groups ─────────────────────────────────────────
    # Organised as class-level group dicts so subtypes can be detected
    # independently and without interference between format signals.

    # Plain-text (-oN) signals
    _TEXT_RULES: list[SignatureRule] = [
        # Most distinctive plain-text header — appears on line 1 of every scan
        SignatureRule(r"nmap scan report for", weight=1.0, is_regex=True),
        # PORT/STATE/SERVICE column header — only in plain-text output
        SignatureRule(r"^PORT\s+STATE\s+SERVICE", weight=0.9, is_regex=True),
        # Individual port table rows: "80/tcp   open   http"
        SignatureRule(r"^\d+/(tcp|udp)\s+(open|closed|filtered)\s+\S", weight=0.8, is_regex=True),
        # Nmap done footer — appears in text and grepable, but with different format
        # In plain-text: "Nmap done: 1 IP address (1 host up) scanned in 39.26 seconds"
        SignatureRule(r"nmap done:\s+\d+\s+IP\s+address", weight=0.8, is_regex=True),
        # OS/Service info block — exclusive to verbose plain-text
        SignatureRule(r"^Service Info:", weight=0.5, is_regex=True),
        # Nmap version line in plain-text header comment
        SignatureRule(r"#\s+nmap\s+\S+\s+scan\s+initiated", weight=0.6, is_regex=True),
    ]

    # XML (-oX) signals
    _XML_RULES: list[SignatureRule] = [
        # XML declaration — strong indicator (most XML files start with this)
        SignatureRule(r"<\?xml\s+version", weight=0.7, is_regex=True),
        # <nmaprun> root element — unique to Nmap XML; nothing else uses this tag
        SignatureRule(r"<nmaprun\s", weight=1.0, is_regex=True),
        # <host> element — appears in every XML scan with at least one host
        SignatureRule(r"<host\s", weight=0.7, is_regex=True),
        # <ports> element — contains the scan results
        SignatureRule(r"<ports>", weight=0.8, is_regex=True),
        # <port protocol= portid= element — inner port detail
        SignatureRule(r'<port\s+protocol="(tcp|udp)"\s+portid="\d+"', weight=0.9, is_regex=True),
        # <state state= element
        SignatureRule(r'<state\s+state="(open|closed|filtered)"', weight=0.8, is_regex=True),
        # </nmaprun> closing tag
        SignatureRule(r"</nmaprun>", weight=0.9, is_regex=True),
    ]

    # Grepable (-oG) signals
    _GREPABLE_RULES: list[SignatureRule] = [
        # "#Nmap" comment prefix — all grepable output lines are comment or Host/Ports
        SignatureRule(r"^#\s*nmap\s+\S+\s+scan\s+initiated", weight=0.9, is_regex=True),
        # "Host:" line — grepable format identifies each host on one line
        SignatureRule(r"^Host:\s+[\d\.]+\s+\(", weight=1.0, is_regex=True),
        # "Ports:" field on the Host line
        SignatureRule(r"\bPorts:\s+\d+/(open|closed|filtered)", weight=1.0, is_regex=True),
        # "Status:" field — also on the Host line in grepable output
        SignatureRule(r"\bStatus:\s+(Up|Down)\b", weight=0.7, is_regex=True),
        # Grepable footer comment
        SignatureRule(r"^#\s+nmap\s+done\s+at", weight=0.6, is_regex=True),
    ]

    # Combined flat rules list — used by base Detector.score() for tool-level
    # identification. All rules from all groups are included.
    rules: list[SignatureRule] = _TEXT_RULES + _XML_RULES + _GREPABLE_RULES

    # ── Override base score() — group-maximum strategy ──────────────────────

    def score(self, content: str) -> float:
        """
        Override base Detector.score() to use the group-maximum strategy.

        Nmap has three mutually exclusive output formats. A file matching
        XML format perfectly will score 0.0 on TEXT rules and vice versa.
        Averaging all rules together causes inter-format signal dilution
        that can push confidence below the classification threshold.

        This override scores each format group independently and returns
        the MAXIMUM group score. A file that matches any single format
        cleanly will score appropriately regardless of the other formats.

        Example: a plain-text Nmap file scores 0.83 for TEXT, 0.0 for XML,
        0.35 for GREPABLE → returns 0.83 instead of the diluted 0.36.
        """
        text_score = self.score_format(content, self._TEXT_RULES)
        xml_score  = self.score_format(content, self._XML_RULES)
        grep_score = self.score_format(content, self._GREPABLE_RULES)
        return max(text_score, xml_score, grep_score)

    # ── Format scoring — used by subtype detection ───────────────────────────

    def score_format(self, content: str, fmt_rules: list[SignatureRule]) -> float:
        """
        Score content against a specific format's rule group.

        Returns a float in [0.0, 1.0] representing how well the content
        matches the given format's signature rules. Each format is scored
        independently to avoid inter-format signal dilution.
        """
        if not fmt_rules:
            return 0.0
        total   = sum(r.weight for r in fmt_rules)
        matched = sum(r.weight for r in fmt_rules if r.matches(content))
        return matched / total if total > 0 else 0.0

    def detect_subtype(self, content: str) -> tuple[NmapSubtype, float]:
        """
        Identify which Nmap output format the content uses.

        Scores the content against each format's rule group independently.
        Returns the (NmapSubtype, confidence) with the highest score.

        If no format clears MIN_SUBTYPE_CONFIDENCE, returns
        (NmapSubtype.UNKNOWN, 0.0) — graceful degradation.

        Called by detect_nmap_subtype() after primary classification
        confirms ToolType.NMAP.
        """
        format_groups: list[tuple[NmapSubtype, list[SignatureRule]]] = [
            (NmapSubtype.XML,      self._XML_RULES),
            (NmapSubtype.TEXT,     self._TEXT_RULES),
            (NmapSubtype.GREPABLE, self._GREPABLE_RULES),
        ]

        best_subtype    = NmapSubtype.UNKNOWN
        best_confidence = 0.0

        for subtype, fmt_rules in format_groups:
            confidence = self.score_format(content, fmt_rules)
            log.debug(
                "nmap subtype score: %s → %.2f", subtype.value, confidence
            )
            if confidence > best_confidence:
                best_confidence = confidence
                best_subtype    = subtype

        if best_confidence < MIN_SUBTYPE_CONFIDENCE:
            log.debug(
                "nmap subtype: UNKNOWN (best=%.2f below threshold %.2f)",
                best_confidence, MIN_SUBTYPE_CONFIDENCE,
            )
            return (NmapSubtype.UNKNOWN, 0.0)

        return (best_subtype, best_confidence)


class HttpxDetector(Detector):
    """
    Detector for Httpx outputs.

    Httpx JSON (-json) markers:
      - JSON object with "status_code" field
      - JSON object with "content_length" field
      - JSON object with "url" field
      - JSON object with "webserver" or "tech" arrays

    Httpx plain-text markers:
      - Lines containing status codes in brackets: [200]
      - Lines with URL + status code patterns

    JSON format is strongly indicated by the co-presence of
    status_code + url + content_length in the same content block.
    """
    tool_type = ToolType.HTTPX
    rules = [
        # JSON key "status_code" — distinctive to Httpx JSON output
        SignatureRule(r'"status_code"\s*:', weight=1.0, is_regex=True),
        # JSON key "content_length" — standard Httpx JSON field
        SignatureRule(r'"content_length"\s*:', weight=0.8, is_regex=True),
        # JSON key "url" alongside scan data
        SignatureRule(r'"url"\s*:\s*"https?://', weight=0.7, is_regex=True),
        # "webserver" field — Httpx tech detection
        SignatureRule(r'"webserver"\s*:', weight=0.6, is_regex=True),
        # Plain-text format: [200] http://target
        SignatureRule(r'\[2\d\d\]\s+https?://', weight=0.6, is_regex=True),
        # "tech" array in JSON output
        SignatureRule(r'"tech"\s*:\s*\[', weight=0.5, is_regex=True),
        # "title" field in JSON output
        SignatureRule(r'"title"\s*:', weight=0.4, is_regex=True),
    ]


class SslscanDetector(Detector):
    """
    Detector for SSLScan outputs.

    SSLScan markers:
      - "Testing SSL server" header
      - "Supported Server Cipher(s)" section
      - "SSL Certificate:" block
      - TLS version lines: "TLSv1.2  enabled"
      - sslscan version banner
    """
    tool_type = ToolType.SSLSCAN
    rules = [
        # Primary header — highly distinctive
        SignatureRule(r"Testing SSL server", weight=1.0, is_regex=True),
        # Cipher suite section header
        SignatureRule(r"Supported Server Cipher\(s\)", weight=0.9, is_regex=True),
        # Certificate block
        SignatureRule(r"SSL Certificate:", weight=0.8, is_regex=True),
        # TLS protocol line
        SignatureRule(r"TLSv\d[\.\d]*\s+(enabled|disabled)", weight=0.8, is_regex=True),
        # sslscan version banner
        SignatureRule(r"sslscan\s+version", weight=0.7, is_regex=True),
        # Heartbleed test line
        SignatureRule(r"Heartbleed:", weight=0.5, is_regex=True),
        # Subject / Issuer lines from cert block
        SignatureRule(r"Subject:\s*/[A-Z]+=", weight=0.4, is_regex=True),
    ]


class SubfinderDetector(Detector):
    """
    Detector for Subfinder outputs.

    Subfinder markers:
      - JSON output contains "host" and "source" fields
      - Plain-text output is a list of subdomains (one per line)
      - Subfinder banner: [INF] and [subfinder] prefixes
      - Domain enumeration context

    Plain-text subdomain lists are the hardest format to classify
    confidently because they look similar to any domain list.
    Subfinder-specific banner lines are the strongest signals.
    """
    tool_type = ToolType.SUBFINDER
    rules = [
        # Subfinder INF banner — most distinctive marker
        SignatureRule(r"\[INF\].*subfinder", weight=1.0, is_regex=True),
        # JSON output: "host" + "source" fields
        SignatureRule(r'"host"\s*:\s*"[^"]+\.[^"]+"', weight=0.8, is_regex=True),
        SignatureRule(r'"source"\s*:', weight=0.6, is_regex=True),
        # Subfinder found X subdomains line
        SignatureRule(r"\[INF\]\s+Found\s+\d+\s+subdomains", weight=0.9, is_regex=True),
        # Plain-text subdomain list: multiple lines each being a valid subdomain
        # This is a weak signal on its own — relies on co-presence with others
        SignatureRule(
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,}){1,}$",
            weight=0.3,
            is_regex=True,
            flags=re.MULTILINE,
        ),
    ]


# ---------------------------------------------------------------------------
# Module-level NmapDetector instance reference
# Used by subtype detection without re-scanning the registry.
# ---------------------------------------------------------------------------

_nmap_detector = NmapDetector()


# ---------------------------------------------------------------------------
# Register all detectors at module load time
# ---------------------------------------------------------------------------

register(_nmap_detector)
register(HttpxDetector())
register(SslscanDetector())
register(SubfinderDetector())


# ---------------------------------------------------------------------------
# Public classification API
# ---------------------------------------------------------------------------

def classify(file_path: Path) -> tuple[ToolType, float]:
    """
    Identify the scan tool that produced file_path.

    Backward-compatible API — returns (ToolType, confidence).
    For Nmap files, use classify_with_subtype() to also get format info.

    Reads the first SAMPLE_BYTES of the file, scores each registered
    detector, and returns the (ToolType, confidence) pair with the
    highest confidence score above MIN_CONFIDENCE_THRESHOLD.

    Returns (ToolType.UNKNOWN, 0.0) if:
      - The file does not exist or cannot be read.
      - No detector scores above MIN_CONFIDENCE_THRESHOLD.
      - The file is empty.

    Thread-safe: reads only, no shared mutable state.

    Args:
        file_path: Path to the file in processed/ (or anywhere).

    Returns:
        tuple[ToolType, float]: Detected tool type and confidence score.

    Example:
        >>> classify(Path("processed/nmap_scan.txt"))
        (ToolType.NMAP, 0.95)
    """
    tool_type, _, confidence = _classify_internal(file_path)
    return (tool_type, confidence)


def classify_with_subtype(
    file_path: Path,
) -> tuple[ToolType, Optional[NmapSubtype], float]:
    """
    Identify the scan tool and, for Nmap files, the output format subtype.

    Returns a 3-tuple: (ToolType, NmapSubtype | None, confidence)

      - For Nmap files: (ToolType.NMAP, NmapSubtype.TEXT | .XML | .GREPABLE | .UNKNOWN, confidence)
      - For all other tools: (ToolType.HTTPX | .SSLSCAN | ..., None, confidence)
      - For unrecognized files: (ToolType.UNKNOWN, None, 0.0)

    The subtype is None (not NmapSubtype.UNKNOWN) for non-Nmap tools to
    signal "not applicable" vs "applicable but indeterminate".

    Thread-safe: reads only, no shared mutable state.

    Args:
        file_path: Path to any scan output file.

    Returns:
        tuple[ToolType, NmapSubtype | None, float]

    Example:
        >>> classify_with_subtype(Path("processed/scan.xml"))
        (ToolType.NMAP, NmapSubtype.XML, 0.93)
        >>> classify_with_subtype(Path("processed/httpx.json"))
        (ToolType.HTTPX, None, 0.88)
    """
    return _classify_internal(file_path)


def detect_nmap_subtype(content: str) -> tuple[NmapSubtype, float]:
    """
    Detect the Nmap output format from already-read content.

    Convenience function for callers that have already read the file
    content (e.g. parsers in Phase 2C+ that read the full file).
    Delegates to NmapDetector.detect_subtype().

    Returns (NmapSubtype, confidence). Always returns a valid NmapSubtype —
    falls back to NmapSubtype.UNKNOWN on low confidence rather than raising.

    Args:
        content: String content of a confirmed Nmap output file.

    Returns:
        tuple[NmapSubtype, float]
    """
    return _nmap_detector.detect_subtype(content)


# ---------------------------------------------------------------------------
# Internal orchestration
# ---------------------------------------------------------------------------

def _classify_internal(
    file_path: Path,
) -> tuple[ToolType, Optional[NmapSubtype], float]:
    """
    Core classification logic shared by classify() and classify_with_subtype().

    1. Read file sample.
    2. Score all registered detectors.
    3. Pick highest-confidence tool type.
    4. If ToolType.NMAP, run secondary subtype detection.
    5. Return (ToolType, NmapSubtype | None, confidence).
    """
    content = _read_sample(file_path)
    if content is None:
        log.warning("classify: cannot read file: %s", file_path)
        return (ToolType.UNKNOWN, None, 0.0)

    if not content.strip():
        log.info("classify: empty file: %s", file_path.name)
        return (ToolType.UNKNOWN, None, 0.0)

    best_type       : ToolType = ToolType.UNKNOWN
    best_confidence : float    = 0.0

    for detector in _registry:
        confidence = detector.score(content)
        log.debug(
            "classify: [%s] %s → %.2f",
            file_path.name, detector.tool_type.value, confidence,
        )
        if confidence > best_confidence:
            best_confidence = confidence
            best_type       = detector.tool_type

    if best_confidence < MIN_CONFIDENCE_THRESHOLD:
        log.info(
            "classify: [%s] UNKNOWN (best=%.2f below threshold %.2f)",
            file_path.name, best_confidence, MIN_CONFIDENCE_THRESHOLD,
        )
        return (ToolType.UNKNOWN, None, 0.0)

    # ── Phase 2B-2: Nmap subtype detection ──────────────────────────────────
    subtype: Optional[NmapSubtype] = None
    if best_type is ToolType.NMAP:
        subtype, subtype_conf = _nmap_detector.detect_subtype(content)
        log.info(
            "classify: [%s] → %s / %s (tool_conf=%.2f, subtype_conf=%.2f)",
            file_path.name, best_type.value, subtype.value,
            best_confidence, subtype_conf,
        )
    else:
        log.info(
            "classify: [%s] → %s (confidence=%.2f)",
            file_path.name, best_type.value, best_confidence,
        )

    return (best_type, subtype, best_confidence)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_sample(file_path: Path) -> Optional[str]:
    """
    Read the first SAMPLE_BYTES from file_path and return as a string.

    Tries UTF-8 first (most scan tools emit ASCII/UTF-8).
    Falls back to latin-1 (byte-transparent, never raises UnicodeDecodeError)
    so binary-adjacent outputs (e.g. nmap with non-ASCII hostnames) are
    handled without crashing the classifier.

    Returns None only on OSError (file missing, permission denied, etc.).
    """
    try:
        with file_path.open("rb") as fh:
            raw = fh.read(SAMPLE_BYTES)
    except OSError as exc:
        log.error("_read_sample: OSError reading %s: %s", file_path, exc)
        return None

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    # Normalize line endings (CRLF/CR -> LF) so content-based classification is
    # line-ending agnostic, consistent with the parser and extractor read paths.
    return text.replace("\r\n", "\n").replace("\r", "\n")


def list_registered_detectors() -> list[str]:
    """
    Return a list of registered detector names (for diagnostics/logging).

    Usage:
        log.debug("Registered detectors: %s", list_registered_detectors())
    """
    return [f"{d.tool_type.value}({len(d.rules)} rules)" for d in _registry]
