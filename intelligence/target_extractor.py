"""
intelligence/target_extractor.py
=================================
Deterministic target extraction for IntelliAssess AI — Phase 2C-2.

Responsibility: identify and normalize assessed target identifiers from
classified scan output files. Nothing more.

  - NO port or service analysis
  - NO vulnerability interpretation
  - NO CVE correlation
  - NO AI inference

Architecture: Registry Pattern
-------------------------------
Each supported tool type registers a BaseExtractor subclass at module load.
Adding a new tool requires one new BaseExtractor subclass + one register()
call. Zero changes to extract_targets() or the registry machinery are needed.

Extraction strategy: Deterministic Regex Dispatch
--------------------------------------------------
Unlike the classifier (which scores all detectors to find the best match),
extraction dispatches to exactly one registered extractor based on ToolType.
Within NmapExtractor, a secondary dispatch on NmapSubtype selects the
correct regex set (TEXT / XML / GREPABLE) to avoid cross-format noise.

Target normalization:
---------------------
All extracted targets are normalized to a canonical lowercase string before
being returned. Normalization strips protocols, paths, ports, and brackets
so that "HTTPS://Example.COM/path", "example.com:443", and "example.com"
all resolve to the same session target: "example.com".

Phase 2C-2 changes (this version):
-----------------------------------
  [R1] ExtractedTarget gains an optional `related` field — a lightweight
       string reference to a logically associated target value (e.g. the IP
       that appeared alongside a hostname in the same scan report line).
       This is metadata only: no graph, no correlation system. The field
       is None for all non-Nmap extractors and for targets with no peer.

  [R2] NmapExtractor TEXT refinement: "Nmap scan report for hostname (IP)"
       correctly extracts both the hostname and the IP, and each carries a
       `related` pointer to the other. "Nmap scan report for IP" (no parens)
       extracts the IP only with related=None.

  [R3] NmapExtractor XML refinement: <address> elements with
       addrtype="mac" are now explicitly filtered out. Only ipv4 and ipv6
       address types are extracted. <hostname> elements are still extracted
       as before. Each IP and its co-present hostname within the same <host>
       block carry mutual `related` pointers.

  [R4] NmapExtractor GREPABLE refinement: "Host: IP ()" with an empty
       hostname in the parentheses no longer produces an empty/invalid
       ExtractedTarget. The hostname candidate is skipped when empty after
       stripping; only the IP is extracted in that case.

Session tracking:
-----------------
This module returns list[ExtractedTarget]. The caller (core/ingest.py)
is responsible for merging normalized values into session.targets and
deduplicating at the session level. This module only deduplicates within
a single file extraction result.

Phase 3+ integration note:
  ExtractedTarget.target_type, .source_tool, and .related are already
  present for future parser dispatch and correlation. The models/target.py
  dataclass introduced in Phase 3 will supersede ExtractedTarget for
  session-level persistence. The `related` field maps cleanly onto a
  future HostPair or TargetRelationship model without structural change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from intelligence.file_classifier import NmapSubtype, ToolType
from utils.logger import get_logger

log = get_logger(__name__)

# Bytes read for extraction — larger than the classifier sample (8 KB) because
# large scan files (e.g. multi-host Nmap runs) may have targets spread throughout.
EXTRACTION_BYTES: int = 524_288  # 512 KB


# ---------------------------------------------------------------------------
# TargetType enum
# ---------------------------------------------------------------------------

class TargetType(str, Enum):
    """
    Canonical type identifiers for extracted targets.

    Inherits from str for JSON-serialization consistency with ToolType.

    HOSTNAME covers both bare hostnames and FQDNs — the distinction
    between a single-label hostname and a multi-label FQDN is meaningful
    at the correlation layer (Phase 3+), not at the extraction layer.

    CIDR is reserved for Phase 2C-2+ — CIDR ranges are not yet extracted.
    """
    IPV4     = "IPV4"
    IPV6     = "IPV6"
    HOSTNAME = "HOSTNAME"   # bare hostnames and FQDNs
    CIDR     = "CIDR"       # reserved — not extracted in Phase 2C-1
    UNKNOWN  = "UNKNOWN"    # valid string but could not be classified


# ---------------------------------------------------------------------------
# ExtractedTarget dataclass
# ---------------------------------------------------------------------------

@dataclass
class ExtractedTarget:
    """
    A single extracted, normalized target from a scan output file.

    value       : str              — normalized canonical string (e.g. "example.com")
    raw         : str              — original string as found in the file
    target_type : TargetType       — classified type of the normalized value
    source_tool : str              — ToolType.value of the producing tool
    related     : Optional[str]    — [Phase 2C-2] normalized value of a logically
                                     associated target on the same scan line.
                                     Example: hostname's related = its IP, and
                                     vice versa, when both appear as
                                     "Nmap scan report for host (IP)".
                                     None when no peer relationship exists.

    The `related` field is lightweight metadata only. It carries no graph
    semantics and imposes no correlation logic on callers. Callers may
    inspect it, ignore it, or forward it to Phase 3+ models.

    This is an internal processing record. Future phases (Phase 3+) will
    persist targets via models/target.py which extends this concept.
    """
    value:       str
    raw:         str
    target_type: TargetType
    source_tool: str
    related:     Optional[str] = field(default=None)


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
)
_IPV6_RE = re.compile(
    r'^[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}$'
)
_HOSTNAME_RE = re.compile(
    r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$',
    re.IGNORECASE,
)
_CIDR_RE = re.compile(
    r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
)


def _classify_type(value: str) -> TargetType:
    """
    Classify a normalized target string into a TargetType.

    Called after normalize_target() so value is already lowercase with
    no surrounding whitespace, no protocol, no port, and no brackets.
    """
    if _CIDR_RE.match(value):
        return TargetType.CIDR

    m = _IPV4_RE.match(value)
    if m:
        # Validate all four octets are in [0, 255]
        if all(0 <= int(m.group(i)) <= 255 for i in range(1, 5)):
            return TargetType.IPV4

    # IPv6: at least two colons (minimum valid compressed form is "::")
    if value.count(':') >= 2 and _IPV6_RE.match(value):
        return TargetType.IPV6

    if _HOSTNAME_RE.match(value):
        return TargetType.HOSTNAME

    return TargetType.UNKNOWN


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_target(raw: str) -> Optional[str]:
    """
    Normalize a raw target string to a canonical lowercase form.

    Transformations applied in order:
      1. Strip surrounding whitespace
      2. Strip URL protocol and path using urlparse (covers http/https/ftp)
      3. Strip IPv6 brackets: [::1] → ::1, [::1]:port → ::1
      4. Strip port suffix from host:port (only when port is all-digits
         and there is exactly one colon — avoids mangling IPv6 addresses)
      5. Lowercase + strip trailing dots/whitespace
      6. Reject results that are empty, single-character, or pure digits

    Examples:
      "HTTPS://Example.COM/path?q=1"  → "example.com"
      "10.0.0.1:443"                  → "10.0.0.1"
      "www.Example.com."              → "www.example.com"
      "[::1]:8080"                    → "::1"
      "cms.aptech-worldwide.com"      → "cms.aptech-worldwide.com"

    Returns None for empty, unresolvable, or clearly invalid strings.
    """
    if not raw:
        return None

    value = raw.strip()

    # ── 1. Strip URL protocol and path ──────────────────────────────────────
    if '://' in value:
        try:
            parsed = urlparse(value)
            # urlparse.hostname strips port, brackets, and lowercases
            host = parsed.hostname
            if host:
                # Return early — urlparse has already handled lowercasing
                # and port stripping. Only strip trailing dots.
                return host.rstrip('.') or None
        except Exception:
            # Fallback: manual strip
            value = value.split('://', 1)[1]
            value = value.split('/')[0].split('?')[0].split('#')[0]

    # ── 2. Strip IPv6 brackets ────────────────────────────────────────────
    # Handles [::1] and [::1]:port
    if value.startswith('['):
        close = value.find(']')
        if close != -1:
            value = value[1:close]   # strips brackets; port after ] is discarded
        # If no closing bracket, fall through — invalid but we try anyway

    # ── 3. Strip host:port (only for single-colon strings) ────────────────
    # Excludes IPv6 addresses (which have 2+ colons)
    if ':' in value and value.count(':') == 1:
        host_part, port_part = value.rsplit(':', 1)
        if port_part.isdigit():
            value = host_part

    # ── 4. Lowercase + strip trailing dots ────────────────────────────────
    value = value.lower().strip().rstrip('.')

    # ── 5. Reject clearly invalid results ─────────────────────────────────
    if not value or len(value) < 2:
        return None

    # Pure digit strings are not valid hostnames or IPs (octets need dots)
    if value.isdigit():
        return None

    return value


# ---------------------------------------------------------------------------
# Base extractor
# ---------------------------------------------------------------------------

class BaseExtractor:
    """
    Abstract base class for tool-specific target extractors.

    Subclasses override extract() with tool-specific regex logic.
    The base class provides three shared helpers:
      _make_target()       — normalize + classify a single raw string
      _make_pair()         — normalize + classify two related raw strings
      _dedup()             — remove duplicate normalized values within one result set

    To add support for a new tool:
      1. Subclass BaseExtractor
      2. Set tool_type
      3. Implement extract()
      4. Call register(YourExtractor()) at module level

    No changes to extract_targets() or the registry are needed.
    """

    #: ToolType this extractor handles. Must be set by subclasses.
    tool_type: ToolType = ToolType.UNKNOWN

    def extract(
        self,
        content: str,
        nmap_subtype: Optional[NmapSubtype] = None,
    ) -> list[ExtractedTarget]:
        """
        Extract targets from file content string.

        Args:
            content:      Full (or sampled) content of the scan file.
            nmap_subtype: Nmap output format subtype. Forwarded to
                          NmapExtractor only; ignored by all others.

        Returns:
            Deduplicated list of ExtractedTarget instances.
        """
        raise NotImplementedError

    def _make_target(self, raw: str, related: Optional[str] = None) -> Optional[ExtractedTarget]:
        """
        Normalize raw and return an ExtractedTarget, or None if invalid.

        Skips targets whose normalized form cannot be classified into a
        known TargetType — these are likely scan metadata strings that
        accidentally matched a pattern, not genuine target identifiers.

        Args:
            raw:     The original string as found in the scan file.
            related: [Phase 2C-2] Already-normalized value of a logically
                     associated target (e.g. the IP peer of a hostname).
                     Passed through directly to ExtractedTarget.related.
                     Callers are responsible for normalizing this value
                     before passing — use _make_pair() for convenience.
        """
        value = normalize_target(raw)
        if value is None:
            return None
        target_type = _classify_type(value)
        if target_type is TargetType.UNKNOWN:
            log.debug(
                "extractor[%s]: skipped unclassifiable value: %r (raw=%r)",
                self.tool_type.value, value, raw,
            )
            return None
        return ExtractedTarget(
            value=value,
            raw=raw,
            target_type=target_type,
            source_tool=self.tool_type.value,
            related=related,
        )

    def _make_pair(
        self,
        raw_a: str,
        raw_b: str,
    ) -> tuple[Optional[ExtractedTarget], Optional[ExtractedTarget]]:
        """
        [Phase 2C-2] Normalize and classify two raw strings as a related pair.

        Each ExtractedTarget's `related` field points to the other's normalized
        value, providing a lightweight peer reference without any graph machinery.

        If either raw string fails normalization or classification, that slot
        returns None. The other slot is still returned (with related=None if
        its peer was invalid, since there is no valid peer value to reference).

        Typical Nmap TEXT usage:
            "Nmap scan report for cms.example.com (3.108.93.130)"
            → raw_a = "cms.example.com"   (hostname)
            → raw_b = "3.108.93.130"      (IP in parens)
            → hostname.related = "3.108.93.130"
            → ip.related       = "cms.example.com"

        Args:
            raw_a: First raw string (e.g. hostname from scan report line).
            raw_b: Second raw string (e.g. IP from same scan report line).

        Returns:
            (ExtractedTarget | None, ExtractedTarget | None)
        """
        val_a = normalize_target(raw_a)
        val_b = normalize_target(raw_b)

        type_a = _classify_type(val_a) if val_a else TargetType.UNKNOWN
        type_b = _classify_type(val_b) if val_b else TargetType.UNKNOWN

        # Discard values that cannot be classified
        valid_a = val_a is not None and type_a is not TargetType.UNKNOWN
        valid_b = val_b is not None and type_b is not TargetType.UNKNOWN

        target_a: Optional[ExtractedTarget] = None
        target_b: Optional[ExtractedTarget] = None

        if valid_a:
            target_a = ExtractedTarget(
                value=val_a,
                raw=raw_a,
                target_type=type_a,
                source_tool=self.tool_type.value,
                related=val_b if valid_b else None,
            )
        else:
            log.debug(
                "extractor[%s]: _make_pair: skipped unclassifiable A: %r",
                self.tool_type.value, raw_a,
            )

        if valid_b:
            target_b = ExtractedTarget(
                value=val_b,
                raw=raw_b,
                target_type=type_b,
                source_tool=self.tool_type.value,
                related=val_a if valid_a else None,
            )
        else:
            log.debug(
                "extractor[%s]: _make_pair: skipped unclassifiable B: %r",
                self.tool_type.value, raw_b,
            )

        return (target_a, target_b)

    def _dedup(self, targets: list[ExtractedTarget]) -> list[ExtractedTarget]:
        """
        Remove duplicates by normalized value. First occurrence wins.

        Handles the case where a single file contains multiple scan blocks
        for the same host (e.g. Nmap running multiple scripts on one target).
        When the same value appears more than once, the first occurrence is
        kept — which is also the first occurrence with a `related` pointer
        if the relationship was seen on that first line.
        """
        seen: set[str] = set()
        result: list[ExtractedTarget] = []
        for t in targets:
            if t.value not in seen:
                seen.add(t.value)
                result.append(t)
        return result

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(tool_type={self.tool_type!r})"


# ---------------------------------------------------------------------------
# Concrete extractors
# ---------------------------------------------------------------------------

class NmapExtractor(BaseExtractor):
    """
    Extracts targets from Nmap scan output.

    Dispatches to format-specific extraction methods based on NmapSubtype.

    Phase 2C-2 refinements:
    -----------------------

    TEXT (-oN):
      "Nmap scan report for hostname (IP)"
        → hostname extracted with related=IP
        → IP extracted with related=hostname
      "Nmap scan report for IP"  (no parentheses)
        → IP extracted with related=None
      Uses _make_pair() so both targets carry mutual peer references.

    XML (-oX):
      <address addr="IP" addrtype="ipv4"/>   → extracted
      <address addr="IP" addrtype="ipv6"/>   → extracted
      <address addr="XX:XX" addrtype="mac"/> → FILTERED OUT (Phase 2C-2)
      <hostname name="hostname" type="user"/> → extracted
      Within each <host> block, IPs and hostnames carry mutual `related`
      pointers when both are present.

    GREPABLE (-oG):
      "Host: IP (hostname)"   → both extracted with mutual related pointers
      "Host: IP ()"           → IP extracted only; empty hostname NOT extracted
                                avoids creating invalid/empty ExtractedTarget
                                artifacts from scans with no rDNS resolution.
    """
    tool_type = ToolType.NMAP

    # TEXT: "Nmap scan report for hostname (IP)" or "Nmap scan report for IP"
    # Groups: (1) hostname or bare IP,  (2) IP in parens (optional)
    _TEXT_REPORT_RE = re.compile(
        r"Nmap scan report for\s+(\S+?)(?:\s+\(([^)]+)\))?$",
        re.MULTILINE | re.IGNORECASE,
    )

    # GREPABLE: "Host: IP (hostname)" — hostname may be empty parens
    # Groups: (1) IP,  (2) hostname (may be empty string)
    _GREP_HOST_RE = re.compile(
        r"^Host:\s+(\S+)\s+\(([^)]*)\)",
        re.MULTILINE | re.IGNORECASE,
    )

    # XML: <address addr="..." addrtype="ipv4|ipv6">
    # [Phase 2C-2] Explicit addrtype filter — only ipv4 and ipv6 are extracted.
    # addrtype="mac" is excluded: MAC addresses are not valid scan targets and
    # would fail _classify_type() anyway, but filtering them here avoids
    # unnecessary normalize_target() calls and spurious debug log entries.
    _XML_ADDR_RE = re.compile(
        r'<address\s+addr="([^"]+)"\s+addrtype="(ipv4|ipv6)"',
        re.IGNORECASE,
    )

    # XML: <hostname name="..."> — user-supplied or PTR-resolved hostnames.
    # The `type` attribute ("user" or "PTR") is not used for filtering here;
    # both are valid target identifiers. Callers can inspect raw for the type
    # if needed at Phase 3+.
    _XML_HOST_RE = re.compile(
        r'<hostname\s+name="([^"]+)"',
        re.IGNORECASE,
    )

    # XML: <host> block boundary — used to scope IP↔hostname pairing within
    # a single host block rather than across the entire document.
    _XML_HOST_BLOCK_RE = re.compile(
        r'<host\b[^>]*>(.*?)</host>',
        re.IGNORECASE | re.DOTALL,
    )

    def extract(
        self,
        content: str,
        nmap_subtype: Optional[NmapSubtype] = None,
    ) -> list[ExtractedTarget]:
        if nmap_subtype is NmapSubtype.XML:
            return self._extract_xml(content)
        elif nmap_subtype is NmapSubtype.GREPABLE:
            return self._extract_grepable(content)
        else:
            # TEXT format — default for UNKNOWN subtype as well
            return self._extract_text(content)

    # ── Format-specific extraction methods ──────────────────────────────────

    def _extract_text(self, content: str) -> list[ExtractedTarget]:
        """
        Extract targets from Nmap plain-text (-oN) output.

        [Phase 2C-2] Handles both one-token and two-token scan report lines:

          "Nmap scan report for scanme.nmap.org (45.33.32.156)"
            → hostname "scanme.nmap.org" with related="45.33.32.156"
            → IP "45.33.32.156" with related="scanme.nmap.org"

          "Nmap scan report for 45.33.32.156"
            → IP "45.33.32.156" with related=None

        When the scan report line has parentheses (group 2 present), both
        tokens are passed to _make_pair() for mutual relationship tagging.
        When there are no parentheses (bare IP or hostname only), the single
        token is passed to _make_target() with related=None.
        """
        targets: list[ExtractedTarget] = []

        for m in self._TEXT_REPORT_RE.finditer(content):
            token_a = m.group(1)   # hostname or bare IP
            token_b = m.group(2)   # IP in parens — None if not present

            if token_b:
                # Two-token line: e.g. "cms.example.com (3.108.93.130)"
                t_a, t_b = self._make_pair(token_a, token_b)
                if t_a is not None:
                    targets.append(t_a)
                if t_b is not None:
                    targets.append(t_b)
            else:
                # Single-token line: bare IP or hostname with no peer
                t = self._make_target(token_a, related=None)
                if t is not None:
                    targets.append(t)

        return self._dedup(targets)

    def _extract_xml(self, content: str) -> list[ExtractedTarget]:
        """
        Extract targets from Nmap XML (-oX) output.

        [Phase 2C-2] Changes:
          - <address> elements filtered to addrtype="ipv4" and addrtype="ipv6"
            only. addrtype="mac" is now explicitly excluded by the regex.
          - Extraction is scoped per <host> block so that IPs and hostnames
            from the same host carry mutual `related` pointers.
          - When a host block has exactly one IP and exactly one hostname,
            both carry the other's normalized value in their `related` field.
          - When a host block has multiple IPs or multiple hostnames (unusual
            but possible in dual-stack or aliased hosts), related is set to
            the first peer found. This is lightweight heuristic behaviour —
            full multi-IP relationship tracking belongs at Phase 3+.

        Falls back to flat document scan if no <host> blocks are found
        (e.g. truncated or non-standard XML), producing targets with
        related=None in that case.
        """
        targets: list[ExtractedTarget] = []

        host_blocks = self._XML_HOST_BLOCK_RE.findall(content)

        if host_blocks:
            # Scoped extraction: one <host> block at a time
            for block in host_blocks:
                block_targets = self._extract_xml_block(block)
                targets.extend(block_targets)
        else:
            # Fallback: flat document scan without relationship pairing
            log.debug(
                "NmapExtractor XML: no <host> blocks found — "
                "falling back to flat document scan (related=None)"
            )
            for m in self._XML_ADDR_RE.finditer(content):
                t = self._make_target(m.group(1), related=None)
                if t is not None:
                    targets.append(t)
            for m in self._XML_HOST_RE.finditer(content):
                t = self._make_target(m.group(1), related=None)
                if t is not None:
                    targets.append(t)

        return self._dedup(targets)

    def _extract_xml_block(self, block: str) -> list[ExtractedTarget]:
        """
        Extract and pair targets from a single XML <host>...</host> block.

        Finds all valid IP addresses (ipv4/ipv6 only) and all hostnames
        within the block, then builds mutual `related` pointers between
        the first IP and the first hostname when both are present.

        Remaining IPs and hostnames beyond the first pair are extracted
        with related=None — tracking N-to-M relationships is a Phase 3+
        concern (models/target.py HostPair).
        """
        ip_raws:       list[str] = [m.group(1) for m in self._XML_ADDR_RE.finditer(block)]
        hostname_raws: list[str] = [m.group(1) for m in self._XML_HOST_RE.finditer(block)]

        # Normalize all found values so we can use them as related pointers
        ip_norms       = [normalize_target(r) for r in ip_raws]
        hostname_norms = [normalize_target(r) for r in hostname_raws]

        # Filter out values that fail normalization
        valid_ips       = [(r, n) for r, n in zip(ip_raws, ip_norms) if n is not None]
        valid_hostnames = [(r, n) for r, n in zip(hostname_raws, hostname_norms) if n is not None]

        targets: list[ExtractedTarget] = []

        # Determine the primary peer for each group (first of the opposite group)
        first_hostname_norm = valid_hostnames[0][1] if valid_hostnames else None
        first_ip_norm       = valid_ips[0][1]       if valid_ips       else None

        for idx, (raw, norm) in enumerate(valid_ips):
            ttype = _classify_type(norm)
            if ttype is TargetType.UNKNOWN:
                log.debug("NmapExtractor XML: skipped unclassifiable IP: %r", raw)
                continue
            # First IP gets related=first_hostname; subsequent IPs get related=None
            related = first_hostname_norm if idx == 0 else None
            targets.append(ExtractedTarget(
                value=norm,
                raw=raw,
                target_type=ttype,
                source_tool=self.tool_type.value,
                related=related,
            ))

        for idx, (raw, norm) in enumerate(valid_hostnames):
            ttype = _classify_type(norm)
            if ttype is TargetType.UNKNOWN:
                log.debug("NmapExtractor XML: skipped unclassifiable hostname: %r", raw)
                continue
            # First hostname gets related=first_ip; subsequent hostnames get related=None
            related = first_ip_norm if idx == 0 else None
            targets.append(ExtractedTarget(
                value=norm,
                raw=raw,
                target_type=ttype,
                source_tool=self.tool_type.value,
                related=related,
            ))

        return targets

    def _extract_grepable(self, content: str) -> list[ExtractedTarget]:
        """
        Extract targets from Nmap grepable (-oG) output.

        [Phase 2C-2] Refinements:
          - "Host: 45.33.32.156 ()"  — empty parentheses → IP only, no
            hostname artifact. The hostname candidate is checked after
            stripping and skipped when empty.
          - "Host: 45.33.32.156 (scanme.nmap.org)"  — both extracted with
            mutual `related` pointers via _make_pair().

        The hostname group from the regex is always captured (the parens are
        always present in grepable format). Emptiness is checked explicitly
        after stripping whitespace.
        """
        targets: list[ExtractedTarget] = []

        for m in self._GREP_HOST_RE.finditer(content):
            ip_raw       = m.group(1)
            hostname_raw = m.group(2).strip()   # may be empty string

            if hostname_raw:
                # Non-empty hostname present — extract as a related pair
                t_ip, t_host = self._make_pair(ip_raw, hostname_raw)
                if t_ip is not None:
                    targets.append(t_ip)
                if t_host is not None:
                    targets.append(t_host)
            else:
                # [Phase 2C-2] Empty hostname "Host: IP ()" — extract IP only.
                # Avoids creating an empty/unclassifiable ExtractedTarget for
                # hosts that have no rDNS resolution recorded in the scan.
                t = self._make_target(ip_raw, related=None)
                if t is not None:
                    targets.append(t)

        return self._dedup(targets)


class HttpxExtractor(BaseExtractor):
    """
    Extracts targets from Httpx scan output (JSON or plain text).

    JSON format (httpx -json):
      {"url":"https://example.com","status_code":200,...}

    Plain text format (httpx default):
      https://example.com [200] [Page Title]
      [200] https://example.com

    No `related` field is populated for Httpx targets — URL-based extraction
    produces single-token identifiers with no peer relationship on the same line.
    """
    tool_type = ToolType.HTTPX

    # JSON format: explicit "url" key — most reliable signal
    _JSON_URL_RE = re.compile(
        r'"url"\s*:\s*"(https?://[^"]+)"',
        re.IGNORECASE,
    )

    # Plain text / any format: extract any http/https URL
    # Stops at whitespace, quotes, or brackets to avoid capturing metadata
    _URL_RE = re.compile(
        r'(https?://[^\s"\'<>\[\]]+)',
        re.IGNORECASE,
    )

    def extract(
        self,
        content: str,
        nmap_subtype: Optional[NmapSubtype] = None,
    ) -> list[ExtractedTarget]:
        candidates: list[str] = []

        # Try JSON extraction first (more structured, fewer false positives)
        json_matches = self._JSON_URL_RE.findall(content)
        if json_matches:
            candidates.extend(json_matches)
        else:
            # Plain text fallback — extract any URL found
            candidates.extend(self._URL_RE.findall(content))

        targets = [
            t for raw in candidates
            if (t := self._make_target(raw)) is not None
        ]
        return self._dedup(targets)


class SslscanExtractor(BaseExtractor):
    """
    Extracts targets from SSLScan output.

    SSLScan format:
      "Testing SSL server hostname on port 443"
      "Testing SSL server 10.0.0.1 on port 443 using SNI name hostname"

    Both the server field and SNI name are extracted. When both are
    present and different (IP tested with SNI hostname), the SNI hostname
    is typically the more meaningful target identifier for the report.
    Both are returned; dedup will collapse identical values.

    No `related` field is populated — the server and SNI name are distinct
    target identifiers but are not on the same token-pair line structure
    that warrants a mutual peer pointer.
    """
    tool_type = ToolType.SSLSCAN

    # Primary server identifier
    _SERVER_RE = re.compile(
        r"Testing SSL server\s+(\S+)\s+on port",
        re.IGNORECASE,
    )

    # SNI name — present when testing an IP with a virtual host name
    _SNI_RE = re.compile(
        r"using SNI name\s+(\S+)",
        re.IGNORECASE,
    )

    def extract(
        self,
        content: str,
        nmap_subtype: Optional[NmapSubtype] = None,
    ) -> list[ExtractedTarget]:
        candidates: list[str] = []

        candidates.extend(m.group(1) for m in self._SERVER_RE.finditer(content))
        candidates.extend(m.group(1) for m in self._SNI_RE.finditer(content))

        targets = [
            t for raw in candidates
            if (t := self._make_target(raw)) is not None
        ]
        return self._dedup(targets)


class SubfinderExtractor(BaseExtractor):
    """
    Extracts targets from Subfinder subdomain enumeration output.

    JSON format (subfinder -json):
      {"host":"sub.domain.com","source":"...","input":"domain.com"}

    Plain text format (subfinder default):
      sub.domain.com        (one subdomain per line)

    The plain-text FQDN pattern is intentionally conservative to avoid
    false positives from log lines or prose text in edge-case outputs.
    It requires at least one dot and a valid TLD-like suffix.

    No `related` field is populated — subdomain list outputs are single-column
    with no peer relationship structure.
    """
    tool_type = ToolType.SUBFINDER

    # JSON format: "host" key
    _JSON_HOST_RE = re.compile(
        r'"host"\s*:\s*"([^"]+)"',
        re.IGNORECASE,
    )

    # Plain text: one FQDN per line
    # Requires: starts with alphanumeric, contains at least one dot,
    # ends with 2+ alpha characters (TLD), no whitespace
    _FQDN_LINE_RE = re.compile(
        r'^([a-z0-9][a-z0-9\-\.]*\.[a-z]{2,})$',
        re.IGNORECASE | re.MULTILINE,
    )

    def extract(
        self,
        content: str,
        nmap_subtype: Optional[NmapSubtype] = None,
    ) -> list[ExtractedTarget]:
        candidates: list[str] = []

        json_matches = self._JSON_HOST_RE.findall(content)
        if json_matches:
            candidates.extend(json_matches)
        else:
            candidates.extend(self._FQDN_LINE_RE.findall(content))

        targets = [
            t for raw in candidates
            if (t := self._make_target(raw)) is not None
        ]
        return self._dedup(targets)


# ---------------------------------------------------------------------------
# Extractor registry
# ---------------------------------------------------------------------------

# Keyed by ToolType — O(1) dispatch. Unlike the classifier registry (list
# scored in order), extraction dispatch is deterministic: one tool → one
# extractor. No ordering dependency.
_registry: dict[ToolType, BaseExtractor] = {}


def register(extractor: BaseExtractor) -> BaseExtractor:
    """
    Register an extractor for its declared tool_type.

    Usage:
        register(NmapExtractor())

    Returns the extractor (allows inline usage if needed).
    Re-registering the same ToolType overwrites the previous entry.
    """
    _registry[extractor.tool_type] = extractor
    log.debug("Extractor registered: %s", extractor)
    return extractor


# Register all concrete extractors at module load time.
register(NmapExtractor())
register(HttpxExtractor())
register(SslscanExtractor())
register(SubfinderExtractor())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_targets(
    file_path: Path,
    tool_type: ToolType,
    nmap_subtype: Optional[NmapSubtype] = None,
) -> list[ExtractedTarget]:
    """
    Extract and normalize assessed targets from a classified scan file.

    Dispatches to the registered extractor for tool_type, reads the file
    content, and returns a deduplicated list of normalized ExtractedTarget
    instances.

    Returns an empty list (never raises) if:
      - tool_type is UNKNOWN
      - No extractor is registered for tool_type
      - The file cannot be read (logged at WARNING)
      - The file is empty
      - No valid targets are found after normalization

    Args:
        file_path:    Path to the classified scan file (in processed/).
        tool_type:    ToolType identified by file_classifier.
        nmap_subtype: Nmap output format (TEXT/XML/GREPABLE/UNKNOWN).
                      Pass None (default) for non-Nmap tools.

    Returns:
        list[ExtractedTarget]: Deduplicated, normalized target records.

    Example:
        >>> targets = extract_targets(Path("processed/nmap_scan.txt"),
        ...                           ToolType.NMAP, NmapSubtype.TEXT)
        >>> [(t.value, t.related) for t in targets]
        [('cms.aptech-worldwide.com', '3.108.93.130'),
         ('3.108.93.130', 'cms.aptech-worldwide.com')]
    """
    if tool_type is ToolType.UNKNOWN:
        log.debug(
            "extract_targets: skipping UNKNOWN tool type for %s",
            file_path.name,
        )
        return []

    extractor = _registry.get(tool_type)
    if extractor is None:
        log.debug(
            "extract_targets: no extractor registered for %s — skipping %s",
            tool_type.value, file_path.name,
        )
        return []

    content = _read_content(file_path)
    if content is None:
        log.warning(
            "extract_targets: could not read file: %s", file_path
        )
        return []

    if not content.strip():
        log.debug("extract_targets: empty file: %s", file_path.name)
        return []

    targets = extractor.extract(content, nmap_subtype=nmap_subtype)

    subtype_label = f"/{nmap_subtype.value}" if nmap_subtype else ""
    log.info(
        "extract_targets: [%s%s] %d target(s) from %s",
        tool_type.value, subtype_label, len(targets), file_path.name,
    )
    for t in targets:
        related_label = f" → related={t.related!r}" if t.related is not None else ""
        log.debug(
            "  ↳ %s (%s)%s ← raw=%r",
            t.value, t.target_type.value, related_label, t.raw,
        )

    return targets


def list_registered_extractors() -> list[str]:
    """Return registered extractor tool types (for diagnostics/logging)."""
    return [tool_type.value for tool_type in _registry]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_content(file_path: Path) -> Optional[str]:
    """
    Read file content up to EXTRACTION_BYTES.

    Tries UTF-8 first (all major scan tools emit ASCII/UTF-8).
    Falls back to latin-1 (byte-transparent — never raises UnicodeDecodeError)
    to handle files with non-ASCII hostnames or banners.

    Returns None only on OSError (file missing, permissions, etc.).
    """
    try:
        with file_path.open("rb") as fh:
            raw = fh.read(EXTRACTION_BYTES)
    except OSError as exc:
        log.error("_read_content: OSError reading %s: %s", file_path, exc)
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    # Normalize line endings (CRLF/CR -> LF) so CRLF scan files extract the
    # same targets as LF files. Line-oriented extractor regexes assume LF.
    return text.replace("\r\n", "\n").replace("\r", "\n")
