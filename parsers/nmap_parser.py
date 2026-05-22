"""
intelligence/parsers/nmap_parser.py
=====================================
Nmap scan output parser for IntelliAssess AI — Phase 3-2.

Responsibility: parse Nmap scan output (TEXT / XML / GREPABLE) into structured
ParsedScanData. Deterministic extraction only — no AI, no CVE lookup, no
severity engine, no compliance logic.

Supported subtypes:
  TEXT     (-oN) — PRIMARY. Full parsing: hosts, ports, services,
                   versions, OS inference, lightweight findings.
  XML      (-oX) — LIGHTWEIGHT. Regex-based host/port/service extraction.
  GREPABLE (-oG) — LIGHTWEIGHT. Host:/Ports: line extraction.

Finding types generated (deterministic, port-number driven):
  OPEN_FTP_PORT     — port 21 open
  OPEN_TELNET_PORT  — port 23 open
  OPEN_SSH_PORT     — port 22 open
  OPEN_SMTP_PORT    — port 25 open
  OPEN_SMB_PORT     — port 445 open
  OPEN_RDP_PORT     — port 3389 open
  OPEN_VNC_PORT     — port 5900 open
  HIGH_RISK_PORT    — suspicious/unusual port open
  UNKNOWN_SERVICE   — open port with unrecognized service on non-standard port

Intentionally NOT in this phase:
  - CVE correlation         (Phase 4 — cve_enricher.py)
  - Severity adjustment     (Phase 4 — context_risk_engine.py)
  - AI-generated narrative  (Phase 4 — analyzer.py + LLMClient)
  - Compliance mapping      (Phase 5 — compliance_engine.py)

Integration:
  - Registered at module load via register() from parsers/registry.py
  - Imported in intelligence/parsers/__init__.py (triggers registration)
  - Called from core/ingest.py via parse_file() after extract_targets()

Phase 3-3 note:
  HttpxParser is next. HTTP/HTTPS/SSL ports are intentionally skipped by
  this parser — HttpxParser owns all web-layer findings.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from intelligence.file_classifier import NmapSubtype, ToolType
from parsers.base import BaseParser, ParsedScanData
from parsers.models import ParsedAsset, ParsedFinding, ParsedService
from parsers.registry import register
from utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Port-based finding classification tables
# ---------------------------------------------------------------------------

# Ports with a specific finding type and severity hint.
# (finding_type, severity_hint)
_CLASSIFIED_PORTS: dict[int, tuple[str, str]] = {
    21:   ("OPEN_FTP_PORT",    "HIGH"),
    22:   ("OPEN_SSH_PORT",    "MEDIUM"),
    23:   ("OPEN_TELNET_PORT", "HIGH"),
    25:   ("OPEN_SMTP_PORT",   "MEDIUM"),
    110:  ("OPEN_POP3_PORT",   "MEDIUM"),
    143:  ("OPEN_IMAP_PORT",   "MEDIUM"),
    445:  ("OPEN_SMB_PORT",    "HIGH"),
    3389: ("OPEN_RDP_PORT",    "HIGH"),
    5900: ("OPEN_VNC_PORT",    "HIGH"),
}

# Unusual / suspicious ports — generate HIGH_RISK_PORT finding.
_HIGH_RISK_PORTS: frozenset[int] = frozenset([
    31337, 1337, 4444, 5555, 6666, 7777,
    6667, 6668, 6669,   # IRC
    1080,               # SOCKS proxy
    3128,               # Squid proxy
    9001, 9030,         # Tor
])

# Service names that belong to the HTTP/SSL layer — skip here, let
# HttpxParser (Phase 3-3) own all web findings.
_WEB_SERVICES: frozenset[str] = frozenset([
    "http", "https", "ssl", "ssl/http", "http-alt",
    "https-alt", "http-proxy",
])

# Service names that produce no finding (informational only).
_INFO_ONLY_SERVICES: frozenset[str] = frozenset([
    "tcpwrapped",   # port wrapped — no clean banner
    "unknown",
])


# ---------------------------------------------------------------------------
# Compiled regexes — TEXT format
# ---------------------------------------------------------------------------

# "# Nmap 7.80 scan initiated ..."
_T_HEADER_RE = re.compile(
    r"#\s*Nmap\s+(\S+)\s+scan\s+initiated",
    re.IGNORECASE,
)

# "Nmap scan report for hostname (IP)" or "for IP"
_T_REPORT_RE = re.compile(
    r"^Nmap scan report for\s+(\S+?)(?:\s+\(([^)]+)\))?$",
    re.MULTILINE | re.IGNORECASE,
)

# Port table row: "80/tcp   open   http   nginx 1.24.0 (Ubuntu)"
# Groups: port, proto, state, service, version(optional)
_T_PORT_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(open(?:\|filtered)?|closed|filtered)\s+(\S+)(?:\s+(.+))?$",
    re.MULTILINE | re.IGNORECASE,
)

# "Host is up (0.006s latency)." or "Host is down."
_T_HOST_STATE_RE = re.compile(
    r"Host is (up|down)",
    re.IGNORECASE,
)

# rDNS record: "rDNS record for 3.108.93.130: ec2-3-108-..."
_T_RDNS_RE = re.compile(
    r"rDNS record for\s+[\d\.]+:\s+(\S+)",
    re.IGNORECASE,
)

# OS inference lines — priority order handled in _extract_os_text()
_T_OS_DETAILS_RE = re.compile(
    r"^OS details:\s+(.+)$",
    re.MULTILINE | re.IGNORECASE,
)
_T_RUNNING_RE = re.compile(
    r"^Running(?:\s+\(JUST GUESSING\))?:\s+(.+)$",
    re.MULTILINE | re.IGNORECASE,
)
_T_AGGRESSIVE_OS_RE = re.compile(
    r"Aggressive OS guesses:\s+([^\n]+)",
    re.IGNORECASE,
)

# "Service Info: OS: Linux; CPE: ..."
_T_SERVICE_INFO_RE = re.compile(
    r"^Service Info:\s+(.+)$",
    re.MULTILINE | re.IGNORECASE,
)
_T_SI_OS_RE = re.compile(
    r"OS:\s*([^;,\n]+)",
    re.IGNORECASE,
)

# "Not shown: 8318 filtered ports"
_T_NOT_SHOWN_RE = re.compile(
    r"Not shown:\s+(\d+)\s+(filtered|closed)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Compiled regexes — XML format (lightweight, regex-based, tolerates truncation)
# ---------------------------------------------------------------------------

_X_VERSION_RE    = re.compile(r'<nmaprun\b[^>]*\bversion="([^"]*)"', re.IGNORECASE)
_X_HOST_BLOCK_RE = re.compile(r'<host\b[^>]*>(.*?)</host>', re.IGNORECASE | re.DOTALL)
_X_ADDR_RE       = re.compile(r'<address\s+addr="([^"]+)"\s+addrtype="(ipv4|ipv6)"', re.IGNORECASE)
_X_HOSTNAME_RE   = re.compile(r'<hostname\s+name="([^"]+)"', re.IGNORECASE)
_X_PORT_RE       = re.compile(
    r'<port\s+protocol="(tcp|udp)"\s+portid="(\d+)"[^>]*>'
    r'.*?<state\s+state="([^"]+)"[^/]*/>'
    r'(?:.*?<service\s+name="([^"]*)"'
    r'(?:[^>]*\bproduct="([^"]*)")?'
    r'(?:[^>]*\bversion="([^"]*)")?'
    r'(?:[^>]*\bextrainfo="([^"]*)")?'
    r')?',
    re.IGNORECASE | re.DOTALL,
)
_X_OSMATCH_RE    = re.compile(r'<osmatch\b[^>]*\bname="([^"]*)"[^>]*\bacc="(\d+)"', re.IGNORECASE)
_X_OSCLASS_RE    = re.compile(r'<osclass\b[^>]*\bosfamily="([^"]*)"', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Compiled regexes — GREPABLE format
# ---------------------------------------------------------------------------

_G_VERSION_RE   = re.compile(r'^#\s*Nmap\s+(\S+)\s+scan', re.MULTILINE | re.IGNORECASE)
_G_HOST_RE      = re.compile(r'^Host:\s+(\S+)\s+\(([^)]*)\)', re.MULTILINE | re.IGNORECASE)
_G_PORTS_RE     = re.compile(r'\bPorts:\s+([^\t\n]+)', re.IGNORECASE)
# Each port entry in grepable: "80/open/tcp//http//nginx 1.24.0/"
_G_PORT_ENTRY_RE = re.compile(
    r'(\d+)/(open|closed|filtered)/(tcp|udp)//([^/]*)//([^/,]*)',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# NmapParser
# ---------------------------------------------------------------------------

class NmapParser(BaseParser):
    """
    Parser for Nmap scan output in TEXT, XML, and GREPABLE formats.

    TEXT (-oN) is the primary and highest-quality parsing path.
    XML  (-oX) and GREPABLE (-oG) are lightweight secondary paths.

    All three paths produce ParsedScanData with the same field contract.
    TEXT produces the richest output: version strings, OS inference,
    rDNS aliases, and port-based lightweight findings.
    """

    tool_type = ToolType.NMAP

    # =========================================================================
    # Public parse() — dispatch entry point
    # =========================================================================

    def parse(
        self,
        content: str,
        file_path: Path,
        nmap_subtype: Optional[NmapSubtype] = None,
    ) -> ParsedScanData:
        """
        Dispatch to format-specific parser based on nmap_subtype.

        Falls back to TEXT parser when subtype is UNKNOWN — TEXT has the
        broadest regex coverage and handles most real-world scan outputs.
        """
        result = self._empty_result(nmap_subtype=nmap_subtype)

        try:
            if nmap_subtype is NmapSubtype.XML:
                self._parse_xml(content, file_path, result)
            elif nmap_subtype is NmapSubtype.GREPABLE:
                self._parse_grepable(content, file_path, result)
            else:
                # TEXT or UNKNOWN — TEXT parser handles both
                self._parse_text(content, file_path, result)
        except Exception as exc:
            self._add_error(result, f"unexpected exception during parse: {exc!r}")
            log.error(
                "NmapParser: unexpected exception parsing %s: %s",
                file_path.name, exc,
                exc_info=True,
            )

        log.debug("NmapParser: %s", result.summary())
        return result

    # =========================================================================
    # TEXT parser — primary, highest-quality path
    # =========================================================================

    def _parse_text(
        self,
        content: str,
        file_path: Path,
        result: ParsedScanData,
    ) -> None:
        """
        Parse Nmap plain-text (-oN) output.

        Strategy:
          1. Extract tool version from header comment.
          2. Find all "Nmap scan report for" lines — each marks a host block.
          3. Slice the content into per-host blocks between consecutive report lines.
          4. Parse each host block: report line → hostname/IP, port table,
             OS detection, Service Info, rDNS.
          5. Set primary_target from the first host's report line.
          6. Append ParsedAsset and ParsedFindings to result for each host.
        """
        # ── Tool version ──────────────────────────────────────────────────
        vm = _T_HEADER_RE.search(content)
        if vm:
            result.tool_version = f"Nmap {vm.group(1)}"
            result.scan_metadata["nmap_version"] = vm.group(1)

        # ── Locate all report lines ───────────────────────────────────────
        report_matches = list(_T_REPORT_RE.finditer(content))

        if not report_matches:
            self._add_error(result, "no 'Nmap scan report for' lines found in TEXT output")
            return

        # ── Set primary_target from first host ────────────────────────────
        first = report_matches[0]
        # Prefer hostname over bare IP as the primary target label
        result.primary_target = first.group(1)

        # ── Build per-host block slices ───────────────────────────────────
        for i, m in enumerate(report_matches):
            start = m.start()
            end   = report_matches[i + 1].start() if i + 1 < len(report_matches) else len(content)
            block = content[start:end]

            asset = self._parse_text_host_block(m, block, result)
            if asset is not None:
                result.assets.append(asset)

        result.scan_metadata["total_hosts"] = len(result.assets)

    def _parse_text_host_block(
        self,
        report_m: re.Match,
        block: str,
        result: ParsedScanData,
    ) -> Optional[ParsedAsset]:
        """
        Parse a single host block from TEXT output.

        A block runs from one "Nmap scan report for" line to the next (or EOF).
        Extracts: hostname/IP identity, open ports + services, OS, rDNS aliases.

        Returns ParsedAsset or None if the block cannot be resolved to any target.
        """
        token_a = report_m.group(1)   # hostname or bare IP
        token_b = report_m.group(2)   # IP in parentheses (may be None)

        # Determine which token is the hostname and which is the IP
        if token_b:
            # "report for hostname (IP)"
            hostname   = token_a
            ip_address = token_b
        else:
            # "report for IP" — no hostname resolution recorded
            hostname   = ""
            ip_address = token_a

        # Primary asset identifier: prefer hostname for readability
        asset_value = hostname if hostname else ip_address
        asset_type  = "hostname" if hostname else "ipv4"

        asset = ParsedAsset(
            value=      asset_value,
            asset_type= asset_type,
        )

        # Populate IP / hostname lists (exclude primary value from duplicates)
        if ip_address and ip_address != asset_value:
            asset.ip_addresses = [ip_address]
        if hostname and hostname != asset_value:
            asset.hostnames = [hostname]

        # ── rDNS alias ────────────────────────────────────────────────────
        rdns_m = _T_RDNS_RE.search(block)
        if rdns_m:
            alias = rdns_m.group(1).strip().rstrip(".")
            if alias and alias not in asset.hostnames and alias != asset_value:
                asset.hostnames.append(alias)

        # ── Port table ────────────────────────────────────────────────────
        for pm in _T_PORT_RE.finditer(block):
            port_num  = int(pm.group(1))
            protocol  = pm.group(2).lower()
            state     = pm.group(3).lower()
            svc_name  = pm.group(4).strip()
            ver_raw   = pm.group(5)
            version   = ver_raw.strip() if ver_raw else None

            svc = ParsedService(
                port=         port_num,
                protocol=     protocol,
                state=        state,
                service_name= svc_name,
                version=      version,
                extra_info=   pm.group(0).strip(),   # raw port line as evidence
            )
            asset.services.append(svc)

            # Generate finding for open ports only
            if "open" in state:
                finding = self._make_port_finding(
                    port=         port_num,
                    protocol=     protocol,
                    service_name= svc_name,
                    version=      version,
                    target=       asset_value,
                    raw_evidence= pm.group(0).strip(),
                )
                if finding is not None:
                    result.findings.append(finding)

        # ── OS detection ──────────────────────────────────────────────────
        os_name, os_conf = self._extract_os_text(block)
        if os_name:
            asset.os_name       = os_name
            asset.os_confidence = os_conf

        # ── Service Info OS fallback ──────────────────────────────────────
        # "Service Info: OS: Linux; CPE: ..."
        if not asset.os_name:
            si_m = _T_SERVICE_INFO_RE.search(block)
            if si_m:
                os_m2 = _T_SI_OS_RE.search(si_m.group(1))
                if os_m2:
                    asset.os_name       = os_m2.group(1).strip()
                    asset.os_confidence = "medium"

        # ── Hosting hint — first version string from an open service ─────
        for svc in asset.services:
            if svc.version and "open" in svc.state:
                asset.hosting_hint = svc.version
                break

        # ── Not-shown metadata ────────────────────────────────────────────
        ns_m = _T_NOT_SHOWN_RE.search(block)
        if ns_m:
            asset.scan_metadata["not_shown_count"] = int(ns_m.group(1))
            asset.scan_metadata["not_shown_type"]  = ns_m.group(2).lower()

        return asset

    def _extract_os_text(self, block: str) -> tuple[Optional[str], str]:
        """
        Extract OS name and confidence from a TEXT host block.

        Priority (highest to lowest):
          1. "OS details: ..." — most specific, Nmap confirmed exact match
          2. "Running: ..."    — good signal, may be a guess
          3. "Aggressive OS guesses: ..." — first guess, lowest confidence

        Returns (os_name, confidence_label).
        """
        # 1. "OS details: Microsoft Windows 10"
        od_m = _T_OS_DETAILS_RE.search(block)
        if od_m:
            return od_m.group(1).strip(), "high"

        # 2. "Running (JUST GUESSING): Linux 2.6.X|3.X|4.X (92%)"
        run_m = _T_RUNNING_RE.search(block)
        if run_m:
            # Take up to the first comma, strip trailing percentage
            raw = run_m.group(1).split(",")[0].strip()
            raw = re.sub(r"\s*\(\d+%\)\s*$", "", raw).strip()
            return raw, "medium"

        # 3. "Aggressive OS guesses: Linux 2.6.32 (92%), ..."
        agg_m = _T_AGGRESSIVE_OS_RE.search(block)
        if agg_m:
            first_guess = agg_m.group(1).split(",")[0].strip()
            first_guess = re.sub(r"\s*\(\d+%\)\s*$", "", first_guess).strip()
            if first_guess:
                return first_guess, "low"

        return None, "unknown"

    # =========================================================================
    # XML parser — lightweight, regex-based
    # =========================================================================

    def _parse_xml(
        self,
        content: str,
        file_path: Path,
        result: ParsedScanData,
    ) -> None:
        """
        Parse Nmap XML (-oX) output using regex.

        regex-based (not xml.etree.ElementTree) intentionally: large or
        truncated XML files from long scans are common. ElementTree raises
        on any parse error; regex tolerates partial content gracefully.

        Extracts per <host> block: IPs, hostnames, open ports, services,
        OS match. Generates port-based findings matching TEXT parser output.
        """
        # Tool version from <nmaprun version="...">
        vx_m = _X_VERSION_RE.search(content)
        if vx_m:
            result.tool_version = f"Nmap {vx_m.group(1)}"

        host_blocks = _X_HOST_BLOCK_RE.findall(content)

        if not host_blocks:
            self._add_error(result, "no <host> blocks found in XML output")
            return

        first = True
        for block in host_blocks:
            asset = self._parse_xml_host_block(block, result)
            if asset is None:
                continue
            if first:
                result.primary_target = asset.value
                first = False
            result.assets.append(asset)

    def _parse_xml_host_block(
        self,
        block: str,
        result: ParsedScanData,
    ) -> Optional[ParsedAsset]:
        """Parse one <host>...</host> XML block into a ParsedAsset."""
        ip_matches  = _X_ADDR_RE.findall(block)    # [(addr, addrtype), ...]
        host_names  = _X_HOSTNAME_RE.findall(block) # [name, ...]

        ips       = [m[0] for m in ip_matches]
        hostnames = list(host_names)

        asset_value = hostnames[0] if hostnames else (ips[0] if ips else None)
        if not asset_value:
            return None

        asset = ParsedAsset(
            value=       asset_value,
            asset_type=  "hostname" if hostnames else "ipv4",
            ip_addresses= ips,
            hostnames=    hostnames,
        )

        # ── Ports ─────────────────────────────────────────────────────────
        for pm in _X_PORT_RE.finditer(block):
            protocol  = pm.group(1).lower()
            port_num  = int(pm.group(2))
            state     = pm.group(3).lower()
            svc_name  = (pm.group(4) or "").strip()
            product   = (pm.group(5) or "").strip()
            version   = (pm.group(6) or "").strip()
            extrainfo = (pm.group(7) or "").strip()

            # Build a readable version string from available fields
            ver_parts = [p for p in (product, version, extrainfo) if p]
            ver_str   = " ".join(ver_parts) or None

            svc = ParsedService(
                port=         port_num,
                protocol=     protocol,
                state=        state,
                service_name= svc_name,
                version=      ver_str,
            )
            asset.services.append(svc)

            if "open" in state:
                finding = self._make_port_finding(
                    port=         port_num,
                    protocol=     protocol,
                    service_name= svc_name,
                    version=      ver_str,
                    target=       asset_value,
                    raw_evidence= f"port {port_num}/{protocol} {state} {svc_name}",
                )
                if finding:
                    result.findings.append(finding)

        # ── OS — prefer highest-accuracy osmatch, fall back to osclass ────
        best_os, best_acc = None, -1
        for om in _X_OSMATCH_RE.finditer(block):
            acc = int(om.group(2))
            if acc > best_acc:
                best_acc = acc
                best_os  = om.group(1).strip()

        if best_os:
            asset.os_name       = best_os
            asset.os_confidence = "high" if best_acc >= 90 else "medium"
        else:
            osc_m = _X_OSCLASS_RE.search(block)
            if osc_m:
                asset.os_name       = osc_m.group(1).strip()
                asset.os_confidence = "low"

        # ── Hosting hint from first open service version ──────────────────
        for svc in asset.services:
            if svc.version and "open" in svc.state:
                asset.hosting_hint = svc.version
                break

        return asset

    # =========================================================================
    # GREPABLE parser — lightweight
    # =========================================================================

    def _parse_grepable(
        self,
        content: str,
        file_path: Path,
        result: ParsedScanData,
    ) -> None:
        """
        Parse Nmap grepable (-oG) output.

        Each host appears on a "Host: IP (hostname)" line.
        The "Ports:" field on the same line lists port entries in the format:
          80/open/tcp//http//nginx 1.24.0/
        """
        vg_m = _G_VERSION_RE.search(content)
        if vg_m:
            result.tool_version = f"Nmap {vg_m.group(1)}"

        lines = content.splitlines()
        first = True

        for line in lines:
            host_m = _G_HOST_RE.match(line.strip())
            if not host_m:
                continue

            ip_raw       = host_m.group(1).strip()
            hostname_raw = host_m.group(2).strip()

            asset_value = hostname_raw if hostname_raw else ip_raw
            if not asset_value:
                continue

            asset = ParsedAsset(
                value=       asset_value,
                asset_type=  "hostname" if hostname_raw else "ipv4",
                ip_addresses= [ip_raw] if ip_raw else [],
                hostnames=    [hostname_raw] if hostname_raw else [],
            )

            if first:
                result.primary_target = asset_value
                first = False

            # Extract port entries from "Ports:" field on same line
            ports_m = _G_PORTS_RE.search(line)
            if ports_m:
                for pe_m in _G_PORT_ENTRY_RE.finditer(ports_m.group(1)):
                    port_num  = int(pe_m.group(1))
                    state     = pe_m.group(2).lower()
                    protocol  = pe_m.group(3).lower()
                    svc_name  = pe_m.group(4).strip()
                    version   = pe_m.group(5).strip() or None

                    svc = ParsedService(
                        port=         port_num,
                        protocol=     protocol,
                        state=        state,
                        service_name= svc_name,
                        version=      version,
                    )
                    asset.services.append(svc)

                    if "open" in state:
                        finding = self._make_port_finding(
                            port=         port_num,
                            protocol=     protocol,
                            service_name= svc_name,
                            version=      version,
                            target=       asset_value,
                            raw_evidence= pe_m.group(0),
                        )
                        if finding:
                            result.findings.append(finding)

            result.assets.append(asset)

        if not result.assets:
            self._add_error(result, "no 'Host:' lines found in GREPABLE output")

    # =========================================================================
    # Finding generation — deterministic, port-number driven
    # =========================================================================

    def _make_port_finding(
        self,
        port: int,
        protocol: str,
        service_name: str,
        version: Optional[str],
        target: str,
        raw_evidence: str,
    ) -> Optional[ParsedFinding]:
        """
        Generate a ParsedFinding for a single open port.

        Decision tree (evaluated in order, first match wins):
          1. Port in _CLASSIFIED_PORTS → named finding type + assigned severity
          2. Port in _HIGH_RISK_PORTS  → HIGH_RISK_PORT / LOW
          3. Service is web (http/https/ssl) → None (HttpxParser owns these)
          4. Service is info-only (tcpwrapped) → None
          5. Unrecognized service on unusual port → UNKNOWN_SERVICE / INFO
          6. Otherwise (standard service, not classified) → None

        Returns ParsedFinding or None if no finding is warranted for this port.
        """
        svc_lower = service_name.lower().strip()

        # 1. Explicitly classified ports (FTP, SSH, Telnet, SMB, etc.)
        if port in _CLASSIFIED_PORTS:
            finding_type, severity = _CLASSIFIED_PORTS[port]
            detail = f"Port {port}/{protocol} open — service: {service_name}"
            if version:
                detail += f" ({version})"
            return ParsedFinding(
                finding_type=  finding_type,
                target=        target,
                port=          port,
                protocol=      protocol,
                service=       service_name,
                detail=        detail,
                severity_hint= severity,
                raw_evidence=  raw_evidence,
                source_tool=   self.tool_type.value,
            )

        # 2. High-risk / suspicious ports
        if port in _HIGH_RISK_PORTS:
            return ParsedFinding(
                finding_type=  "HIGH_RISK_PORT",
                target=        target,
                port=          port,
                protocol=      protocol,
                service=       service_name or "unknown",
                detail=        (
                    f"Unusual high-risk port {port}/{protocol} open — "
                    f"service: {service_name or 'unknown'}"
                ),
                severity_hint= "LOW",
                raw_evidence=  raw_evidence,
                source_tool=   self.tool_type.value,
            )

        # 3. Web services — HttpxParser owns these findings
        if svc_lower in _WEB_SERVICES:
            return None

        # 4. Info-only services — no finding value
        if svc_lower in _INFO_ONLY_SERVICES:
            return None

        # 5. Unrecognized service on a non-standard high port
        if (not svc_lower or svc_lower == "unknown") and port > 1024:
            return ParsedFinding(
                finding_type=  "UNKNOWN_SERVICE",
                target=        target,
                port=          port,
                protocol=      protocol,
                service=       service_name or "unknown",
                detail=        f"Unrecognized service on port {port}/{protocol}",
                severity_hint= "INFO",
                raw_evidence=  raw_evidence,
                source_tool=   self.tool_type.value,
            )

        # 6. Known but unremarkable service — informational only
        return None


# ---------------------------------------------------------------------------
# Registration — runs at module import time
# Mirrors the pattern used by classifiers and extractors.
# ---------------------------------------------------------------------------

register(NmapParser())
log.debug("NmapParser registered for ToolType.NMAP")
