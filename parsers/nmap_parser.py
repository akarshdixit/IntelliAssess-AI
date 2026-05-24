"""
intelligence/parsers/nmap_parser.py
=====================================
Nmap scan output parser for IntelliAssess AI.

Responsibility: parse Nmap scan output (TEXT / XML / GREPABLE) into structured
ParsedScanData, and generate deterministic security findings from the extracted
infrastructure data via the centralized finding catalog.

Extraction (unchanged): hosts, ports, services, versions, OS inference, rDNS.
Finding generation (Phase A-1): delegated to intelligence/finding_catalog.py so
that every finding shares the platform-wide standardized schema (finding_id,
title, severity, evidence, technical description, remediation, compliance refs,
confidence). This parser no longer hand-rolls finding objects or invents
finding_type strings — it observes evidence and asks the catalog to build the
finding. That keeps a future migration to intelligence/findings_engine.py
mechanical.

Supported subtypes:
  TEXT     (-oN) — PRIMARY. Full parsing: hosts, ports, services,
                   versions, OS inference, findings.
  XML      (-oX) — LIGHTWEIGHT. Regex-based host/port/service extraction.
  GREPABLE (-oG) — LIGHTWEIGHT. Host:/Ports: line extraction.

Finding types generated (deterministic, catalog-driven):
  OPEN_PORT                  — every open port (attack-surface inventory, INFO)
  SERVICE_VERSION_DISCLOSURE — open service leaks a product/version banner
  OUTDATED_SERVICE           — banner matches a known-outdated version pattern
  HTTP_ONLY                  — cleartext HTTP exposed (TLS also present on host)
  HTTPS_MISSING              — HTTP exposed with no TLS service on the host
  TELNET_EXPOSED             — port 23 open
  FTP_EXPOSED                — port 21 open
  SMBV1_ENABLED              — port 445 open with explicit SMBv1 banner indicators
  EOL_OPERATING_SYSTEM       — OS fingerprint matches an end-of-life pattern

Intentionally NOT here:
  - CVE correlation, severity contextualization (risk_adjustment.py at report time),
    AI narrative, deep TLS/header analysis (SSLScan / Httpx parsers own those).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from intelligence.file_classifier import NmapSubtype, ToolType
from intelligence.finding_catalog import (
    build_finding,
    is_eol_os,
    is_outdated_service,
)
from parsers.base import BaseParser, ParsedScanData
from parsers.models import ParsedAsset, ParsedFinding, ParsedService
from parsers.registry import register
from utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Port / service classification tables (drive catalog-based finding selection)
# ---------------------------------------------------------------------------

# Ports that map directly to a specific cleartext/legacy-protocol finding type.
_PORT_FINDING_TYPE: dict[int, str] = {
    21:  "FTP_EXPOSED",
    23:  "TELNET_EXPOSED",
}

# Service labels (and ports) considered HTTP (cleartext web).
_HTTP_SERVICES: frozenset[str] = frozenset(["http", "http-alt", "http-proxy"])
_HTTP_PORTS:    frozenset[int] = frozenset([80, 8080, 8000, 8888])

# Service labels (and ports) considered TLS-wrapped web / TLS present.
_TLS_HINT_SERVICES: frozenset[str] = frozenset([
    "https", "ssl/http", "ssl", "https-alt", "ssl/https",
])
_TLS_PORTS: frozenset[int] = frozenset([443, 8443])

# Services that carry no useful banner — skip version-disclosure findings.
_INFO_ONLY_SERVICES: frozenset[str] = frozenset(["tcpwrapped", "unknown", ""])

# SMB ports — only flag SMBv1 when the banner explicitly indicates v1.
# "cifs" is intentionally NOT a hint: CIFS is a loose dialect label that does
# not reliably imply SMBv1, and a false SMBv1 claim erodes report trust.
_SMB_PORTS: frozenset[int] = frozenset([445, 139])
_SMBV1_HINTS: tuple[str, ...] = ("smbv1", "smb 1", "smb1", "smb v1", "smb1_enabled")


# ---------------------------------------------------------------------------
# Compiled regexes — TEXT format
# ---------------------------------------------------------------------------

_T_HEADER_RE = re.compile(
    r"#\s*Nmap\s+(\S+)\s+scan\s+initiated",
    re.IGNORECASE,
)
_T_REPORT_RE = re.compile(
    r"^Nmap scan report for\s+(\S+?)(?:\s+\(([^)]+)\))?$",
    re.MULTILINE | re.IGNORECASE,
)
_T_PORT_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(open(?:\|filtered)?|closed|filtered)\s+(\S+)(?:\s+(.+))?$",
    re.MULTILINE | re.IGNORECASE,
)
_T_HOST_STATE_RE = re.compile(
    r"Host is (up|down)",
    re.IGNORECASE,
)
_T_RDNS_RE = re.compile(
    r"rDNS record for\s+[\d\.]+:\s+(\S+)",
    re.IGNORECASE,
)
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
_T_SERVICE_INFO_RE = re.compile(
    r"^Service Info:\s+(.+)$",
    re.MULTILINE | re.IGNORECASE,
)
_T_SI_OS_RE = re.compile(
    r"OS:\s*([^;,\n]+)",
    re.IGNORECASE,
)
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

    Extraction populates ParsedAsset/ParsedService objects. Finding generation
    is centralized in _generate_findings_for_asset(), shared by all three
    format paths, and built entirely through the finding catalog.
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
        """Dispatch to the format-specific parser; TEXT handles TEXT/UNKNOWN."""
        result = self._empty_result(nmap_subtype=nmap_subtype)

        try:
            if nmap_subtype is NmapSubtype.XML:
                self._parse_xml(content, file_path, result)
            elif nmap_subtype is NmapSubtype.GREPABLE:
                self._parse_grepable(content, file_path, result)
            else:
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
        """Parse Nmap plain-text (-oN) output."""
        vm = _T_HEADER_RE.search(content)
        if vm:
            result.tool_version = f"Nmap {vm.group(1)}"
            result.scan_metadata["nmap_version"] = vm.group(1)

        report_matches = list(_T_REPORT_RE.finditer(content))
        if not report_matches:
            self._add_error(result, "no 'Nmap scan report for' lines found in TEXT output")
            return

        result.primary_target = report_matches[0].group(1)

        for i, m in enumerate(report_matches):
            start = m.start()
            end   = report_matches[i + 1].start() if i + 1 < len(report_matches) else len(content)
            block = content[start:end]

            asset = self._parse_text_host_block(m, block, result)
            if asset is not None:
                self._generate_findings_for_asset(asset, result)
                result.assets.append(asset)

        result.scan_metadata["total_hosts"] = len(result.assets)

    def _parse_text_host_block(
        self,
        report_m: re.Match,
        block: str,
        result: ParsedScanData,
    ) -> Optional[ParsedAsset]:
        """Parse a single host block from TEXT output into a ParsedAsset."""
        token_a = report_m.group(1)
        token_b = report_m.group(2)

        if token_b:
            hostname   = token_a
            ip_address = token_b
        else:
            hostname   = ""
            ip_address = token_a

        asset_value = hostname if hostname else ip_address
        asset_type  = "hostname" if hostname else "ipv4"

        asset = ParsedAsset(value=asset_value, asset_type=asset_type)

        if ip_address and ip_address != asset_value:
            asset.ip_addresses = [ip_address]
        if hostname and hostname != asset_value:
            asset.hostnames = [hostname]

        rdns_m = _T_RDNS_RE.search(block)
        if rdns_m:
            alias = rdns_m.group(1).strip().rstrip(".")
            if alias and alias not in asset.hostnames and alias != asset_value:
                asset.hostnames.append(alias)

        # ── Port table (extraction only — no finding emission here) ─────────
        for pm in _T_PORT_RE.finditer(block):
            port_num  = int(pm.group(1))
            protocol  = pm.group(2).lower()
            state     = pm.group(3).lower()
            svc_name  = pm.group(4).strip()
            ver_raw   = pm.group(5)
            version   = ver_raw.strip() if ver_raw else None

            asset.services.append(ParsedService(
                port=         port_num,
                protocol=     protocol,
                state=        state,
                service_name= svc_name,
                version=      version,
                extra_info=   pm.group(0).strip(),
            ))

        # ── OS detection ────────────────────────────────────────────────────
        os_name, os_conf = self._extract_os_text(block)
        if os_name:
            asset.os_name       = os_name
            asset.os_confidence = os_conf

        if not asset.os_name:
            si_m = _T_SERVICE_INFO_RE.search(block)
            if si_m:
                os_m2 = _T_SI_OS_RE.search(si_m.group(1))
                if os_m2:
                    asset.os_name       = os_m2.group(1).strip()
                    asset.os_confidence = "medium"

        for svc in asset.services:
            if svc.version and "open" in svc.state:
                asset.hosting_hint = svc.version
                break

        ns_m = _T_NOT_SHOWN_RE.search(block)
        if ns_m:
            asset.scan_metadata["not_shown_count"] = int(ns_m.group(1))
            asset.scan_metadata["not_shown_type"]  = ns_m.group(2).lower()

        return asset

    def _extract_os_text(self, block: str) -> tuple[Optional[str], str]:
        """Extract OS name and confidence from a TEXT host block."""
        od_m = _T_OS_DETAILS_RE.search(block)
        if od_m:
            return od_m.group(1).strip(), "high"

        run_m = _T_RUNNING_RE.search(block)
        if run_m:
            raw = run_m.group(1).split(",")[0].strip()
            raw = re.sub(r"\s*\(\d+%\)\s*$", "", raw).strip()
            return raw, "medium"

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
        """Parse Nmap XML (-oX) output using regex (tolerates truncation)."""
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
            self._generate_findings_for_asset(asset, result)
            result.assets.append(asset)

    def _parse_xml_host_block(
        self,
        block: str,
        result: ParsedScanData,
    ) -> Optional[ParsedAsset]:
        """Parse one <host>...</host> XML block into a ParsedAsset."""
        ip_matches  = _X_ADDR_RE.findall(block)
        host_names  = _X_HOSTNAME_RE.findall(block)

        ips       = [m[0] for m in ip_matches]
        hostnames = list(host_names)

        asset_value = hostnames[0] if hostnames else (ips[0] if ips else None)
        if not asset_value:
            return None

        asset = ParsedAsset(
            value=        asset_value,
            asset_type=   "hostname" if hostnames else "ipv4",
            ip_addresses= ips,
            hostnames=    hostnames,
        )

        for pm in _X_PORT_RE.finditer(block):
            protocol  = pm.group(1).lower()
            port_num  = int(pm.group(2))
            state     = pm.group(3).lower()
            svc_name  = (pm.group(4) or "").strip()
            product   = (pm.group(5) or "").strip()
            version   = (pm.group(6) or "").strip()
            extrainfo = (pm.group(7) or "").strip()

            ver_parts = [p for p in (product, version, extrainfo) if p]
            ver_str   = " ".join(ver_parts) or None

            asset.services.append(ParsedService(
                port=         port_num,
                protocol=     protocol,
                state=        state,
                service_name= svc_name,
                version=      ver_str,
            ))

        # ── OS — prefer highest-accuracy osmatch, fall back to osclass ───────
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
        """Parse Nmap grepable (-oG) output."""
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
                value=        asset_value,
                asset_type=   "hostname" if hostname_raw else "ipv4",
                ip_addresses= [ip_raw] if ip_raw else [],
                hostnames=    [hostname_raw] if hostname_raw else [],
            )

            if first:
                result.primary_target = asset_value
                first = False

            ports_m = _G_PORTS_RE.search(line)
            if ports_m:
                for pe_m in _G_PORT_ENTRY_RE.finditer(ports_m.group(1)):
                    port_num  = int(pe_m.group(1))
                    state     = pe_m.group(2).lower()
                    protocol  = pe_m.group(3).lower()
                    svc_name  = pe_m.group(4).strip()
                    version   = pe_m.group(5).strip() or None

                    asset.services.append(ParsedService(
                        port=         port_num,
                        protocol=     protocol,
                        state=        state,
                        service_name= svc_name,
                        version=      version,
                        extra_info=   pe_m.group(0),
                    ))

            self._generate_findings_for_asset(asset, result)
            result.assets.append(asset)

        if not result.assets:
            self._add_error(result, "no 'Host:' lines found in GREPABLE output")

    # =========================================================================
    # Finding generation — centralized, catalog-driven, shared by all formats
    # =========================================================================

    def _generate_findings_for_asset(
        self,
        asset: ParsedAsset,
        result: ParsedScanData,
    ) -> None:
        """
        Generate deterministic findings for one fully-parsed asset.

        Runs after all services and OS data are populated, so host-level logic
        (e.g. "is any TLS service present?") can see the complete picture. All
        findings are built through the catalog; this method only decides WHICH
        finding types apply and supplies the observed evidence.
        """
        src = self.tool_type.value

        open_services = [s for s in asset.services if "open" in (s.state or "").lower()]
        host_has_tls  = any(self._is_tls_service(s) for s in open_services)

        # Dedup version-disclosure per (product/version) so identical banners on
        # multiple ports of the same host produce a single finding.
        seen_versions: set[str] = set()

        for svc in open_services:
            port      = svc.port
            svc_lower = (svc.service_name or "").lower().strip()
            evidence  = svc.extra_info or f"{port}/{svc.protocol} {svc.state} {svc.service_name}".strip()

            specific_emitted = False

            # ── 1. Legacy/cleartext protocol exposures (port-driven) ─────────
            if port in _PORT_FINDING_TYPE:
                result.findings.append(build_finding(
                    _PORT_FINDING_TYPE[port],
                    asset.value, port=port, protocol=svc.protocol,
                    service=svc.service_name, version=svc.version,
                    evidence=evidence, source_tool=src,
                ))
                specific_emitted = True

            # ── 2. SMBv1 — only when the banner explicitly indicates it ──────
            elif port in _SMB_PORTS:
                banner = f"{svc_lower} {(svc.version or '').lower()}"
                if any(h in banner for h in _SMBV1_HINTS):
                    result.findings.append(build_finding(
                        "SMBV1_ENABLED",
                        asset.value, port=port, protocol=svc.protocol,
                        service=svc.service_name, version=svc.version,
                        evidence=evidence, source_tool=src,
                    ))
                    specific_emitted = True

            # ── 3. Cleartext HTTP (host-aware: HTTP_ONLY vs HTTPS_MISSING) ──
            elif self._is_http_service(svc):
                if host_has_tls:
                    result.findings.append(build_finding(
                        "HTTP_ONLY",
                        asset.value, port=port, protocol=svc.protocol,
                        service=svc.service_name, version=svc.version,
                        evidence=evidence, source_tool=src,
                    ))
                else:
                    result.findings.append(build_finding(
                        "HTTPS_MISSING",
                        asset.value, port=port, protocol=svc.protocol,
                        service=svc.service_name, version=svc.version,
                        evidence=evidence, source_tool=src,
                    ))
                specific_emitted = True

            # ── 4. Outdated service (banner version heuristic) ───────────────
            outdated, reason = is_outdated_service(svc.service_name, svc.version)
            if outdated:
                result.findings.append(build_finding(
                    "OUTDATED_SERVICE",
                    asset.value, port=port, protocol=svc.protocol,
                    service=svc.service_name, version=svc.version,
                    evidence=evidence, source_tool=src, reason=reason,
                ))

            # ── 5. Service version disclosure (any banner-leaking service) ──
            if svc.version and svc_lower not in _INFO_ONLY_SERVICES:
                vkey = svc.version.strip().lower()
                if vkey not in seen_versions:
                    seen_versions.add(vkey)
                    result.findings.append(build_finding(
                        "SERVICE_VERSION_DISCLOSURE",
                        asset.value, port=port, protocol=svc.protocol,
                        service=svc.service_name, version=svc.version,
                        evidence=evidence, source_tool=src,
                    ))

            # ── 6. Open-port inventory baseline (only if nothing specific) ──
            if not specific_emitted:
                result.findings.append(build_finding(
                    "OPEN_PORT",
                    asset.value, port=port, protocol=svc.protocol,
                    service=svc.service_name, version=svc.version,
                    evidence=evidence, source_tool=src,
                ))

        # ── 7. Asset-level: end-of-life operating system ─────────────────────
        eol, reason = is_eol_os(asset.os_name)
        if eol:
            # OS detection is a fingerprint guess; scale severity/confidence to
            # how confident Nmap was. High-confidence match → keep HIGH.
            conf = asset.os_confidence or "low"
            severity = "HIGH" if conf == "high" else "MEDIUM"
            result.findings.append(build_finding(
                "EOL_OPERATING_SYSTEM",
                asset.value,
                version=     asset.os_name,
                evidence=    f"OS fingerprint: {asset.os_name} (confidence: {conf})",
                source_tool= src,
                severity=    severity,
                confidence=  conf,
                reason=      reason,
            ))

    # ── Service-classification helpers ──────────────────────────────────────

    @staticmethod
    def _is_http_service(svc: ParsedService) -> bool:
        """True for cleartext HTTP services (not TLS-wrapped)."""
        name = (svc.service_name or "").lower().strip()
        if "ssl" in name or "https" in name:
            return False
        return name in _HTTP_SERVICES or svc.port in _HTTP_PORTS

    @staticmethod
    def _is_tls_service(svc: ParsedService) -> bool:
        """True when the service indicates TLS is available on the host."""
        name = (svc.service_name or "").lower().strip()
        if "ssl" in name or "https" in name:
            return True
        return name in _TLS_HINT_SERVICES or svc.port in _TLS_PORTS


# ---------------------------------------------------------------------------
# Registration — runs at module import time
# ---------------------------------------------------------------------------

register(NmapParser())
log.debug("NmapParser registered for ToolType.NMAP")
