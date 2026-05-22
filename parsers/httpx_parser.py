"""
intelligence/parsers/httpx_parser.py
=====================================
Httpx scan output parser for IntelliAssess AI — Phase 3-3.

Responsibility: parse Httpx scan output (JSONL / plain-text) into structured
ParsedScanData. Deterministic extraction only — no AI, no CVE lookup, no
severity engine, no compliance logic.

Supported formats:
  JSONL      (httpx -json) — PRIMARY. One JSON object per line. Richest
                             signal: URL, status, title, headers, tech,
                             redirect, IP, webserver, CDN indicator.
  PLAIN TEXT (httpx default) — SECONDARY. Line-based patterns. Extracts
                               URL, status code, optional title. No header
                               data available; header-dependent findings
                               are suppressed on this path.

Finding types generated (deterministic, header/scheme driven):
  HTTP_ONLY                    — target URL uses http:// scheme
  VERSION_DISCLOSURE           — Server header exposes product + version string
  MISSING_HSTS                 — HTTPS target lacks Strict-Transport-Security
  MISSING_CSP                  — Content-Security-Policy header absent
  MISSING_X_FRAME_OPTIONS      — X-Frame-Options header absent
  MISSING_REFERRER_POLICY      — Referrer-Policy header absent
  MISSING_X_CONTENT_TYPE_OPTIONS — X-Content-Type-Options header absent

Intentionally NOT in this phase:
  - CVE correlation             (Phase 4 — cve_enricher.py)
  - Severity adjustment         (Phase 4 — context_risk_engine.py)
  - AI-generated narrative      (Phase 4 — analyzer.py + LLMClient)
  - Compliance mapping          (Phase 5 — compliance_engine.py)
  - Cookie flag analysis        (deferred — no Httpx default output)
  - CORS misconfiguration       (deferred — requires active probing)

Integration:
  - Registered at module load via register() from parsers/registry.py
  - Imported in intelligence/parsers/__init__.py (triggers registration)
  - Called from core/ingest.py via parse_file() — zero ingest.py changes needed

Phase 3-4 note:
  SslscanParser is next. TLS-layer findings (cipher suites, weak protocols,
  cert analysis) belong there — HttpxParser notes the presence of HTTPS
  but does not inspect TLS configuration details.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from intelligence.file_classifier import NmapSubtype, ToolType
from parsers.base import BaseParser, ParsedScanData
from parsers.models import ParsedAsset, ParsedFinding, ParsedService
from parsers.registry import register
from utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Security header registry — drives header-based finding generation.
# Each entry: (header_name_lowercase, finding_type, severity_hint, scope)
# scope: "https_only" — finding suppressed for plain http:// targets
#        "any"        — finding generated regardless of scheme
# ---------------------------------------------------------------------------

_SECURITY_HEADERS: list[tuple[str, str, str, str]] = [
    ("strict-transport-security",  "MISSING_HSTS",                     "MEDIUM", "https_only"),
    ("content-security-policy",    "MISSING_CSP",                      "MEDIUM", "any"),
    ("x-frame-options",            "MISSING_X_FRAME_OPTIONS",          "MEDIUM", "any"),
    ("referrer-policy",            "MISSING_REFERRER_POLICY",          "LOW",    "any"),
    ("x-content-type-options",     "MISSING_X_CONTENT_TYPE_OPTIONS",   "LOW",    "any"),
]

# Regex: detect version-bearing Server header values.
# Matches patterns like "nginx/1.24.0", "Apache/2.4.58", "openresty/1.19.3"
# Does NOT match bare product names with no version ("cloudflare", "AmazonS3").
_SERVER_VERSION_RE = re.compile(
    r"^([A-Za-z][A-Za-z0-9\-_]*)/(\d[\d\.]+)",
    re.IGNORECASE,
)

# Plain-text output patterns.
# Httpx default: "https://example.com [200] [Page Title]"
# Httpx compact: "[200] https://example.com"
# Httpx minimal: "https://example.com" (no extras)
_PT_URL_STATUS_TITLE_RE = re.compile(
    r"^(https?://\S+)\s+\[(\d{3})\](?:\s+\[([^\]]*)\])?",
    re.IGNORECASE,
)
_PT_STATUS_URL_RE = re.compile(
    r"^\[(\d{3})\]\s+(https?://\S+)",
    re.IGNORECASE,
)
_PT_URL_ONLY_RE = re.compile(
    r"^(https?://\S+)$",
    re.IGNORECASE,
)

# CDN / hosting indicator strings that appear in JSONL "cdn" or tech arrays.
# Used to populate asset.hosting_hint for Phase 4 infra_reasoner consumption.
_CDN_INDICATORS: frozenset[str] = frozenset([
    "cloudflare", "cloudfront", "akamai", "fastly", "sucuri",
    "incapsula", "maxcdn", "cdn77", "stackpath",
])


# ---------------------------------------------------------------------------
# HttpxParser
# ---------------------------------------------------------------------------

class HttpxParser(BaseParser):
    """
    Parser for Httpx scan output in JSONL and plain-text formats.

    JSONL (httpx -json) is the primary and highest-quality parsing path.
    Each JSON line produces one ParsedAsset with full header data, tech stack,
    redirect chain, and server banner. Header-based findings (HSTS, CSP, etc.)
    are only generated on this path.

    Plain-text is the secondary path. It yields URL, status code, and optional
    title. No header data is available; only HTTP_ONLY and VERSION_DISCLOSURE
    (from webserver field if present) are attempted.

    Format detection is content-based: if any line parses as valid JSON
    containing a "url" or "status_code" key, JSONL mode is used.
    """

    tool_type = ToolType.HTTPX

    # =========================================================================
    # Public parse() — format detection and dispatch
    # =========================================================================

    def parse(
        self,
        content: str,
        file_path: Path,
        nmap_subtype: Optional[NmapSubtype] = None,
    ) -> ParsedScanData:
        """
        Detect format (JSONL vs plain-text) and dispatch accordingly.

        JSONL detection: scan up to 10 non-empty lines for a valid JSON
        object containing "url" or "status_code". If found → JSONL path.
        Otherwise → plain-text path.

        nmap_subtype is ignored — always None for Httpx files.
        """
        result = self._empty_result()

        try:
            if self._is_jsonl(content):
                result.scan_metadata["format"] = "jsonl"
                self._parse_jsonl(content, file_path, result)
            else:
                result.scan_metadata["format"] = "plaintext"
                self._parse_plaintext(content, file_path, result)
        except Exception as exc:
            self._add_error(result, f"unexpected exception during parse: {exc!r}")
            log.error(
                "HttpxParser: unexpected exception parsing %s: %s",
                file_path.name, exc,
                exc_info=True,
            )

        log.debug("HttpxParser: %s", result.summary())
        return result

    # =========================================================================
    # Format detection
    # =========================================================================

    @staticmethod
    def _is_jsonl(content: str) -> bool:
        """
        Return True if the content looks like Httpx JSONL output.

        Scans the first 10 non-empty lines. If any line is valid JSON
        containing a "url" or "status_code" key, declares JSONL format.
        This tolerates mixed output (e.g., a log header before JSON lines).
        """
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict) and ("url" in obj or "status_code" in obj):
                    return True
            except (json.JSONDecodeError, ValueError):
                pass
        return False

    # =========================================================================
    # JSONL parser — primary, highest-quality path
    # =========================================================================

    def _parse_jsonl(
        self,
        content: str,
        file_path: Path,
        result: ParsedScanData,
    ) -> None:
        """
        Parse Httpx JSONL output.

        Each valid JSON line → one ParsedAsset + associated ParsedFindings.

        Common JSONL fields (httpx -json output):
          url           : str         — full URL including scheme
          status_code   : int         — HTTP response status
          title         : str         — page <title>
          webserver     : str         — Server header value (e.g. "nginx/1.24.0")
          content_length: int         — response body size
          location      : str         — redirect target (if 3xx)
          host          : str         — resolved IP address
          tech          : list[str]   — detected technologies
          cdn            : bool        — CDN indicator flag (some versions)
          header        : dict        — response headers (key: value)
          input         : str         — original scan target
          scheme        : str         — "http" | "https"
          port          : int         — target port

        Fields vary by Httpx version and flags used — all accesses use .get()
        with safe defaults. Missing fields are silently skipped.
        """
        first = True
        line_num = 0

        for raw_line in content.splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            try:
                obj = json.loads(raw_line)
            except (json.JSONDecodeError, ValueError):
                # Non-JSON lines (tool banners, progress output) — skip quietly
                log.debug("HttpxParser JSONL: skipping non-JSON line %d", line_num)
                line_num += 1
                continue

            line_num += 1

            if not isinstance(obj, dict):
                continue

            url = obj.get("url", "")
            if not url:
                # url is the primary key — a line without it isn't a scan result
                continue

            asset = self._build_asset_from_jsonl(obj, url)
            if asset is None:
                continue

            if first:
                result.primary_target = asset.value
                result.tool_version   = obj.get("version")   # some builds include this
                first = False

            result.assets.append(asset)

            # Store all response headers in result.http_headers for the
            # FIRST asset only (most Httpx runs target a single base URL).
            # Phase 4: analyzer will consume these for deeper header analysis.
            if len(result.assets) == 1:
                headers_raw = obj.get("header", {})
                if isinstance(headers_raw, dict):
                    # Normalize header names to lowercase for consistent lookup
                    result.http_headers = {
                        k.lower(): v for k, v in headers_raw.items()
                    }

            # Generate findings for this asset
            findings = self._generate_findings_jsonl(obj, url, asset.value)
            result.findings.extend(findings)

        if not result.assets:
            self._add_error(result, "no valid JSON result lines found in JSONL output")

        result.scan_metadata["total_urls"] = len(result.assets)

    def _build_asset_from_jsonl(
        self,
        obj: dict,
        url: str,
    ) -> Optional[ParsedAsset]:
        """
        Build a ParsedAsset from a single Httpx JSONL object.

        asset.value is the normalized hostname (no scheme/port/path).
        asset.hosting_hint carries the webserver string or a CDN name.
        asset.services carries a synthetic HTTP/HTTPS service entry.
        asset.scan_metadata carries URL-level extras (status, title, tech).
        """
        try:
            parsed_url = urlparse(url)
        except Exception:
            log.debug("HttpxParser: urlparse failed for %r", url)
            return None

        hostname = (parsed_url.hostname or "").lower().strip()
        if not hostname:
            return None

        scheme      = (parsed_url.scheme or "http").lower()
        port_raw    = obj.get("port") or parsed_url.port
        status_code = obj.get("status_code", 0)
        title       = obj.get("title", "") or ""
        webserver   = obj.get("webserver", "") or ""
        ip_address  = obj.get("host", "") or ""
        location    = obj.get("location", "") or ""
        tech_list   = obj.get("tech", []) or []
        cdn_flag    = obj.get("cdn", False)

        # Determine port: explicit JSON field → URL port → scheme default
        if port_raw:
            port = int(port_raw)
        else:
            port = 443 if scheme == "https" else 80

        # Hosting hint — CDN takes priority over webserver string for
        # infra_reasoner. CDN name extracted from tech list or flag.
        hosting_hint = _extract_hosting_hint(webserver, tech_list, cdn_flag)

        asset = ParsedAsset(
            value=        hostname,
            asset_type=   "hostname",
            ip_addresses= [ip_address] if ip_address else [],
            hosting_hint= hosting_hint,
            scan_metadata={
                "url":          url,
                "scheme":       scheme,
                "status_code":  status_code,
                "title":        title,
                "webserver":    webserver,
                "location":     location,
                "tech":         tech_list,
                "cdn":          cdn_flag,
            },
        )

        # Synthetic service entry — HTTP/HTTPS on discovered port
        service_name = "https" if scheme == "https" else "http"
        svc = ParsedService(
            port=         port,
            protocol=     "tcp",
            state=        "open",
            service_name= service_name,
            version=      webserver or None,
        )
        asset.services.append(svc)

        return asset

    def _generate_findings_jsonl(
        self,
        obj: dict,
        url: str,
        target: str,
    ) -> list[ParsedFinding]:
        """
        Generate deterministic ParsedFinding entries from a JSONL object.

        Finding generation order (each is independent):
          1. HTTP_ONLY            — scheme is http://
          2. VERSION_DISCLOSURE   — Server header exposes version
          3. Security headers     — iterate _SECURITY_HEADERS table
        """
        findings: list[ParsedFinding] = []

        scheme    = (urlparse(url).scheme or "").lower()
        webserver = obj.get("webserver", "") or ""
        headers   = obj.get("header", {}) or {}

        # Normalize header keys for consistent lookup
        headers_lc = {k.lower(): v for k, v in headers.items()} if isinstance(headers, dict) else {}

        # ── 1. HTTP_ONLY ──────────────────────────────────────────────────
        if scheme == "http":
            findings.append(ParsedFinding(
                finding_type=  "HTTP_ONLY",
                target=        target,
                port=          80,
                protocol=      "tcp",
                service=       "http",
                detail=        f"Target served over unencrypted HTTP: {url}",
                severity_hint= "MEDIUM",
                raw_evidence=  url,
                source_tool=   self.tool_type.value,
            ))

        # ── 2. VERSION_DISCLOSURE ─────────────────────────────────────────
        # Triggered when Server header contains a product/version string.
        # Plain version string from webserver field (already extracted by Httpx).
        if webserver:
            vm = _SERVER_VERSION_RE.match(webserver)
            if vm:
                findings.append(ParsedFinding(
                    finding_type=  "VERSION_DISCLOSURE",
                    target=        target,
                    port=          443 if scheme == "https" else 80,
                    protocol=      "tcp",
                    service=       "http",
                    detail=        f"Server header discloses version: {webserver}",
                    severity_hint= "LOW",
                    raw_evidence=  f"Server: {webserver}",
                    source_tool=   self.tool_type.value,
                ))

        # ── 3. Security headers (JSONL path only — headers available) ────
        # Only run when we actually have header data to inspect.
        if headers_lc:
            for header_name, finding_type, severity, scope in _SECURITY_HEADERS:
                # Scope guard: HSTS is only relevant on HTTPS targets
                if scope == "https_only" and scheme != "https":
                    continue
                if header_name not in headers_lc:
                    findings.append(ParsedFinding(
                        finding_type=  finding_type,
                        target=        target,
                        port=          443 if scheme == "https" else 80,
                        protocol=      "tcp",
                        service=       service_name_for_scheme(scheme),
                        detail=        f"Missing security header: {header_name}",
                        severity_hint= severity,
                        raw_evidence=  f"Header absent: {header_name}",
                        source_tool=   self.tool_type.value,
                    ))

        return findings

    # =========================================================================
    # Plain-text parser — secondary path
    # =========================================================================

    def _parse_plaintext(
        self,
        content: str,
        file_path: Path,
        result: ParsedScanData,
    ) -> None:
        """
        Parse Httpx default plain-text output.

        Pattern variants handled:
          "https://example.com [200] [Page Title]"   — url + status + title
          "[200] https://example.com"                — status + url (alt format)
          "https://example.com"                      — url only

        No header data is available on this path. Header-dependent findings
        (HSTS, CSP, X-Frame-Options, etc.) are suppressed. Only HTTP_ONLY
        and VERSION_DISCLOSURE (from a webserver field, if present in some
        extended plain-text variants) are attempted.
        """
        first = True

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            url, status_code, title = self._parse_plaintext_line(line)
            if not url:
                continue

            try:
                parsed_url = urlparse(url)
            except Exception:
                continue

            hostname = (parsed_url.hostname or "").lower().strip()
            if not hostname:
                continue

            scheme = (parsed_url.scheme or "http").lower()
            port_from_url = parsed_url.port
            port = port_from_url if port_from_url else (443 if scheme == "https" else 80)

            asset = ParsedAsset(
                value=     hostname,
                asset_type="hostname",
                scan_metadata={
                    "url":         url,
                    "scheme":      scheme,
                    "status_code": status_code,
                    "title":       title,
                },
            )

            svc = ParsedService(
                port=         port,
                protocol=     "tcp",
                state=        "open",
                service_name= "https" if scheme == "https" else "http",
            )
            asset.services.append(svc)
            result.assets.append(asset)

            if first:
                result.primary_target = hostname
                first = False

            # Plain-text path: HTTP_ONLY finding only (no header data available)
            if scheme == "http":
                result.findings.append(ParsedFinding(
                    finding_type=  "HTTP_ONLY",
                    target=        hostname,
                    port=          port,
                    protocol=      "tcp",
                    service=       "http",
                    detail=        f"Target served over unencrypted HTTP: {url}",
                    severity_hint= "MEDIUM",
                    raw_evidence=  line,
                    source_tool=   self.tool_type.value,
                ))

        if not result.assets:
            self._add_error(result, "no valid URL lines found in plain-text output")

        result.scan_metadata["total_urls"] = len(result.assets)

    @staticmethod
    def _parse_plaintext_line(line: str) -> tuple[str, int, str]:
        """
        Extract (url, status_code, title) from a single plain-text line.

        Returns ("", 0, "") for lines that don't match any known pattern.
        """
        # Pattern 1: "https://example.com [200] [Title]"
        m = _PT_URL_STATUS_TITLE_RE.match(line)
        if m:
            return m.group(1), int(m.group(2)), (m.group(3) or "")

        # Pattern 2: "[200] https://example.com"
        m = _PT_STATUS_URL_RE.match(line)
        if m:
            return m.group(2), int(m.group(1)), ""

        # Pattern 3: bare URL only
        m = _PT_URL_ONLY_RE.match(line)
        if m:
            return m.group(1), 0, ""

        return "", 0, ""


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _extract_hosting_hint(
    webserver: str,
    tech_list: list,
    cdn_flag: bool,
) -> Optional[str]:
    """
    Derive a hosting_hint string for asset.hosting_hint.

    Priority:
      1. CDN name from tech list (e.g. "Cloudflare", "Amazon CloudFront")
      2. cdn_flag=True with no specific name → "CDN"
      3. webserver string (e.g. "nginx/1.24.0 (Ubuntu)")
      4. None

    hosting_hint is consumed by Phase 4's infra_reasoner.py.
    """
    if isinstance(tech_list, list):
        for tech in tech_list:
            tech_lower = (tech or "").lower()
            for cdn_name in _CDN_INDICATORS:
                if cdn_name in tech_lower:
                    return tech   # Return the original capitalized form

    if cdn_flag:
        return "CDN"

    if webserver:
        return webserver

    return None


def service_name_for_scheme(scheme: str) -> str:
    """Return the canonical service name for a URL scheme."""
    return "https" if scheme == "https" else "http"


# ---------------------------------------------------------------------------
# Registration — runs at module import time.
# Mirrors the pattern used by NmapParser.
# ---------------------------------------------------------------------------

register(HttpxParser())
log.debug("HttpxParser registered for ToolType.HTTPX")
