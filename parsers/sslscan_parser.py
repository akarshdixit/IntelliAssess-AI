"""
intelligence/parsers/sslscan_parser.py
=======================================
SSLScan output parser for IntelliAssess AI — Phase 3-4.

Responsibility: parse SSLScan plain-text output into structured ParsedScanData.
Deterministic extraction only — no AI, no CVE lookup, no severity engine,
no compliance logic.

SSLScan produces a single plain-text output format. There are no subtypes.
The nmap_subtype parameter is always ignored.

Supported SSLScan output sections:
  Header         — "Testing SSL server <host> on port <port>"
                   → primary_target, port, optional SNI name
  Protocol table — "SSLv2     disabled", "TLSv1.2   enabled"
                   → ParsedFinding entries per protocol
  Cipher table   — "Accepted TLSv1.2 256 bits ECDHE-RSA-AES256-GCM-SHA384"
                   → cipher entries, weak-cipher finding generation
  Certificate    — "SSL Certificate:" block with Subject, Issuer,
                   Not valid after, Self Signed fields
                   → ParsedAsset ssl_info population + cert findings

Finding types generated (deterministic):
  WEAK_TLS_VERSION     — SSLv2, SSLv3, TLSv1.0, or TLSv1.1 accepted
  WEAK_CIPHER          — Cipher suite containing a known-weak algorithm
  SELF_SIGNED_CERT     — Certificate is self-signed
  EXPIRED_CERT         — Certificate validity has passed
  TLS_ENABLED          — TLSv1.2 or TLSv1.3 accepted (positive, INFO)

Intentionally NOT in this phase:
  - CVE correlation                  (Phase 4 — cve_enricher.py)
  - Severity adjustment              (Phase 4 — context_risk_engine.py)
  - AI-generated narrative           (Phase 4 — analyzer.py + LLMClient)
  - Compliance mapping               (Phase 5 — compliance_engine.py)
  - Heartbleed / ROBOT test parsing  (deferred — test output is tool-version
                                      dependent and not universally present)
  - OCSP stapling analysis           (deferred — Phase 4+)

Integration:
  - Registered at module load via register() from parsers/registry.py
  - Imported in intelligence/parsers/__init__.py (triggers registration)
  - Called from core/ingest.py via parse_file() — zero ingest.py changes needed

Phase 3-5 note:
  SubfinderParser is next. Subdomain enumeration output belongs there.
  SslscanParser does not interpret subdomain data.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from intelligence.file_classifier import NmapSubtype, ToolType
from intelligence.finding_catalog import build_finding, is_short_rsa_key
from parsers.base import BaseParser, ParsedScanData
from parsers.models import ParsedAsset, ParsedFinding, ParsedService
from parsers.registry import register
from utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Protocol classification — severity and finding generation rules
# ---------------------------------------------------------------------------

# Protocols that generate a WEAK_TLS_VERSION finding.
# Key: normalized lowercase name found in the line.
# Value: (finding_severity_hint, human_label)
_WEAK_PROTOCOLS: dict[str, tuple[str, str]] = {
    "sslv2":   ("CRITICAL", "SSLv2"),
    "sslv3":   ("HIGH",     "SSLv3"),
    "tlsv1.0": ("HIGH",     "TLSv1.0"),
    "tlsv1.1": ("MEDIUM",   "TLSv1.1"),
}

# Protocols that generate a positive TLS_ENABLED finding (INFO — for report context).
_STRONG_PROTOCOLS: dict[str, str] = {
    "tlsv1.2": "TLSv1.2",
    "tlsv1.3": "TLSv1.3",
}

# All protocol keywords the parser recognizes (used for line filtering).
_ALL_PROTOCOL_KEYWORDS: frozenset[str] = frozenset(
    list(_WEAK_PROTOCOLS.keys()) + list(_STRONG_PROTOCOLS.keys())
)


# ---------------------------------------------------------------------------
# Cipher weakness detection — deny-list of algorithm substrings
# ---------------------------------------------------------------------------

# Cipher name substrings that indicate a weak or deprecated algorithm.
# Matched case-insensitively against the cipher suite name token only.
#
# Rationale per entry:
#   RC4        — stream cipher, biased keystream, deprecated RFC 7465
#   DES-       — 56-bit key, broken since 1998 (prefix match avoids "3DES")
#   3DES       — SWEET32 birthday attack (CVE-2016-2183)
#   _DES_      — catches interior DES variants (e.g. EDE variants)
#   EXPORT     — 40-bit keys, intentionally weak (FREAK, LOGJAM)
#   NULL       — no encryption
#   ANON       — anonymous key exchange, no authentication
#   ADH        — Anonymous Diffie-Hellman
#   AECDH      — Anonymous ECDH
#   MD5        — in cipher name (e.g. RC4-MD5); NOT the hash used in ECDHE
#   SEED       — Korean algorithm, not universally trusted, rarely patched
#   IDEA       — 64-bit block cipher, SWEET32-class risk
#   CAMELLIA   — not broken but rarely maintained; low severity — omitted here
#                (include only unambiguously weak/broken algorithms)
_WEAK_CIPHER_SUBSTRINGS: tuple[str, ...] = (
    "RC4",
    "DES-",
    "3DES",
    "_DES_",
    "EXPORT",
    "NULL",
    "ANON",
    "ADH-",
    "AECDH-",
    "RC4-MD5",
    "RC4-SHA",
    "SEED-",
    "IDEA-",
)


def _is_weak_cipher(cipher_name: str) -> bool:
    """
    Return True if the cipher name contains any known-weak algorithm substring.

    Case-insensitive match. The cipher_name is the full suite name token
    (e.g. "ECDHE-RSA-AES256-GCM-SHA384", "RC4-MD5", "DES-CBC3-SHA").
    """
    upper = cipher_name.upper()
    for substring in _WEAK_CIPHER_SUBSTRINGS:
        if substring.upper() in upper:
            return True
    return False


# ---------------------------------------------------------------------------
# Compiled regexes
# ---------------------------------------------------------------------------

# Header: "Testing SSL server hostname on port 443"
# Optional SNI: "Testing SSL server 10.0.0.1 on port 443 using SNI name example.com"
_HEADER_RE = re.compile(
    r"Testing SSL server\s+(\S+)\s+on port\s+(\d+)"
    r"(?:\s+using SNI name\s+(\S+))?",
    re.IGNORECASE,
)

# Protocol line: "    SSLv2     disabled" / "    TLSv1.2   enabled"
# Captures: (protocol_token, status_token)
_PROTOCOL_RE = re.compile(
    r"^\s*(SSLv[23]|TLSv1(?:\.[0-3])?)\s+(enabled|disabled|not supported|accepted|rejected)",
    re.IGNORECASE | re.MULTILINE,
)

# Cipher line: "    Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384"
# Also handles: "    Preferred TLSv1.3 256 bits TLS_AES_256_GCM_SHA384"
# Captures: (status, protocol, bits, cipher_name)
_CIPHER_RE = re.compile(
    r"^\s*(Accepted|Preferred)\s+(SSLv[23]|TLSv1(?:\.[0-3])?)\s+(\d+)\s+bits\s+(\S+)",
    re.IGNORECASE | re.MULTILINE,
)

# Certificate block start marker
_CERT_BLOCK_RE = re.compile(r"SSL Certificate:", re.IGNORECASE)

# Certificate field lines — parse the block line-by-line after locating the block.
# re.MULTILINE is REQUIRED: without it, the trailing `$` only anchors at end of
# the whole block, so any field that is NOT on the final line silently fails to
# match (this previously suppressed Subject/Issuer/Self-Signed/key-size parsing
# whenever the block did not end on that field).
_CERT_SUBJECT_RE  = re.compile(r"Subject:\s+(.+)$",          re.IGNORECASE | re.MULTILINE)
_CERT_ISSUER_RE   = re.compile(r"Issuer:\s+(.+)$",           re.IGNORECASE | re.MULTILINE)
_CERT_EXPIRY_RE   = re.compile(r"Not valid after:\s+(.+)$",  re.IGNORECASE | re.MULTILINE)
_CERT_NOTBEFORE_RE= re.compile(r"Not valid before:\s+(.+)$", re.IGNORECASE | re.MULTILINE)
_CERT_SELFSIGN_RE = re.compile(r"Self[- ]Signed:\s+(\w+)",   re.IGNORECASE | re.MULTILINE)
_CERT_ALG_RE      = re.compile(r"Signature Algorithm:\s+(.+)$", re.IGNORECASE | re.MULTILINE)
_CERT_KEYSIZE_RE  = re.compile(r"RSA Key Strength:\s+(\d+)",  re.IGNORECASE | re.MULTILINE)

# SSLScan version line: "Version: 2.0.15" or banner "sslscan version 2.0.15"
_VERSION_RE = re.compile(
    r"(?:Version:|sslscan\s+version)\s+(\S+)",
    re.IGNORECASE,
)

# Known date formats emitted by different SSLScan versions
_CERT_DATE_FORMATS: tuple[str, ...] = (
    "%b %d %H:%M:%S %Y %Z",   # "May 20 12:00:00 2027 GMT"
    "%b %d %H:%M:%S %Y",      # "May 20 12:00:00 2027"
    "%Y-%m-%d %H:%M:%S %Z",   # "2027-05-20 12:00:00 GMT" (some builds)
    "%Y-%m-%d %H:%M:%S",      # "2027-05-20 12:00:00"
    "%d/%m/%Y",               # "20/05/2027"
)


# ---------------------------------------------------------------------------
# SslscanParser
# ---------------------------------------------------------------------------

class SslscanParser(BaseParser):
    """
    Parser for SSLScan plain-text output.

    SSLScan produces a single output format — no subtype dispatch needed.
    Parsing is always sequential over the full content string.

    Parsing flow:
      1. Extract tool version from banner.
      2. Parse header line → primary_target, port, optional SNI hostname.
      3. Parse protocol acceptance table → per-protocol findings.
      4. Parse cipher suite table → cipher inventory + weak-cipher findings.
      5. Parse SSL certificate block → cert metadata + cert findings.
      6. Build ParsedAsset with ssl_info populated.
      7. Build ParsedService for the TLS port.
    """

    tool_type = ToolType.SSLSCAN

    # =========================================================================
    # Public parse() entry point
    # =========================================================================

    def parse(
        self,
        content: str,
        file_path: Path,
        nmap_subtype: Optional[NmapSubtype] = None,
    ) -> ParsedScanData:
        """
        Parse SSLScan plain-text content into ParsedScanData.

        nmap_subtype is always ignored — SSLScan has no output subtypes.
        """
        result = self._empty_result()

        try:
            self._parse_sslscan(content, file_path, result)
        except Exception as exc:
            self._add_error(result, f"unexpected exception during parse: {exc!r}")
            log.error(
                "SslscanParser: unexpected exception parsing %s: %s",
                file_path.name, exc,
                exc_info=True,
            )

        log.debug("SslscanParser: %s", result.summary())
        return result

    # =========================================================================
    # Main parsing driver
    # =========================================================================

    def _parse_sslscan(
        self,
        content: str,
        file_path: Path,
        result: ParsedScanData,
    ) -> None:
        """
        Sequential parsing of SSLScan plain-text output.

        Sections are identified by regex anchors and parsed independently.
        Partial results are accumulated even if one section fails to parse.
        """
        # ── 1. Tool version ───────────────────────────────────────────────
        vm = _VERSION_RE.search(content)
        if vm:
            result.tool_version = f"sslscan {vm.group(1)}"

        # ── 2. Header: target + port ──────────────────────────────────────
        hm = _HEADER_RE.search(content)
        if not hm:
            self._add_error(result, "no 'Testing SSL server' header found")
            return

        server_raw = hm.group(1)      # may be hostname or IP
        port_raw   = hm.group(2)      # port number string
        sni_raw    = hm.group(3)      # SNI name (may be None)

        # Prefer SNI hostname as the meaningful target identifier when present
        primary_target = (sni_raw or server_raw).lower().strip()
        port           = int(port_raw)

        result.primary_target        = primary_target
        result.scan_metadata["host"] = server_raw
        result.scan_metadata["port"] = port
        result.scan_metadata["sni"]  = sni_raw

        # ── 3. Protocol table ─────────────────────────────────────────────
        proto_findings, supported_protocols = self._parse_protocols(
            content, primary_target, port
        )
        result.findings.extend(proto_findings)
        result.scan_metadata["supported_protocols"] = supported_protocols

        # ── 4. Cipher suite table ─────────────────────────────────────────
        cipher_findings, cipher_inventory = self._parse_ciphers(
            content, primary_target, port
        )
        result.findings.extend(cipher_findings)
        result.scan_metadata["cipher_inventory"] = cipher_inventory

        # ── 5. Certificate block ──────────────────────────────────────────
        cert_info, cert_findings = self._parse_certificate(
            content, primary_target, port
        )
        result.findings.extend(cert_findings)

        # ── 6. Build ssl_info dict (consumed by Phase 4 analyzer) ─────────
        result.ssl_info = {
            "supported_protocols": supported_protocols,
            "cipher_inventory":    cipher_inventory,
            "certificate":         cert_info,
        }

        # ── 7. Build ParsedAsset ──────────────────────────────────────────
        asset = ParsedAsset(
            value=      primary_target,
            asset_type= "hostname" if _looks_like_hostname(primary_target) else "ipv4",
            scan_metadata={
                "ssl_port":          port,
                "server_raw":        server_raw,
                "sni":               sni_raw,
                "protocols_enabled": [p for p in supported_protocols if p.get("enabled")],
            },
        )

        # IP address: server_raw if it looks like an IP (SNI case)
        if sni_raw and _looks_like_ip(server_raw):
            asset.ip_addresses = [server_raw]

        # TLS service entry
        svc = ParsedService(
            port=         port,
            protocol=     "tcp",
            state=        "open",
            service_name= "https" if port == 443 else "ssl",
            version=      None,   # version populated from cert or banner if available
        )
        asset.services.append(svc)
        result.assets.append(asset)

    # =========================================================================
    # Protocol parsing
    # =========================================================================

    def _parse_protocols(
        self,
        content: str,
        target: str,
        port: int,
    ) -> tuple[list[ParsedFinding], list[dict]]:
        """
        Parse protocol acceptance lines and generate per-protocol findings.

        Returns:
          findings          — list of ParsedFinding (one per notable protocol)
          supported_protocols — list of dicts for ssl_info

        SSLScan protocol line forms vary by version:
          "SSLv2     disabled"
          "TLSv1.0   enabled"
          "TLSv1.3   not supported"   (some older sslscan builds)
        """
        findings: list[ParsedFinding] = []
        inventory: list[dict] = []

        for m in _PROTOCOL_RE.finditer(content):
            proto_raw  = m.group(1)              # e.g. "TLSv1.2"
            status_raw = m.group(2).lower()       # e.g. "enabled", "disabled"

            proto_key = proto_raw.lower()         # normalize for dict lookup
            is_enabled = status_raw in ("enabled", "accepted", "preferred")

            inventory.append({
                "protocol": proto_raw,
                "enabled":  is_enabled,
                "raw":      m.group(0).strip(),
            })

            if is_enabled:
                if proto_key in _WEAK_PROTOCOLS:
                    severity, label = _WEAK_PROTOCOLS[proto_key]
                    findings.append(build_finding(
                        "WEAK_TLS",
                        target, port=port, protocol="tcp", service="ssl",
                        version=label, evidence=m.group(0).strip(),
                        source_tool=self.tool_type.value, severity=severity,
                    ))

                elif proto_key in _STRONG_PROTOCOLS:
                    label = _STRONG_PROTOCOLS[proto_key]
                    findings.append(build_finding(
                        "TLS_ENABLED",
                        target, port=port, protocol="tcp", service="ssl",
                        version=label, evidence=m.group(0).strip(),
                        source_tool=self.tool_type.value,
                    ))

        if not inventory:
            self._add_error_to_list(findings, target, "No protocol lines found in SSLScan output")

        return findings, inventory

    # =========================================================================
    # Cipher suite parsing
    # =========================================================================

    def _parse_ciphers(
        self,
        content: str,
        target: str,
        port: int,
    ) -> tuple[list[ParsedFinding], list[dict]]:
        """
        Parse accepted cipher suite lines and flag weak ciphers.

        Returns:
          findings  — one WEAK_CIPHER finding per weak cipher suite accepted
          inventory — full list of accepted cipher suite dicts for ssl_info

        SSLScan cipher line format:
          "Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384"
          "Preferred TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384"

        One finding per weak cipher (not one per protocol-cipher pair) keeps
        the finding list usable. The raw_evidence field records the full line.
        """
        findings:  list[ParsedFinding] = []
        inventory: list[dict]          = []

        seen_weak: set[str] = set()   # dedup: one finding per cipher name

        for m in _CIPHER_RE.finditer(content):
            status      = m.group(1)   # "Accepted" or "Preferred"
            tls_version = m.group(2)   # e.g. "TLSv1.2"
            bits        = int(m.group(3))
            cipher_name = m.group(4)   # e.g. "ECDHE-RSA-AES256-GCM-SHA384"

            entry = {
                "status":      status,
                "protocol":    tls_version,
                "bits":        bits,
                "cipher":      cipher_name,
                "weak":        _is_weak_cipher(cipher_name),
                "raw":         m.group(0).strip(),
            }
            inventory.append(entry)

            if entry["weak"] and cipher_name not in seen_weak:
                seen_weak.add(cipher_name)
                severity = "HIGH" if bits < 128 else "MEDIUM"
                findings.append(build_finding(
                    "WEAK_CIPHER",
                    target, port=port, protocol="tcp", service="ssl",
                    version=cipher_name,
                    evidence=m.group(0).strip(),
                    source_tool=self.tool_type.value, severity=severity,
                ))

        return findings, inventory

    # =========================================================================
    # Certificate block parsing
    # =========================================================================

    def _parse_certificate(
        self,
        content: str,
        target: str,
        port: int,
    ) -> tuple[dict, list[ParsedFinding]]:
        """
        Locate and parse the "SSL Certificate:" block.

        Returns:
          cert_info — dict of certificate metadata for ssl_info["certificate"]
          findings  — SELF_SIGNED_CERT and/or EXPIRED_CERT findings if applicable

        The certificate block is terminated when a line with no leading
        indentation is encountered (indicating a new SSLScan section has begun)
        or at end-of-file. Field extraction is line-by-line regex.
        """
        cert_info: dict = {}
        findings:  list[ParsedFinding] = []

        # Locate the certificate block
        cert_start = _CERT_BLOCK_RE.search(content)
        if not cert_start:
            log.debug("SslscanParser: no 'SSL Certificate:' block found in %s", target)
            return cert_info, findings

        block_text = content[cert_start.start():]

        # Extract certificate fields
        for regex, key in (
            (_CERT_SUBJECT_RE,   "subject"),
            (_CERT_ISSUER_RE,    "issuer"),
            (_CERT_EXPIRY_RE,    "not_after"),
            (_CERT_NOTBEFORE_RE, "not_before"),
            (_CERT_SELFSIGN_RE,  "self_signed"),
            (_CERT_ALG_RE,       "signature_algorithm"),
            (_CERT_KEYSIZE_RE,   "rsa_key_bits"),
        ):
            m = regex.search(block_text)
            if m:
                cert_info[key] = m.group(1).strip()

        # Reporter-facing aliases. The SSL/TLS report block reads cert["key_size"]
        # and cert["sig_algorithm"]; expose those names too (additive — the
        # original keys are preserved for any other consumer).
        if cert_info.get("rsa_key_bits"):
            cert_info.setdefault("key_size", cert_info["rsa_key_bits"])
        if cert_info.get("signature_algorithm"):
            cert_info.setdefault("sig_algorithm", cert_info["signature_algorithm"])

        # ── Self-signed detection ─────────────────────────────────────────
        self_signed_raw = cert_info.get("self_signed", "").lower()
        if self_signed_raw in ("true", "yes", "1"):
            cert_info["self_signed"] = True
            findings.append(build_finding(
                "SELF_SIGNED_CERT",
                target, port=port, protocol="tcp", service="ssl",
                evidence=f"Self Signed: {self_signed_raw}",
                source_tool=self.tool_type.value,
            ))
        else:
            # Normalize to boolean False for non-self-signed certificates
            cert_info["self_signed"] = False

        # ── Subject == Issuer heuristic (older sslscan without Self Signed field) ──
        # If the "Self Signed" field was absent but Subject == Issuer, flag it.
        if not cert_info.get("self_signed") and \
           cert_info.get("subject") and cert_info.get("issuer"):
            subj = cert_info["subject"].lower()
            iss  = cert_info["issuer"].lower()
            if subj == iss and "SELF_SIGNED_CERT" not in {f.finding_type for f in findings}:
                cert_info["self_signed"] = True
                findings.append(build_finding(
                    "SELF_SIGNED_CERT",
                    target, port=port, protocol="tcp", service="ssl",
                    evidence=(f"Subject: {cert_info['subject']} | "
                              f"Issuer: {cert_info['issuer']} (Subject equals Issuer)"),
                    source_tool=self.tool_type.value,
                ))

        # ── Short RSA key detection ───────────────────────────────────────
        # Conservative: only RSA keys, only when a numeric strength was parsed.
        bits_raw = cert_info.get("rsa_key_bits")
        if bits_raw:
            try:
                bits = int(bits_raw)
            except (TypeError, ValueError):
                bits = 0
            is_short, _reason = is_short_rsa_key(bits)
            if is_short:
                severity = "HIGH" if bits < 1024 else "MEDIUM"
                findings.append(build_finding(
                    "SHORT_KEY_LENGTH",
                    target, port=port, protocol="tcp", service="ssl",
                    version=f"{bits}-bit RSA",
                    evidence=f"RSA Key Strength: {bits}",
                    source_tool=self.tool_type.value, severity=severity,
                ))

        # ── Expiry detection ──────────────────────────────────────────────
        expiry_str = cert_info.get("not_after", "")
        if expiry_str:
            expiry_dt = _parse_cert_date(expiry_str)
            cert_info["not_after_parsed"] = expiry_dt.isoformat() if expiry_dt else None
            if expiry_dt is not None:
                now = datetime.now(timezone.utc)
                # Make expiry_dt timezone-aware for comparison
                if expiry_dt.tzinfo is None:
                    expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                if expiry_dt < now:
                    findings.append(build_finding(
                        "EXPIRED_CERT",
                        target, port=port, protocol="tcp", service="ssl",
                        version=f"expired {expiry_str}",
                        evidence=f"Not valid after: {expiry_str}",
                        source_tool=self.tool_type.value,
                    ))

        return cert_info, findings

    # =========================================================================
    # Private helper
    # =========================================================================

    @staticmethod
    def _add_error_to_list(findings: list, target: str, message: str) -> None:
        """
        Add a parse note as an INFO finding when a section is missing.
        Only used internally — not a real security finding.
        Used conservatively to avoid polluting the finding list.
        """
        # We do NOT add a ParsedFinding for parse errors — that belongs
        # in result.parse_errors. This method is a no-op placeholder in
        # case future phases need section-level diagnostic findings.
        pass


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _parse_cert_date(date_str: str) -> Optional[datetime]:
    """
    Attempt to parse a certificate date string using known SSLScan date formats.

    Returns a datetime object (naïve or aware) on success, None on failure.
    Tries multiple format strings because SSLScan versions differ in output format.
    """
    date_str = date_str.strip()
    # Normalize "GMT" → "UTC" for %Z compatibility on some platforms
    normalized = date_str.replace("GMT", "UTC")

    for fmt in _CERT_DATE_FORMATS:
        try:
            dt = datetime.strptime(normalized, fmt)
            return dt
        except ValueError:
            continue

    log.debug("SslscanParser: could not parse certificate date: %r", date_str)
    return None


_IPV4_SIMPLE_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _looks_like_ip(value: str) -> bool:
    """Return True if value is a plausible IPv4 address string."""
    return bool(_IPV4_SIMPLE_RE.match(value.strip()))


def _looks_like_hostname(value: str) -> bool:
    """Return True if value is likely a hostname (contains a dot and non-digits)."""
    return "." in value and not _looks_like_ip(value)


# ---------------------------------------------------------------------------
# Registration — runs at module import time.
# Mirrors the pattern used by NmapParser and HttpxParser.
# ---------------------------------------------------------------------------

register(SslscanParser())
log.debug("SslscanParser registered for ToolType.SSLSCAN")
