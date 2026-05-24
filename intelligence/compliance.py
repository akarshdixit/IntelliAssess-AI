"""
intelligence/compliance.py
===========================
Lightweight deterministic compliance mapping for IntelliAssess AI — Phase 5-1.

Responsibility: map known finding types to compliance framework control references.

  - NO scoring
  - NO pass/fail logic
  - NO compliance reasoning
  - NO audit determination

This module is a pure reference lookup: given a finding type, return the
list of compliance controls that are relevant. The reporter uses this output
to annotate each finding block with applicable framework references, giving
the report enterprise maturity without requiring a compliance engine.

Supported frameworks:
    PCI-DSS    — Payment Card Industry Data Security Standard v4.0
    CIS        — CIS Controls v8
    HIPAA      — Health Insurance Portability and Accountability Act (Security Rule)
    ISO27001   — ISO/IEC 27001:2022
    NIST       — NIST SP 800-53 Rev. 5 control identifiers
    SOC2       — SOC 2 Trust Services Criteria (CC series)

Usage:
    from intelligence.compliance import get_compliance_refs

    refs = get_compliance_refs("MISSING_HSTS")
    # {'PCI-DSS': ['6.4.1', '6.4.2'], 'CIS': ['9.2'], 'ISO27001': ['A.14.1.2']}

    for framework, controls in refs.items():
        print(f"{framework}: {', '.join(controls)}")

Design contract:
    get_compliance_refs() is a pure function. It never raises and always
    returns a dict (empty if the finding type is unmapped). Callers should
    treat an empty dict as "no specific compliance reference available" and
    suppress the compliance section in the report for that finding.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Compliance mapping registry
# ---------------------------------------------------------------------------
# Structure:  finding_type  →  { framework_name: [control_ref, ...] }
#
# Mapping principles:
#   - Only include controls with a traceable, documented relationship.
#   - Prefer the most specific control reference available.
#   - Do NOT speculate. If a finding has only a tenuous link to a control,
#     omit it — false precision is worse than an empty mapping.
#   - References are to the current published version of each framework.
#     PCI-DSS v4.0, CIS Controls v8, HIPAA Security Rule, ISO 27001:2022.

_COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {

    # =========================================================================
    # HTTP Security Header Findings
    # =========================================================================

    "MISSING_HSTS": {
        # HSTS (HTTP Strict Transport Security) enforces TLS for all connections.
        # PCI-DSS 4.0 Req 6.4 mandates protection of public-facing web apps.
        # CIS Control 9.2 requires secure web application configuration.
        # ISO 27001:2022 A.14.1.2 covers secure system engineering.
        "PCI-DSS":   ["6.4.1", "6.4.2"],
        "CIS":       ["9.2"],
        "ISO27001":  ["A.14.1.2"],
    },

    "MISSING_CSP": {
        # Content Security Policy reduces XSS attack surface.
        # PCI-DSS 4.0 Req 6.4.1 explicitly requires CSP on payment pages.
        "PCI-DSS":   ["6.4.1"],
        "CIS":       ["9.2"],
        "ISO27001":  ["A.14.1.2"],
    },

    "MISSING_X_FRAME_OPTIONS": {
        # X-Frame-Options prevents clickjacking attacks.
        "PCI-DSS":   ["6.4.1"],
        "CIS":       ["9.2"],
        "ISO27001":  ["A.14.1.2"],
    },

    "MISSING_X_CONTENT_TYPE_OPTIONS": {
        # X-Content-Type-Options prevents MIME sniffing attacks.
        "PCI-DSS":   ["6.4.1"],
        "CIS":       ["9.2"],
    },

    "MISSING_X_XSS_PROTECTION": {
        # X-XSS-Protection enables browser's built-in XSS filter (legacy).
        "PCI-DSS":   ["6.4.1"],
        "CIS":       ["9.2"],
    },

    "MISSING_REFERRER_POLICY": {
        # Referrer-Policy limits information leakage in HTTP Referer headers.
        "CIS":       ["9.2"],
        "ISO27001":  ["A.14.1.2"],
    },

    "MISSING_PERMISSIONS_POLICY": {
        # Permissions-Policy restricts access to browser features from web pages.
        "CIS":       ["9.2"],
        "ISO27001":  ["A.14.1.2"],
    },

    # =========================================================================
    # TLS / SSL Findings
    # =========================================================================

    "WEAK_TLS_VERSION": {
        # TLS 1.0 and 1.1 are deprecated and prohibited by all major frameworks.
        # PCI-DSS 4.0 Req 4.2.1 explicitly prohibits TLS < 1.2 for cardholder data.
        # HIPAA 164.312(e) requires encryption for ePHI in transit.
        # CIS Control 3.10 requires data encryption in transit.
        # ISO 27001:2022 A.10.1.1 requires approved cryptographic controls.
        "PCI-DSS":   ["4.2.1", "4.2.2"],
        "HIPAA":     ["164.312(e)(1)", "164.312(e)(2)(ii)"],
        "CIS":       ["3.10", "12.8"],
        "ISO27001":  ["A.10.1.1", "A.14.1.3"],
    },

    "WEAK_CIPHER": {
        # Weak cipher suites (RC4, DES, 3DES, export-grade) compromise all TLS traffic.
        # PCI-DSS 4.0 Req 4.2.1 mandates only strong cryptography.
        # HIPAA 164.312(e)(2)(ii) requires encryption mechanisms that protect ePHI.
        "PCI-DSS":   ["4.2.1"],
        "HIPAA":     ["164.312(e)(2)(ii)"],
        "CIS":       ["3.10"],
        "ISO27001":  ["A.10.1.1"],
    },

    "EXPIRED_CERTIFICATE": {
        # Expired certificates break trust chains and may indicate abandoned maintenance.
        # PCI-DSS 4.0 Req 4.2.1 requires valid certificates for TLS.
        # HIPAA 164.312(e)(1) requires transmission security for ePHI.
        "PCI-DSS":   ["4.2.1"],
        "HIPAA":     ["164.312(e)(1)"],
        "CIS":       ["3.10"],
        "ISO27001":  ["A.10.1.2"],
    },

    "SELF_SIGNED_CERTIFICATE": {
        # Self-signed certificates are not trusted by browsers and create MitM risk.
        "PCI-DSS":   ["4.2.1"],
        "CIS":       ["3.10"],
        "ISO27001":  ["A.10.1.2"],
    },

    "SHORT_KEY_LENGTH": {
        # Keys below 2048-bit (RSA) or 224-bit (EC) are cryptographically weak.
        "PCI-DSS":   ["4.2.1"],
        "HIPAA":     ["164.312(e)(2)(ii)"],
        "CIS":       ["3.10"],
        "ISO27001":  ["A.10.1.1"],
    },

    # =========================================================================
    # Network / Infrastructure Findings
    # =========================================================================

    "OPEN_PORT": {
        # Unnecessary open ports expand the attack surface.
        # PCI-DSS 4.0 Req 1.3 restricts inbound/outbound traffic.
        # CIS Control 4.4 requires disabling unused ports and services.
        # ISO 27001:2022 A.13.1.1 covers network controls.
        # NIST SP 800-53: CM-7 (least functionality), SC-7 (boundary protection).
        # SOC 2 TSC: CC6.6 (boundary protections), CC6.1 (logical access).
        "PCI-DSS":   ["1.3.1", "1.3.2"],
        "CIS":       ["4.4", "12.1"],
        "ISO27001":  ["A.13.1.1", "A.13.1.3"],
        "NIST":      ["CM-7", "SC-7"],
        "SOC2":      ["CC6.6", "CC6.1"],
    },

    "HTTP_ONLY": {
        # Serving over plain HTTP exposes all traffic to interception.
        # PCI-DSS 4.0 Req 4.2.1 and 6.4.2 require encrypted transmissions.
        # HIPAA 164.312(e)(1) mandates encryption for ePHI in transit.
        # NIST SP 800-53: SC-8 (transmission confidentiality/integrity).
        # SOC 2 TSC: CC6.7 (data in transit protection).
        "PCI-DSS":   ["4.2.1", "6.4.2"],
        "HIPAA":     ["164.312(e)(1)"],
        "CIS":       ["9.2"],
        "ISO27001":  ["A.14.1.2"],
        "NIST":      ["SC-8"],
        "SOC2":      ["CC6.7"],
    },

    "VERSION_DISCLOSURE": {
        # Disclosing web server version aids targeted exploitation.
        # PCI-DSS 4.0 Req 6.3.3 requires patching and version management.
        # CIS Control 2.2 tracks authorised software inventory.
        # ISO 27001:2022 A.12.6.1 covers management of technical vulnerabilities.
        "PCI-DSS":   ["6.3.3"],
        "CIS":       ["2.2"],
        "ISO27001":  ["A.12.6.1"],
        "NIST":      ["CM-6", "SI-2"],
        "SOC2":      ["CC7.1"],
    },

    "SERVICE_VERSION_DISCLOSURE": {
        # Network service banners leaking version strings expose patch posture.
        "PCI-DSS":   ["6.3.3"],
        "CIS":       ["2.2"],
        "ISO27001":  ["A.12.6.1"],
        "NIST":      ["CM-6", "SI-2"],
        "SOC2":      ["CC7.1"],
    },

    "OUTDATED_SERVICE": {
        # Running outdated services with known CVEs is a direct compliance violation.
        # PCI-DSS 4.0 Req 6.3 requires security patches within one month.
        # CIS Control 7.4 requires timely patching.
        "PCI-DSS":   ["6.3.1", "6.3.3"],
        "CIS":       ["2.2", "7.4"],
        "ISO27001":  ["A.12.6.1"],
        "NIST":      ["SI-2"],
        "SOC2":      ["CC7.1"],
    },

    # =========================================================================
    # Network service exposure findings (Phase A-1 — finding_catalog taxonomy)
    # =========================================================================

    "HTTPS_MISSING": {
        # No TLS/HTTPS option at all — all traffic is necessarily cleartext.
        "PCI-DSS":   ["4.2.1", "6.4.2"],
        "HIPAA":     ["164.312(e)(1)"],
        "CIS":       ["3.10", "9.2"],
        "ISO27001":  ["A.14.1.2", "A.10.1.1"],
        "NIST":      ["SC-8", "SC-13"],
        "SOC2":      ["CC6.7"],
    },

    "TELNET_EXPOSED": {
        # Telnet transmits credentials/session data in cleartext.
        # PCI-DSS 4.0 Req 2.2.7 requires strong crypto for non-console admin access.
        "PCI-DSS":   ["2.2.7", "4.2.1"],
        "HIPAA":     ["164.312(e)(1)"],
        "CIS":       ["4.4", "4.6"],
        "ISO27001":  ["A.13.1.1", "A.9.4.2"],
        "NIST":      ["AC-17", "SC-8", "CM-7"],
        "SOC2":      ["CC6.1", "CC6.6"],
    },

    "FTP_EXPOSED": {
        # Plain FTP transmits credentials and file contents in cleartext.
        "PCI-DSS":   ["2.2.7", "4.2.1"],
        "HIPAA":     ["164.312(e)(1)"],
        "CIS":       ["4.4", "3.10"],
        "ISO27001":  ["A.13.1.1", "A.10.1.1"],
        "NIST":      ["SC-8", "CM-7"],
        "SOC2":      ["CC6.7", "CC6.6"],
    },

    "SMBV1_ENABLED": {
        # SMBv1 is the EternalBlue/WannaCry attack surface; deprecated by vendors.
        "PCI-DSS":   ["2.2.4", "6.3.3"],
        "CIS":       ["4.4", "4.8"],
        "ISO27001":  ["A.12.6.1", "A.13.1.1"],
        "NIST":      ["CM-7", "SI-2"],
        "SOC2":      ["CC6.6", "CC7.1"],
    },

    # =========================================================================
    # TLS finding aliases (Phase A-1 names used by finding_catalog / parsers).
    # These mirror the canonical WEAK_TLS_VERSION / *_CERTIFICATE entries above
    # so that compliance refs resolve regardless of which name a parser emits.
    # (This also activates the SSLScan parser's existing EXPIRED_CERT /
    #  SELF_SIGNED_CERT finding types, which previously had no mapping.)
    # =========================================================================

    "WEAK_TLS": {
        "PCI-DSS":   ["4.2.1", "4.2.2"],
        "HIPAA":     ["164.312(e)(1)", "164.312(e)(2)(ii)"],
        "CIS":       ["3.10"],
        "ISO27001":  ["A.10.1.1", "A.14.1.3"],
        "NIST":      ["SC-8", "SC-13"],
        "SOC2":      ["CC6.7"],
    },

    "EXPIRED_CERT": {
        "PCI-DSS":   ["4.2.1"],
        "HIPAA":     ["164.312(e)(1)"],
        "CIS":       ["3.10"],
        "ISO27001":  ["A.10.1.2"],
        "NIST":      ["SC-12", "SC-17"],
        "SOC2":      ["CC6.7"],
    },

    "SELF_SIGNED_CERT": {
        "PCI-DSS":   ["4.2.1"],
        "CIS":       ["3.10"],
        "ISO27001":  ["A.10.1.2"],
        "NIST":      ["SC-12", "SC-17"],
        "SOC2":      ["CC6.7"],
    },

    # =========================================================================
    # Operating system findings
    # =========================================================================

    "EOL_OPERATING_SYSTEM": {
        # Unsupported OS releases never receive security updates.
        "PCI-DSS":   ["6.3.1", "6.3.3"],
        "CIS":       ["2.2", "7.4"],
        "ISO27001":  ["A.12.6.1"],
        "NIST":      ["SI-2", "CM-6"],
        "SOC2":      ["CC7.1"],
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_compliance_refs(finding_type: str) -> dict[str, list[str]]:
    """
    Return compliance framework references for a given finding type.

    Args:
        finding_type: Normalised finding type string (e.g. "MISSING_HSTS").
                      Case-insensitive.

    Returns:
        Dict mapping framework name → list of control reference strings.
        Example: {'PCI-DSS': ['6.4.1', '6.4.2'], 'CIS': ['9.2']}
        Returns empty dict {} if the finding type has no mapped controls.

    Design contract:
        Pure function. Never raises. Empty return is valid (not an error).
        Callers should treat {} as "suppress compliance section for this finding".
    """
    if not finding_type:
        return {}
    return dict(_COMPLIANCE_MAP.get(finding_type.strip().upper(), {}))


def get_supported_finding_types() -> list[str]:
    """
    Return all finding types that have at least one compliance mapping.

    Useful for diagnostics and coverage reporting.
    """
    return sorted(_COMPLIANCE_MAP.keys())


def get_frameworks() -> list[str]:
    """
    Return the set of all compliance framework names present in the registry.

    Returns a sorted list: ['CIS', 'HIPAA', 'ISO27001', 'PCI-DSS']
    """
    frameworks: set[str] = set()
    for mapping in _COMPLIANCE_MAP.values():
        frameworks.update(mapping.keys())
    return sorted(frameworks)


def get_findings_for_framework(framework: str) -> dict[str, list[str]]:
    """
    Return all findings and their control references for a specific framework.

    Args:
        framework: Framework name (e.g. "PCI-DSS"). Case-sensitive.

    Returns:
        Dict mapping finding_type → list of control references for that framework.
        Example: {'MISSING_HSTS': ['6.4.1', '6.4.2'], 'HTTP_ONLY': ['4.2.1', '6.4.2']}
        Returns empty dict if no findings map to that framework.

    Useful for future compliance-summary sections in the report.
    """
    result: dict[str, list[str]] = {}
    for finding_type, framework_map in _COMPLIANCE_MAP.items():
        if framework in framework_map:
            result[finding_type] = framework_map[framework]
    return result
