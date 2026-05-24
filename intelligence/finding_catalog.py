"""
intelligence/finding_catalog.py
================================
Centralized deterministic finding taxonomy + factory for IntelliAssess AI.

Responsibility: own the SINGLE standardized definition of every finding type
the platform can produce, and the SINGLE construction path that turns raw
scan evidence into a fully-populated, schema-consistent ParsedFinding.

Why this exists (architecture rationale):
  The platform is following an evolutionary path:
    Option A (now)   — findings are generated inside parsers, for fast iteration.
    Option C (later) — finding generation migrates into intelligence/findings_engine.py.
  To make that future migration mechanical rather than a rewrite, ALL findings
  — regardless of which parser emits them — must already share one standardized
  schema, one taxonomy of stable IDs, one severity vocabulary, one remediation
  structure, and one compliance-reference source. This module is that single
  source of truth. Parsers call build_finding(); they never hand-roll finding
  dicts or invent ad-hoc finding_type strings.

What this module is NOT:
  - NOT a rule engine, DSL, or plugin framework.
  - NOT a CVE database or scoring engine.
  - NOT AI-aware. Gemini enrichment wraps these findings; it never produces them.
  - NOT a sector-risk engine (contextual severity uplift stays in risk_adjustment.py).

Design contract:
  - build_finding() NEVER raises. Unknown finding types degrade to a generic
    but valid ParsedFinding so a parser bug can never abort ingestion.
  - Every produced ParsedFinding carries: finding_id, finding_type, title,
    severity_hint, target, detail (technical description), remediation,
    compliance_refs, raw_evidence, source_tool, and (where relevant) confidence.
  - Compliance references are pulled live from intelligence.compliance, so the
    two modules can evolve independently and never drift.

Supported finding types:
  Network / host (Nmap):
    OPEN_PORT, SERVICE_VERSION_DISCLOSURE, OUTDATED_SERVICE, TELNET_EXPOSED,
    FTP_EXPOSED, SMBV1_ENABLED, HTTP_ONLY, HTTPS_MISSING, EOL_OPERATING_SYSTEM
  Web layer (HTTPX) — Phase 1B-A:
    VERSION_DISCLOSURE, MISSING_HSTS, MISSING_CSP, MISSING_X_FRAME_OPTIONS,
    MISSING_X_CONTENT_TYPE_OPTIONS, MISSING_REFERRER_POLICY,
    MISSING_PERMISSIONS_POLICY
  TLS layer (SSLScan) — Phase 1B-A:
    WEAK_TLS, WEAK_CIPHER, EXPIRED_CERT, SELF_SIGNED_CERT, SHORT_KEY_LENGTH,
    TLS_ENABLED (positive/INFO)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from intelligence.compliance import get_compliance_refs
from parsers.models import ParsedFinding
from utils.logger import get_logger

log = get_logger(__name__)

# Canonical severity vocabulary (ordered most→least severe). The reporter and
# risk_adjustment.py share this vocabulary; the catalog never invents others.
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


# ---------------------------------------------------------------------------
# FindingTemplate — the standardized definition of one finding type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FindingTemplate:
    """
    Immutable definition of a finding type.

    finding_id    : stable catalog identifier, distinct from finding_type,
                    suitable for report/audit cross-referencing (e.g. "IAA-WEB-001").
    finding_type  : machine key used for correlation and compliance lookup.
    title         : short human title shown in the report.
    base_severity : default severity_hint before any contextual adjustment.
    description   : technical description template. May contain {placeholders}
                    that build_finding() fills from the supplied context
                    (target, port, service, version).
    remediation   : deterministic baseline remediation guidance (offline-safe).
    """
    finding_id:    str
    finding_type:  str
    title:         str
    base_severity: str
    description:   str
    remediation:   str


# ---------------------------------------------------------------------------
# The catalog — one entry per finding type, keyed by finding_type
# ---------------------------------------------------------------------------

_CATALOG: dict[str, FindingTemplate] = {

    "OPEN_PORT": FindingTemplate(
        finding_id=    "IAA-NET-001",
        finding_type=  "OPEN_PORT",
        title=         "Open Network Port",
        base_severity= "INFO",
        description=   ("Port {port}/{protocol} is open on {target} "
                        "({service}). Each reachable port expands the attack "
                        "surface and should correspond to a documented, "
                        "required business service."),
        remediation=   ("Confirm this port supports a required service. If it "
                        "is not needed, close it at the host firewall or "
                        "security group. Restrict source ranges to known "
                        "administrative or client networks where feasible."),
    ),

    "HTTP_ONLY": FindingTemplate(
        finding_id=    "IAA-WEB-001",
        finding_type=  "HTTP_ONLY",
        title=         "Cleartext HTTP Service Exposed",
        base_severity= "MEDIUM",
        description=   ("{target} serves content over plaintext HTTP on port "
                        "{port}. Traffic on this channel — including any "
                        "credentials, session tokens, or form data — is "
                        "transmitted unencrypted and can be intercepted or "
                        "modified by a network-positioned attacker."),
        remediation=   ("Redirect all HTTP traffic to HTTPS (301), enforce "
                        "HSTS, and ensure no sensitive functionality is "
                        "reachable over the cleartext channel."),
    ),

    "HTTPS_MISSING": FindingTemplate(
        finding_id=    "IAA-WEB-002",
        finding_type=  "HTTPS_MISSING",
        title=         "No TLS/HTTPS Service Available",
        base_severity= "HIGH",
        description=   ("{target} exposes HTTP on port {port} but offers no "
                        "TLS/HTTPS service. All communication with this host "
                        "is therefore unencrypted, with no option for a secure "
                        "channel."),
        remediation=   ("Provision a valid TLS certificate and serve the "
                        "application over HTTPS (port 443). Redirect HTTP to "
                        "HTTPS and enable HSTS once TLS is confirmed working."),
    ),

    "SERVICE_VERSION_DISCLOSURE": FindingTemplate(
        finding_id=    "IAA-INF-001",
        finding_type=  "SERVICE_VERSION_DISCLOSURE",
        title=         "Service Version Disclosure",
        base_severity= "LOW",
        description=   ("The service on port {port} of {target} discloses its "
                        "product and version in its banner ({version}). "
                        "Precise version information helps an attacker map the "
                        "host to known vulnerabilities and tailor exploits."),
        remediation=   ("Where the service permits, suppress or genericize "
                        "version banners (e.g. server_tokens off for nginx, "
                        "ServerTokens Prod for Apache). Treat banner "
                        "suppression as defense-in-depth, not a substitute for "
                        "patching."),
    ),

    "OUTDATED_SERVICE": FindingTemplate(
        finding_id=    "IAA-INF-002",
        finding_type=  "OUTDATED_SERVICE",
        title=         "Outdated Service Version",
        base_severity= "HIGH",
        description=   ("The service on port {port} of {target} reports an "
                        "outdated version ({version}). {reason} Outdated "
                        "software frequently carries publicly known "
                        "vulnerabilities."),
        remediation=   ("Upgrade the affected service to a current, vendor-"
                        "supported release and establish a recurring patch "
                        "cycle. Validate the running version after patching."),
    ),

    "TELNET_EXPOSED": FindingTemplate(
        finding_id=    "IAA-NET-002",
        finding_type=  "TELNET_EXPOSED",
        title=         "Telnet Service Exposed (Cleartext Administration)",
        base_severity= "HIGH",
        description=   ("Telnet is exposed on port {port} of {target}. Telnet "
                        "transmits credentials and session data in cleartext, "
                        "allowing trivial interception of administrative "
                        "access by any network-positioned attacker."),
        remediation=   ("Disable Telnet and replace it with SSH for remote "
                        "administration. Block port 23 at the perimeter and "
                        "verify no automation depends on Telnet."),
    ),

    "FTP_EXPOSED": FindingTemplate(
        finding_id=    "IAA-NET-003",
        finding_type=  "FTP_EXPOSED",
        title=         "FTP Service Exposed (Cleartext File Transfer)",
        base_severity= "MEDIUM",
        description=   ("FTP is exposed on port {port} of {target}. Standard "
                        "FTP transmits credentials and file contents in "
                        "cleartext and often permits anonymous or weakly "
                        "authenticated access."),
        remediation=   ("Replace FTP with SFTP or FTPS. If file transfer is "
                        "not required, disable the service and close port 21. "
                        "Verify anonymous access is not enabled."),
    ),

    "SMBV1_ENABLED": FindingTemplate(
        finding_id=    "IAA-NET-004",
        finding_type=  "SMBV1_ENABLED",
        title=         "SMBv1 Protocol Enabled",
        base_severity= "HIGH",
        description=   ("SMB is exposed on port {port} of {target} with "
                        "indicators of the deprecated SMBv1 protocol. SMBv1 is "
                        "the attack surface exploited by EternalBlue / "
                        "WannaCry-class threats and is unsupported by modern "
                        "vendors."),
        remediation=   ("Disable SMBv1 entirely and require SMBv2/SMBv3. "
                        "Restrict SMB (port 445) to internal management "
                        "networks and never expose it to untrusted networks."),
    ),

    "WEAK_TLS": FindingTemplate(
        finding_id=    "IAA-TLS-001",
        finding_type=  "WEAK_TLS",
        title=         "Weak or Deprecated TLS Configuration",
        base_severity= "HIGH",
        description=   ("{target} negotiates a weak or deprecated TLS "
                        "configuration on port {port} ({version}). Deprecated "
                        "protocol versions and weak cipher suites undermine the "
                        "confidentiality and integrity of all traffic."),
        remediation=   ("Disable TLS 1.0/1.1 and weak cipher suites. Offer "
                        "only TLS 1.2+ with strong, forward-secret ciphers. "
                        "Re-test the configuration after changes."),
    ),

    "EXPIRED_CERT": FindingTemplate(
        finding_id=    "IAA-TLS-002",
        finding_type=  "EXPIRED_CERT",
        title=         "Expired TLS Certificate",
        base_severity= "HIGH",
        description=   ("The TLS certificate presented by {target} on port "
                        "{port} is expired ({version}). Clients receive trust "
                        "errors, and expiry may indicate lapsed certificate "
                        "lifecycle management."),
        remediation=   ("Renew and deploy a valid certificate from a trusted "
                        "CA, and automate renewal (e.g. ACME) to prevent "
                        "recurrence."),
    ),

    "SELF_SIGNED_CERT": FindingTemplate(
        finding_id=    "IAA-TLS-003",
        finding_type=  "SELF_SIGNED_CERT",
        title=         "Self-Signed TLS Certificate",
        base_severity= "MEDIUM",
        description=   ("{target} presents a self-signed TLS certificate on "
                        "port {port}. Self-signed certificates are not trusted "
                        "by clients and provide no protection against "
                        "man-in-the-middle attacks via certificate "
                        "substitution."),
        remediation=   ("Replace the self-signed certificate with one issued "
                        "by a trusted public or enterprise CA. Reserve "
                        "self-signed certificates for isolated internal use "
                        "with explicit trust pinning."),
    ),

    "EOL_OPERATING_SYSTEM": FindingTemplate(
        finding_id=    "IAA-OS-001",
        finding_type=  "EOL_OPERATING_SYSTEM",
        title=         "End-of-Life Operating System",
        base_severity= "HIGH",
        description=   ("{target} appears to run an end-of-life operating "
                        "system ({version}). {reason} EOL systems no longer "
                        "receive security updates, leaving known "
                        "vulnerabilities permanently unpatched."),
        remediation=   ("Migrate the workload to a vendor-supported operating "
                        "system release. Where immediate migration is not "
                        "possible, isolate the host and apply compensating "
                        "network controls."),
    ),

    # =======================================================================
    # Web-layer findings (HTTPX parser) — Phase 1B-A
    # =======================================================================

    "VERSION_DISCLOSURE": FindingTemplate(
        finding_id=    "IAA-WEB-003",
        finding_type=  "VERSION_DISCLOSURE",
        title=         "Web Server Version Disclosure",
        base_severity= "LOW",
        description=   ("The web server on port {port} of {target} discloses "
                        "its product and version in the Server response header "
                        "({version}). Precise version information lets an "
                        "attacker map the host to publicly known "
                        "vulnerabilities and prioritise exploitation."),
        remediation=   ("Suppress or genericise the Server banner (e.g. "
                        "server_tokens off in nginx, ServerTokens Prod and "
                        "ServerSignature Off in Apache). Treat banner "
                        "suppression as defense-in-depth, not a substitute for "
                        "keeping the server patched."),
    ),

    "MISSING_HSTS": FindingTemplate(
        finding_id=    "IAA-WEB-004",
        finding_type=  "MISSING_HSTS",
        title=         "Missing HTTP Strict Transport Security (HSTS)",
        base_severity= "MEDIUM",
        description=   ("The HTTPS service on port {port} of {target} does not "
                        "return a Strict-Transport-Security response header. "
                        "Without HSTS, a network-positioned attacker can "
                        "downgrade the initial connection to cleartext HTTP "
                        "(SSL-stripping) before the redirect to HTTPS takes "
                        "effect."),
        remediation=   ("Return a Strict-Transport-Security header on all HTTPS "
                        "responses (e.g. max-age=31536000; includeSubDomains). "
                        "Confirm every endpoint is reachable over HTTPS before "
                        "enabling, and consider HSTS preload once stable."),
    ),

    "MISSING_CSP": FindingTemplate(
        finding_id=    "IAA-WEB-005",
        finding_type=  "MISSING_CSP",
        title=         "Missing Content-Security-Policy Header",
        base_severity= "MEDIUM",
        description=   ("The web service on port {port} of {target} does not "
                        "return a Content-Security-Policy header. A CSP is a "
                        "primary defence-in-depth control against cross-site "
                        "scripting (XSS) and content-injection by constraining "
                        "the origins from which scripts and other resources "
                        "may load."),
        remediation=   ("Define and deploy a Content-Security-Policy tuned to "
                        "the application's resource origins. Begin in "
                        "Content-Security-Policy-Report-Only mode to validate "
                        "the policy against real traffic before enforcing it."),
    ),

    "MISSING_X_FRAME_OPTIONS": FindingTemplate(
        finding_id=    "IAA-WEB-006",
        finding_type=  "MISSING_X_FRAME_OPTIONS",
        title=         "Missing Clickjacking Protection (X-Frame-Options)",
        base_severity= "MEDIUM",
        description=   ("The web service on port {port} of {target} does not "
                        "return an X-Frame-Options header (or an equivalent "
                        "frame-ancestors Content-Security-Policy directive). "
                        "The application can therefore be embedded in a "
                        "hostile frame and used to mount clickjacking attacks."),
        remediation=   ("Return X-Frame-Options: DENY (or SAMEORIGIN where "
                        "framing is required) on all responses, and/or set a "
                        "Content-Security-Policy frame-ancestors directive, "
                        "which supersedes X-Frame-Options on modern browsers."),
    ),

    "MISSING_X_CONTENT_TYPE_OPTIONS": FindingTemplate(
        finding_id=    "IAA-WEB-007",
        finding_type=  "MISSING_X_CONTENT_TYPE_OPTIONS",
        title=         "Missing MIME-Sniffing Protection (X-Content-Type-Options)",
        base_severity= "LOW",
        description=   ("The web service on port {port} of {target} does not "
                        "return X-Content-Type-Options: nosniff. Browsers may "
                        "therefore MIME-sniff responses and interpret content "
                        "as a type other than the one declared, which can "
                        "facilitate cross-site scripting in some scenarios."),
        remediation=   ("Return X-Content-Type-Options: nosniff on all "
                        "responses and ensure resources are served with "
                        "correct, explicit Content-Type headers."),
    ),

    "MISSING_REFERRER_POLICY": FindingTemplate(
        finding_id=    "IAA-WEB-008",
        finding_type=  "MISSING_REFERRER_POLICY",
        title=         "Missing Referrer-Policy Header",
        base_severity= "LOW",
        description=   ("The web service on port {port} of {target} does not "
                        "return a Referrer-Policy header. Without it, the "
                        "browser may leak full request URLs — potentially "
                        "containing tokens or identifiers — to third-party "
                        "destinations via the Referer header."),
        remediation=   ("Set a restrictive Referrer-Policy such as "
                        "strict-origin-when-cross-origin (or no-referrer for "
                        "sensitive applications) on all responses."),
    ),

    "MISSING_PERMISSIONS_POLICY": FindingTemplate(
        finding_id=    "IAA-WEB-009",
        finding_type=  "MISSING_PERMISSIONS_POLICY",
        title=         "Missing Permissions-Policy Header",
        base_severity= "LOW",
        description=   ("The web service on port {port} of {target} does not "
                        "return a Permissions-Policy header. This header lets "
                        "the application explicitly disable powerful browser "
                        "features (camera, microphone, geolocation, etc.), "
                        "reducing the impact of a successful content "
                        "injection."),
        remediation=   ("Define a Permissions-Policy that disables browser "
                        "features the application does not use (e.g. "
                        "geolocation=(), camera=(), microphone=())."),
    ),

    # =======================================================================
    # TLS-layer findings (SSLScan parser) — Phase 1B-A
    # =======================================================================

    "WEAK_CIPHER": FindingTemplate(
        finding_id=    "IAA-TLS-004",
        finding_type=  "WEAK_CIPHER",
        title=         "Weak or Broken TLS Cipher Suite Accepted",
        base_severity= "MEDIUM",
        description=   ("The TLS service on port {port} of {target} accepts a "
                        "weak or broken cipher suite ({version}). Such suites "
                        "rely on deprecated algorithms (e.g. RC4, DES/3DES, "
                        "EXPORT, NULL or anonymous key exchange) and undermine "
                        "the confidentiality or integrity of the encrypted "
                        "channel."),
        remediation=   ("Disable all weak and legacy cipher suites and offer "
                        "only strong, forward-secret suites (e.g. "
                        "ECDHE-based AEAD ciphers). Re-test the configuration "
                        "after the change to confirm the weak suites are no "
                        "longer negotiable."),
    ),

    "SHORT_KEY_LENGTH": FindingTemplate(
        finding_id=    "IAA-TLS-005",
        finding_type=  "SHORT_KEY_LENGTH",
        title=         "Short TLS Certificate Key Length",
        base_severity= "MEDIUM",
        description=   ("The TLS certificate presented on port {port} of "
                        "{target} uses a short public key ({version}). Keys "
                        "below 2048-bit RSA no longer provide an adequate "
                        "security margin and are rejected by current browser "
                        "and CA baseline requirements."),
        remediation=   ("Re-issue the certificate with at least a 2048-bit RSA "
                        "key (or a 256-bit elliptic-curve key) from a trusted "
                        "CA, and retire the weak key once the replacement is "
                        "deployed."),
    ),

    # ── Positive / informational control confirmations ─────────────────────

    "TLS_ENABLED": FindingTemplate(
        finding_id=    "IAA-TLS-100",
        finding_type=  "TLS_ENABLED",
        title=         "Modern TLS Protocol Supported",
        base_severity= "INFO",
        description=   ("{target} supports the modern TLS protocol {version} "
                        "on port {port}. This is a positive security control "
                        "and is recorded for assurance context."),
        remediation=   ("No action required. Maintain support for current TLS "
                        "versions and continue to retire deprecated protocols "
                        "as clients allow."),
    ),
}


# ---------------------------------------------------------------------------
# Generic fallback template — used only for unknown finding types
# ---------------------------------------------------------------------------

_GENERIC = FindingTemplate(
    finding_id=    "IAA-GEN-000",
    finding_type=  "GENERIC_FINDING",
    title=         "Security Observation",
    base_severity= "INFO",
    description=   ("A security-relevant observation was recorded for "
                    "{target} on port {port}."),
    remediation=   ("Review this observation against your security baseline "
                    "and remediate if it represents unintended exposure."),
)


# ---------------------------------------------------------------------------
# Lightweight deterministic knowledge — EOL OS + outdated service heuristics
# ---------------------------------------------------------------------------
# Conservative by design: a false positive erodes trust faster than a missed
# finding. Patterns match only clearly end-of-life / clearly outdated signals.

# (regex, human reason) — matched case-insensitively against the OS string.
_EOL_OS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bwindows\s+(xp|2000|2003|2008|vista|7|8(?:\.1)?)\b", re.I),
     "This Windows release has passed Microsoft end-of-support."),
    (re.compile(r"\blinux\s+2\.[0-6]\b", re.I),
     "Linux 2.x kernels are long past end-of-life."),
    (re.compile(r"\blinux\s+3\.\d+\b", re.I),
     "Linux 3.x kernels are end-of-life and no longer maintained."),
    (re.compile(r"\bcentos\s+([5-7])\b", re.I),
     "This CentOS release has reached end-of-life."),
    (re.compile(r"\bubuntu\s+(1[0-6])\.\d+\b", re.I),
     "This Ubuntu release has passed end-of-standard-support."),
]

# (service substring, version regex, human reason). Only flags clearly old
# major versions of common services. Empty matches default to "not outdated".
_OUTDATED_SERVICE_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("apache", re.compile(r"\b2\.[02]\.", re.I),
     "Apache 2.0/2.2 are no longer supported."),
    ("openssh", re.compile(r"\b[1-6]\.", re.I),
     "OpenSSH releases below 7.x are obsolete."),
    ("nginx",  re.compile(r"\b0\.|1\.[0-9]\.", re.I),
     "nginx releases below 1.10 are obsolete."),
    ("vsftpd", re.compile(r"\b2\.3\.4\b", re.I),
     "vsftpd 2.3.4 shipped with a known backdoor."),
    ("proftpd", re.compile(r"\b1\.3\.[0-3]\b", re.I),
     "These ProFTPD releases carry known remote vulnerabilities."),
    ("php",    re.compile(r"\b[45]\.|7\.[0-3]\b", re.I),
     "These PHP releases are end-of-life."),
]


def is_eol_os(os_name: Optional[str]) -> tuple[bool, str]:
    """Return (is_eol, reason). Conservative: unknown/empty → (False, '')."""
    if not os_name:
        return False, ""
    for pattern, reason in _EOL_OS_PATTERNS:
        if pattern.search(os_name):
            return True, reason
    return False, ""


def is_short_rsa_key(bits: Optional[int]) -> tuple[bool, str]:
    """
    Return (is_short, reason) for an RSA public-key length in bits.

    Conservative by design:
      - bits < 1024  → short, HIGH-impact reason
      - bits < 2048  → short, MEDIUM-impact reason
      - bits >= 2048 → not short
      - unknown/None / unparsable → (False, '')

    The caller decides the finding severity from the returned reason; this
    helper only classifies. Elliptic-curve keys are intentionally not flagged
    here — EC key-strength assessment requires curve-aware logic and is
    deferred to avoid false positives on modern short EC keys.
    """
    try:
        b = int(bits)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False, ""
    if b <= 0:
        return False, ""
    if b < 1024:
        return True, f"A {b}-bit RSA key is critically weak and trivially factorable by modern standards."
    if b < 2048:
        return True, f"A {b}-bit RSA key is below the 2048-bit baseline mandated by current CA/Browser Forum requirements."
    return False, ""


def is_outdated_service(service_name: Optional[str],
                        version: Optional[str]) -> tuple[bool, str]:
    """
    Return (is_outdated, reason) for a service banner.

    Conservative: only flags when BOTH the service and a clearly-old version
    pattern match. Anything else → (False, '') to avoid false positives.
    """
    if not version:
        return False, ""
    svc = (service_name or "").lower()
    ver = version.lower()
    for svc_key, ver_pattern, reason in _OUTDATED_SERVICE_PATTERNS:
        if (svc_key in svc or svc_key in ver) and ver_pattern.search(ver):
            return True, reason
    return False, ""


# ---------------------------------------------------------------------------
# Public factory — the single standardized construction path
# ---------------------------------------------------------------------------

def build_finding(
    finding_type: str,
    target:       str,
    *,
    port:         Optional[int] = None,
    protocol:     str           = "",
    service:      str           = "",
    version:      Optional[str] = None,
    evidence:     str           = "",
    source_tool:  str           = "",
    severity:     Optional[str] = None,
    confidence:   str           = "",
    reason:       str           = "",
) -> ParsedFinding:
    """
    Construct a fully-populated, schema-consistent ParsedFinding.

    This is the ONLY supported way to create a ParsedFinding. Parsers pass the
    finding_type plus whatever context they observed; the catalog supplies the
    stable id, title, severity, technical description, remediation, and
    compliance references.

    Args:
        finding_type: A catalog key (e.g. "HTTP_ONLY"). Unknown types degrade
                      to a generic-but-valid finding (never raises).
        target:       Affected asset (hostname / IP / URL).
        port/protocol/service/version: observed context, used to fill the
                      description template and the structured fields.
        evidence:     verbatim supporting snippet (stored in raw_evidence and
                      appended to detail so it surfaces in the current report).
        source_tool:  ToolType.value of the producing parser.
        severity:     optional override of the template's base severity. Must be
                      one of SEVERITIES; ignored otherwise.
        confidence:   qualitative confidence ("high"|"medium"|"low") for
                      findings inferred from unreliable signals.
        reason:       extra clause inserted into templates that contain {reason}
                      (OUTDATED_SERVICE, EOL_OPERATING_SYSTEM).

    Returns:
        A ParsedFinding. Never None, never raises.
    """
    key = (finding_type or "").strip().upper()
    template = _CATALOG.get(key, _GENERIC)

    sev = (severity or template.base_severity or "INFO").upper()
    if sev not in SEVERITIES:
        sev = template.base_severity

    fmt = {
        "target":   target or "the host",
        "port":     port if port is not None else "?",
        "protocol": protocol or "tcp",
        "service":  service or "unknown service",
        "version":  version or "version not reported",
        "reason":   (reason + " ") if reason else "",
    }
    try:
        description = template.description.format(**fmt)
    except (KeyError, IndexError):
        # Defensive: a malformed template must never break ingestion.
        description = template.description

    detail = description
    if evidence:
        detail = f"{description} Evidence: {evidence.strip()}"

    return ParsedFinding(
        finding_type=    template.finding_type if template is _GENERIC else key,
        target=          target,
        port=            port,
        protocol=        protocol,
        service=         service,
        detail=          detail,
        severity_hint=   sev,
        raw_evidence=    evidence,
        source_tool=     source_tool,
        finding_id=      template.finding_id,
        title=           template.title,
        remediation=     template.remediation,
        compliance_refs= get_compliance_refs(key),
        confidence=      confidence,
    )


def get_template(finding_type: str) -> Optional[FindingTemplate]:
    """Return the FindingTemplate for a finding_type, or None if unknown."""
    return _CATALOG.get((finding_type or "").strip().upper())


def supported_finding_types() -> list[str]:
    """Return the sorted list of finding types defined in the catalog."""
    return sorted(_CATALOG.keys())
