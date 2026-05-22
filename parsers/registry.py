"""
intelligence/parsers/registry.py
=================================
Parser registry and dispatch — Phase 3-1.

Responsibility: maintain a registry of tool parsers and dispatch parse()
calls to the correct parser based on ToolType.

Architecture: Registry Pattern
-------------------------------
Mirrors the extractor and classifier registries for consistency across the
intelligence layer. Each parser registers itself at module load. The dispatch
function (parse_file) is the only external API needed by ingest.py.

Registry contract:
  - One parser per ToolType (re-registration overwrites the previous entry)
  - Dispatch is O(1) — dict lookup, not iteration
  - Timing is measured and stored in ParsedScanData.parse_duration_ms
  - All parse errors are returned in ParsedScanData.parse_errors (never raised)
  - Unknown/unregistered ToolType returns an empty ParsedScanData immediately

Design intentionally matches extractor registry pattern so the entire
intelligence layer is consistent:

  file_classifier.py     → classify_with_subtype(file_path) → ToolType, NmapSubtype, float
  target_extractor.py    → extract_targets(file_path, tool_type, nmap_subtype) → list[ExtractedTarget]
  parsers/registry.py    → parse_file(file_path, tool_type, nmap_subtype) → ParsedScanData

Phase 3-1 note:
  No parsers are registered at module load in this foundational phase.
  Each parser (NmapParser, HttpxParser, etc.) will import register() and
  call it at module load as they are added in Phases 3-2 through 3-5.

  The registry is fully functional as soon as this module is imported —
  it returns empty ParsedScanData for any unregistered ToolType, which is
  the correct graceful-degradation behaviour during incremental phase rollout.

ingest.py integration (Phase 3-2+):
  Once NmapParser is implemented, ingest.py will gain a parse step:

    # After extract_targets() in handle_file():
    from parsers.registry import parse_file
    parsed = parse_file(dst_path, tool_type, nmap_subtype)
    _update_session_with_parsed(session_dir, parsed)

  This remains a Phase 3-2 concern. ingest.py is NOT modified in Phase 3-1.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from intelligence.file_classifier import NmapSubtype, ToolType
from parsers.base import BaseParser, ParsedScanData, PARSER_READ_BYTES
from utils.logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Registry storage — keyed by ToolType for O(1) dispatch
# ---------------------------------------------------------------------------

# Unlike the classifier registry (a list scored in iteration order), parser
# dispatch is deterministic: exactly one parser per ToolType. Dict is correct.
_registry: dict[ToolType, BaseParser] = {}


# ---------------------------------------------------------------------------
# Registration API
# ---------------------------------------------------------------------------

def register(parser: BaseParser) -> BaseParser:
    """
    Register a parser for its declared tool_type.

    Re-registering the same ToolType overwrites the previous entry.
    This allows test environments to swap in mock parsers without patching.

    Returns the parser (allows inline use in future module-level code).

    Usage (in each parser module at module level):
        from parsers.registry import register
        register(NmapParser())

    Args:
        parser: A concrete BaseParser instance with tool_type set.

    Returns:
        The registered parser instance.
    """
    _registry[parser.tool_type] = parser
    log.debug("Parser registered: %s → %s", parser.tool_type.value, parser.__class__.__name__)
    return parser


def get_parser(tool_type: ToolType) -> Optional[BaseParser]:
    """
    Return the registered parser for tool_type, or None if not registered.

    Callers use this for diagnostics and testing. Normal dispatch should
    use parse_file() which wraps the full read + dispatch + timing pipeline.

    Args:
        tool_type: The ToolType to look up.

    Returns:
        BaseParser instance or None.
    """
    return _registry.get(tool_type)


def list_registered_parsers() -> list[str]:
    """
    Return a list of registered parser descriptions for diagnostics/logging.

    Returns:
        List of strings like "NMAP → NmapParser", "HTTPX → HttpxParser".
    """
    return [
        f"{tool_type.value} → {parser.__class__.__name__}"
        for tool_type, parser in _registry.items()
    ]


# ---------------------------------------------------------------------------
# Dispatch — the primary public API
# ---------------------------------------------------------------------------

def parse_file(
    file_path: Path,
    tool_type: ToolType,
    nmap_subtype: Optional[NmapSubtype] = None,
) -> ParsedScanData:
    """
    Dispatch a file to its registered parser and return structured scan data.

    This is the single function that ingest.py will call (Phase 3-2+).
    It owns: file reading, parser lookup, timing, error surfacing.
    It does NOT own: classification, extraction, session updates.

    Returns an empty (but valid) ParsedScanData when:
      - tool_type is UNKNOWN
      - No parser is registered for tool_type
      - The file cannot be read
      - The file is empty

    Returns a partial ParsedScanData (with parse_errors populated) when:
      - The parser raised an unexpected exception (defensive catch)
      - The parser returned partial results with non-fatal errors

    Never raises. All failure modes produce a ParsedScanData with errors logged.

    Timing: parse_duration_ms is measured from just before parse() is called
    to just after it returns. File I/O time is included.

    Args:
        file_path:    Path to the classified scan file (in processed/).
        tool_type:    ToolType identified by file_classifier.
        nmap_subtype: Nmap output format (TEXT/XML/GREPABLE/UNKNOWN).
                      Pass None (default) for non-Nmap tools.

    Returns:
        ParsedScanData — always a valid instance, never None.

    Example:
        >>> result = parse_file(Path("processed/nmap_scan.txt"),
        ...                     ToolType.NMAP, NmapSubtype.TEXT)
        >>> result.primary_target
        'cms.aptech-worldwide.com'
        >>> len(result.findings)
        3
    """
    # ── Guard: UNKNOWN tool type ───────────────────────────────────────────
    if tool_type is ToolType.UNKNOWN:
        log.debug(
            "parse_file: skipping UNKNOWN tool type for %s", file_path.name
        )
        return _empty_result_for(tool_type, nmap_subtype)

    # ── Guard: no registered parser ────────────────────────────────────────
    parser = _registry.get(tool_type)
    if parser is None:
        log.debug(
            "parse_file: no parser registered for %s — skipping %s",
            tool_type.value, file_path.name,
        )
        result = _empty_result_for(tool_type, nmap_subtype)
        result.parse_errors.append(
            f"Registry: no parser registered for {tool_type.value} "
            f"(Phase 3-1 — parsers added in Phases 3-2 through 3-5)"
        )
        return result

    # ── Read file content ──────────────────────────────────────────────────
    content = _read_content(file_path)
    if content is None:
        log.warning("parse_file: could not read file: %s", file_path)
        result = _empty_result_for(tool_type, nmap_subtype)
        result.parse_errors.append(f"Registry: could not read file: {file_path.name}")
        return result

    if not content.strip():
        log.debug("parse_file: empty file: %s", file_path.name)
        result = _empty_result_for(tool_type, nmap_subtype)
        result.parse_errors.append(f"Registry: file is empty: {file_path.name}")
        return result

    # ── Dispatch to registered parser ──────────────────────────────────────
    # Timing starts here — after the read, so file I/O is excluded from
    # the parser's own performance measurement. Adjust if you want total time.
    t_start = time.monotonic()

    try:
        result = parser.parse(content, file_path, nmap_subtype=nmap_subtype)
    except Exception as exc:
        # Defensive catch — parsers must not raise, but if they do, the
        # platform must not crash. Surface the error and return partial data.
        log.error(
            "parse_file: unexpected exception in %s.parse() for %s: %s",
            parser.__class__.__name__, file_path.name, exc,
            exc_info=True,
        )
        result = _empty_result_for(tool_type, nmap_subtype)
        result.parse_errors.append(
            f"{parser.__class__.__name__}: unexpected exception: {exc!r}"
        )

    t_end = time.monotonic()
    result.parse_duration_ms = (t_end - t_start) * 1000.0

    # ── Log result summary ─────────────────────────────────────────────────
    subtype_label = f"/{nmap_subtype.value}" if nmap_subtype else ""
    log.info(
        "parse_file: [%s%s] %s — %s",
        tool_type.value, subtype_label, file_path.name, result.summary(),
    )

    if result.has_errors:
        for err in result.parse_errors:
            log.warning("  parse_error: %s", err)

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _empty_result_for(
    tool_type: ToolType,
    nmap_subtype: Optional[NmapSubtype],
) -> ParsedScanData:
    """
    Return a blank ParsedScanData with tool_type and nmap_subtype set.

    Used for all early-exit paths (UNKNOWN tool, no parser, unreadable file).
    """
    return ParsedScanData(
        tool_type=   tool_type.value,
        nmap_subtype= nmap_subtype.value if nmap_subtype is not None else None,
    )


def _read_content(file_path: Path) -> Optional[str]:
    """
    Read up to PARSER_READ_BYTES from file_path.

    Tries UTF-8, falls back to latin-1. Returns None on OSError.
    Mirrors the read strategy in target_extractor._read_content() and
    file_classifier._read_sample() for consistency.
    """
    try:
        with file_path.open("rb") as fh:
            raw = fh.read(PARSER_READ_BYTES)
    except OSError as exc:
        log.error("_read_content: OSError reading %s: %s", file_path, exc)
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    # Normalize line endings (CRLF/CR -> LF). Windows-generated scan files use
    # CRLF; line-oriented parser regexes assume LF, so without this a CRLF file
    # silently parses to zero results. Single-point defensive normalization.
    return text.replace("\r\n", "\n").replace("\r", "\n")
