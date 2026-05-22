"""
intelligence/
=============
Lightweight deterministic intelligence layer for IntelliAssess AI — Phase 5-1.

Modules:
    compliance.py       — finding-type → compliance framework control mappings
    risk_adjustment.py  — contextual severity uplift (exposure / environment / sector)

Architecture position:
    This package sits between the enrichment layer (ai/) and the reporting layer
    (reporting/). It is consumed ONLY by reporting/reporter.py at render time.

    parsers → ParsedScanData → analyzer.py → EnrichedReport
                                                      ↓
                                          intelligence/ (consumed here, display-only)
                                                      ↓
                                            reporter.py → DOCX

Design constraints (Phase 5-1):
    - DETERMINISTIC: no AI calls, no probabilistic scoring
    - PURE:          all functions are side-effect-free
    - LIGHTWEIGHT:   dict lookups and integer arithmetic only
    - ADDITIVE:      nothing in this package mutates upstream data structures

Future phases may extend this package with:
    - correlation.py  — cross-finding pattern detection
    - cve_lookup.py   — deterministic CVE-version matching
    - scoring.py      — CVSS base score table (not dynamic calculation)
"""
