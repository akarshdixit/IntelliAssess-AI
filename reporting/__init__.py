"""
reporting/__init__.py
======================
DOCX report generation package for IntelliAssess AI — Phase 4-2.

Public API surface for the reporting/ sub-package.

Importing from this package:
    from reporting import generate_docx
    from reporting.reporter import DocxReporter  # for testing / extension

Phase 4-2: DOCX report generation.
  - templates.py  — formatting constants, style helpers, cell utilities
  - reporter.py   — DocxReporter class + generate_docx() entry point

Phase 4-3 integration:
  session_manager.py will call:
    from reporting import generate_docx
    report_path = generate_docx(parsed_data_list, enriched_report, session, output_path)

The generate_docx() function below is the SINGLE stable API boundary between
the reporting layer and the session management layer. Internals of reporting/
can be refactored freely as long as this function signature is preserved.

Design notes:
  - This package has NO dependency on the AI layer (ai/).
  - It does NOT call Gemini or any external API.
  - It is a pure consumer of EnrichedReport and ParsedScanData.
  - All OOXML manipulation is isolated in reporting/templates.py.
"""

from reporting.reporter import generate_docx, DocxReporter

__all__ = [
    # Primary entry point for Phase 4-3 session_manager integration
    "generate_docx",
    # Class exposed for testing and future extension
    "DocxReporter",
]
