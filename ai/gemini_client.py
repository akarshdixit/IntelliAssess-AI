"""
ai/gemini_client.py
====================
Lightweight Gemini API client for IntelliAssess AI — Phase 4-1.

Responsibility: make structured requests to the Gemini API and return
raw text responses. Nothing else.

  - NO prompt construction (that is prompt_builder.py's job)
  - NO response parsing into domain objects (that is analyzer.py's job)
  - NO business logic

Design principles:
  - API key loaded from environment variable GEMINI_API_KEY.
  - Returns None on every failure — never raises to caller.
  - All failures are logged with enough context for diagnostics.
  - Timeout enforced on every request (GEMINI_TIMEOUT_S).
  - Model is configurable via GEMINI_MODEL env var with a sensible default.
  - Session-level (not request-level) client: one instance is constructed
    per analyzer run and reused across multiple calls.
  - Requests use the google-generativeai SDK (pip install google-generativeai).

Graceful-failure contract:
  complete() returns None when:
    - GEMINI_API_KEY is not set
    - Network request fails (timeout, DNS, TLS)
    - API returns an error status
    - Response content is empty
    - Any unexpected exception occurs

  Callers (analyzer.py) check for None and fall back to unenriched output.
  The platform NEVER crashes because Gemini is unavailable.

Environment variables:
  GEMINI_API_KEY   — required for real API calls (no key → stub mode)
  GEMINI_MODEL     — optional, defaults to "gemini-2.0-flash"
  GEMINI_TIMEOUT_S — optional, defaults to 30 seconds

Stub mode:
  When GEMINI_API_KEY is not set, complete() returns None immediately
  and logs a one-time INFO message. No repeated warnings per call.
  This allows the full pipeline to run in development without an API key;
  all enrichment fields will have enriched=False and fallback text.
"""

from __future__ import annotations

import os
import time
from typing import Optional

# SDK import is deferred to _get_client() so missing SDK only fails when
# a real API call is attempted, not at module import time.
# This keeps the ingestion pipeline importable in environments where
# google-generativeai is not installed.

from utils.logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration — read from environment at module load time
# ---------------------------------------------------------------------------

_API_KEY:  Optional[str] = os.environ.get("GEMINI_API_KEY")
_MODEL:    str            = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
_TIMEOUT:  float          = float(os.environ.get("GEMINI_TIMEOUT_S", "30"))

# One-time log for missing API key so we don't spam the log per call
_key_warning_emitted: bool = False

# Cached genai client — initialized on first real call
_genai_client = None
_genai_module = None


# ---------------------------------------------------------------------------
# GeminiClient
# ---------------------------------------------------------------------------

class GeminiClient:
    """
    Lightweight Gemini generative AI client.

    One instance is created per analyzer.run() call and reused for all
    Gemini requests within that enrichment session. This avoids re-initializing
    the SDK on every individual finding enrichment call.

    Usage:
        client = GeminiClient()
        response = client.complete("Explain this finding: ...")
        if response is None:
            # Gemini unavailable — use fallback
            pass

    The instance is stateless between complete() calls — it carries only
    the model reference and configuration. Safe to reuse across threads if
    needed in future async phases.
    """

    def __init__(self) -> None:
        self._model_name  = _MODEL
        self._timeout     = _TIMEOUT
        self._model       = None   # lazy-initialized on first complete() call
        self._available   = False  # set to True only after successful init

    def initialize(self) -> bool:
        """
        Initialize the Gemini SDK and validate the API key.

        Called once before the first complete() call. Subsequent complete()
        calls skip re-initialization. Returns True if the client is ready,
        False if initialization failed (key missing, SDK not installed, etc.).

        Not called in __init__ so that a GeminiClient can be constructed
        without side effects even in environments where the SDK is absent.
        """
        global _key_warning_emitted

        if self._available:
            return True   # Already initialized

        if not _API_KEY:
            if not _key_warning_emitted:
                log.info(
                    "GeminiClient: GEMINI_API_KEY not set. "
                    "Running in stub mode — all enrichment will use fallbacks. "
                    "Set GEMINI_API_KEY to enable AI enrichment."
                )
                _key_warning_emitted = True
            return False

        # Attempt SDK import
        try:
            import google.generativeai as genai
        except ImportError:
            log.error(
                "GeminiClient: google-generativeai SDK not installed. "
                "Run: pip install google-generativeai"
            )
            return False

        # Configure SDK and create model reference
        try:
            genai.configure(api_key=_API_KEY)
            self._model    = genai.GenerativeModel(self._model_name)
            self._available = True
            log.info(
                "GeminiClient: initialized — model=%s timeout=%.0fs",
                self._model_name, self._timeout,
            )
            return True

        except Exception as exc:
            log.error(
                "GeminiClient: initialization failed: %s", exc, exc_info=True
            )
            return False

    def complete(self, prompt: str, max_tokens: int = 1024) -> Optional[str]:
        """
        Send a prompt to Gemini and return the response text.

        Returns:
            str  — response text on success (may be empty string)
            None — on any failure (key missing, network error, timeout, API error)

        Never raises. All failures are absorbed and logged at WARNING level.
        The caller (analyzer.py) always checks for None and uses fallback logic.

        Args:
            prompt:     The full prompt string to send to Gemini.
            max_tokens: Approximate output token budget. Gemini uses this as a
                        soft limit — actual output may vary slightly.
        """
        # Lazy initialization on first call
        if not self._available:
            if not self.initialize():
                return None

        if self._model is None:
            return None

        t_start = time.monotonic()

        try:
            # google-generativeai SDK call.
            # generation_config controls output length.
            # request_options carries the timeout.
            import google.generativeai.types as genai_types

            response = self._model.generate_content(
                prompt,
                generation_config=genai_types.GenerationConfig(
                    max_output_tokens=max_tokens,
                    temperature=0.3,   # Low temperature: consistent, factual output
                ),
                request_options={"timeout": self._timeout},
            )

            t_elapsed = time.monotonic() - t_start

            # Extract text from response
            text = self._extract_text(response)

            if text is None:
                log.warning(
                    "GeminiClient: empty or blocked response (%.1fs)", t_elapsed
                )
                return None

            log.debug(
                "GeminiClient: complete() → %d chars in %.1fs",
                len(text), t_elapsed,
            )
            return text

        except Exception as exc:
            t_elapsed = time.monotonic() - t_start
            exc_name  = type(exc).__name__

            # Classify common errors for cleaner log messages
            if "timeout" in exc_name.lower() or "deadline" in str(exc).lower():
                log.warning(
                    "GeminiClient: request timed out after %.1fs (limit=%.0fs)",
                    t_elapsed, self._timeout,
                )
            elif "quota" in str(exc).lower() or "rate" in str(exc).lower():
                log.warning(
                    "GeminiClient: API quota/rate limit exceeded (%.1fs): %s",
                    t_elapsed, exc,
                )
            else:
                log.warning(
                    "GeminiClient: API call failed after %.1fs: %s — %s",
                    t_elapsed, exc_name, exc,
                )
            return None

    @staticmethod
    def _extract_text(response) -> Optional[str]:
        """
        Safely extract text from a Gemini GenerateContentResponse.

        The SDK response structure can vary: response.text is the primary
        accessor, but may raise or be None for blocked/empty responses.
        Falls back to parts[0].text as a secondary accessor.

        Returns None if no text content can be extracted.
        """
        # Primary: response.text property
        try:
            text = response.text
            if text and text.strip():
                return text.strip()
        except Exception:
            pass

        # Secondary: candidates[0].content.parts[0].text
        try:
            part = response.candidates[0].content.parts[0].text
            if part and part.strip():
                return part.strip()
        except Exception:
            pass

        return None

    @property
    def is_available(self) -> bool:
        """True if the client is initialized and ready to make API calls."""
        return self._available

    def __repr__(self) -> str:
        return (
            f"GeminiClient(model={self._model_name!r}, "
            f"available={self._available})"
        )
