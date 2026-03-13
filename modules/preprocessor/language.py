"""
Language detection using langdetect.

Supported languages for the CTI pipeline: en, fr, de, es, ru, zh, ar.
Unknown or unsupported languages default to "en" to ensure LLM processing
still occurs (LLaMA 3.3 and Mistral handle multilingual input reasonably).
"""
from __future__ import annotations

import structlog

log = structlog.get_logger()

# Languages the LLM handles well enough for CTI extraction
_SUPPORTED = frozenset({"en", "fr", "de", "es", "ru", "zh", "ar", "pt", "it", "nl"})
_DEFAULT = "en"


def detect_language(text: str) -> str:
    """
    Detect language of text. Returns ISO 639-1 code.
    Defaults to 'en' on failure or unsupported language.
    """
    if not text or len(text.split()) < 10:
        return _DEFAULT

    try:
        from langdetect import detect, DetectorFactory
        from langdetect.lang_detect_exception import LangDetectException

        # Seed for reproducibility (langdetect is non-deterministic by default)
        DetectorFactory.seed = 42
        lang = detect(text[:2000])  # Use first 2000 chars for speed
        return lang if lang in _SUPPORTED else _DEFAULT

    except Exception as exc:
        log.debug("language_detection_failed", error=str(exc))
        return _DEFAULT
