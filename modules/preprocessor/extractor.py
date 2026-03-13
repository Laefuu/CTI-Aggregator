"""
Text extractor — converts raw bytes to plain text based on MIME type.

Dispatch table:
    text/html        → trafilatura (main content extraction)
    application/pdf  → PyMuPDF, OCR fallback via pytesseract if needed
    application/json → recursive field extraction
    text/*           → decode as UTF-8
"""
from __future__ import annotations

import io
import json
import re
from typing import Any

import structlog
import trafilatura

log = structlog.get_logger()


def extract_text(content_bytes: bytes, content_type: str) -> str:
    """
    Extract clean text from raw bytes.
    Returns empty string if extraction fails or yields nothing useful.
    """
    mime = content_type.split(";")[0].strip().lower()

    match mime:
        case "text/html" | "application/xhtml+xml":
            return _extract_html(content_bytes)
        case "application/pdf":
            return _extract_pdf(content_bytes)
        case "application/json":
            return _extract_json(content_bytes)
        case _:
            if mime.startswith("text/"):
                return _decode_text(content_bytes)
            log.warning("extractor_unknown_mime", mime=mime)
            return _decode_text(content_bytes)


# ── HTML ──────────────────────────────────────────────────────

def _extract_html(content_bytes: bytes) -> str:
    html = _decode_text(content_bytes)
    if not html:
        return ""

    # trafilatura: extracts main article content, removes boilerplate
    text = trafilatura.extract(
        html,
        include_comments=False,
        include_tables=True,
        no_fallback=False,
        favor_recall=True,
    )

    if text and len(text.split()) >= 20:
        return text.strip()

    # Fallback: simple tag stripping
    log.debug("extractor_html_trafilatura_fallback")
    return _strip_html_tags(html)


def _strip_html_tags(html: str) -> str:
    """Minimal HTML tag stripper — used as trafilatura fallback."""
    text = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&[a-z]+;", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ── PDF ───────────────────────────────────────────────────────

def _extract_pdf(content_bytes: bytes) -> str:
    try:
        import fitz  # PyMuPDF
    except ImportError:
        log.error("extractor_pymupdf_not_installed")
        return ""

    try:
        doc = fitz.open(stream=content_bytes, filetype="pdf")
    except Exception as exc:
        log.error("extractor_pdf_open_failed", error=str(exc))
        return ""

    pages: list[str] = []
    ocr_needed = False

    for page_num, page in enumerate(doc):
        text = page.get_text("text")  # type: ignore[attr-defined]
        if text and len(text.strip()) > 20:
            pages.append(text)
        else:
            ocr_needed = True
            log.debug("extractor_pdf_page_no_text", page=page_num)

    doc.close()

    if pages:
        full_text = "\n\n".join(pages)
        # If we got most pages as text but a few needed OCR, proceed without OCR
        if len(full_text.split()) >= 50:
            return full_text.strip()

    # Full OCR path
    from shared.config import get_settings
    if get_settings().ocr_enabled:
        return _extract_pdf_ocr(content_bytes)

    log.warning("extractor_pdf_no_text_ocr_disabled")
    return ""


def _extract_pdf_ocr(content_bytes: bytes) -> str:
    """OCR fallback for scanned PDFs using pytesseract."""
    try:
        import fitz
        import pytesseract
        from PIL import Image
    except ImportError:
        log.error("extractor_ocr_deps_missing")
        return ""

    try:
        doc = fitz.open(stream=content_bytes, filetype="pdf")
    except Exception as exc:
        log.error("extractor_pdf_ocr_open_failed", error=str(exc))
        return ""

    pages: list[str] = []
    for page in doc:
        try:
            # Render page as image at 150 DPI
            pix = page.get_pixmap(dpi=150)  # type: ignore[attr-defined]
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            text = pytesseract.image_to_string(img, lang="eng+fra")
            if text.strip():
                pages.append(text.strip())
        except Exception as exc:
            log.warning("extractor_ocr_page_failed", error=str(exc))

    doc.close()
    return "\n\n".join(pages)


# ── JSON ──────────────────────────────────────────────────────

_JSON_TEXT_FIELDS = frozenset({
    "description", "content", "text", "body", "summary",
    "title", "name", "comment", "value", "detail", "details",
})


def _extract_json(content_bytes: bytes) -> str:
    try:
        data = json.loads(_decode_text(content_bytes))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        log.warning("extractor_json_parse_failed", error=str(exc))
        return ""

    parts: list[str] = []
    _collect_text_fields(data, parts, depth=0)
    return "\n".join(parts)


def _collect_text_fields(obj: Any, parts: list[str], depth: int) -> None:
    """Recursively collect text values from known text fields."""
    if depth > 10:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in _JSON_TEXT_FIELDS and isinstance(v, str) and v.strip():
                parts.append(v.strip())
            else:
                _collect_text_fields(v, parts, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _collect_text_fields(item, parts, depth + 1)


# ── Helpers ───────────────────────────────────────────────────

def _decode_text(content_bytes: bytes) -> str:
    """Decode bytes to string, trying UTF-8 then latin-1."""
    try:
        return content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return content_bytes.decode("latin-1", errors="replace")
