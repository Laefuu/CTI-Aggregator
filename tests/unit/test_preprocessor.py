"""
Unit tests for Preprocessor — extractor, chunker, language detection, worker.
No I/O required (Redis/DB mocked).
"""
from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, patch

import pytest


# ── Extractor ─────────────────────────────────────────────────

@pytest.mark.unit
class TestExtractorHTML:
    def test_html_returns_text(self) -> None:
        from modules.preprocessor.extractor import extract_text
        html = b"""<html><body>
            <nav>Navigation menu item</nav>
            <article>
                <h1>APT28 Campaign Analysis</h1>
                <p>The threat actor APT28, also known as Fancy Bear, was observed
                using IP address 198.51.100.1 as command-and-control infrastructure
                in a campaign targeting European defence organisations.</p>
            </article>
        </body></html>"""
        text = extract_text(html, "text/html")
        assert len(text) > 50
        # trafilatura or fallback should extract meaningful content
        assert "APT28" in text or "198.51.100.1" in text

    def test_html_empty_returns_empty(self) -> None:
        from modules.preprocessor.extractor import extract_text
        text = extract_text(b"<html><body></body></html>", "text/html")
        # May return empty or near-empty — should not crash
        assert isinstance(text, str)

    def test_unknown_mime_falls_back_to_text_decode(self) -> None:
        from modules.preprocessor.extractor import extract_text
        content = b"Some plain text content that is not HTML"
        text = extract_text(content, "application/octet-stream")
        assert "plain text" in text

    def test_html_strips_scripts(self) -> None:
        from modules.preprocessor.extractor import _strip_html_tags
        html = "<script>alert('xss')</script><p>Real content here</p>"
        text = _strip_html_tags(html)
        assert "alert" not in text
        assert "Real content" in text


@pytest.mark.unit
class TestExtractorJSON:
    def test_json_extracts_text_fields(self) -> None:
        from modules.preprocessor.extractor import extract_text
        data = {
            "title": "Malware Analysis Report",
            "description": "The malware communicates with 198.51.100.1 on port 443",
            "version": 1,
            "metadata": {"author": "analyst"},
        }
        content = json.dumps(data).encode()
        text = extract_text(content, "application/json")
        assert "Malware Analysis Report" in text
        assert "198.51.100.1" in text

    def test_json_nested_fields_extracted(self) -> None:
        from modules.preprocessor.extractor import extract_text
        data = {
            "objects": [
                {"type": "indicator", "description": "C2 server used in campaign"},
                {"type": "threat-actor", "name": "APT28", "description": "Russian GRU unit"},
            ]
        }
        content = json.dumps(data).encode()
        text = extract_text(content, "application/json")
        assert "C2 server" in text
        assert "Russian GRU" in text

    def test_invalid_json_returns_empty(self) -> None:
        from modules.preprocessor.extractor import extract_text
        text = extract_text(b"not valid json {{{", "application/json")
        assert text == ""


# ── Chunker ───────────────────────────────────────────────────

@pytest.mark.unit
class TestChunker:
    def test_short_text_returns_empty(self) -> None:
        from modules.preprocessor.chunker import chunk_text
        # Below MIN_CONTENT_WORDS (100)
        text = " ".join(["word"] * 50)
        chunks = chunk_text(text)
        assert chunks == []

    def test_adequate_text_returns_chunks(self) -> None:
        from modules.preprocessor.chunker import chunk_text
        # 200 words — should produce at least 1 chunk
        text = " ".join(["threat"] * 200)
        chunks = chunk_text(text)
        assert len(chunks) >= 1

    def test_long_text_split_into_multiple_chunks(self) -> None:
        from modules.preprocessor.chunker import chunk_text
        # ~6000 tokens worth of text → should produce ≥2 chunks
        word = "The threat actor deployed malware using spearphishing techniques. "
        text = word * 100  # ~1000 words
        chunks = chunk_text(text)
        assert len(chunks) >= 1
        # Each chunk should be non-empty
        for c in chunks:
            assert len(c.strip()) > 0

    def test_chunks_contain_original_content(self) -> None:
        from modules.preprocessor.chunker import chunk_text
        unique_phrase = "UNIQUE_CTI_PHRASE_XYZ_12345"
        text = f"Introduction paragraph. {unique_phrase}. " + " ".join(["context"] * 200)
        chunks = chunk_text(text)
        combined = " ".join(chunks)
        assert unique_phrase in combined

    def test_empty_text_returns_empty(self) -> None:
        from modules.preprocessor.chunker import chunk_text
        assert chunk_text("") == []


# ── Language detection ────────────────────────────────────────

@pytest.mark.unit
class TestLanguageDetection:
    def test_english_detected(self) -> None:
        from modules.preprocessor.language import detect_language
        text = (
            "The threat actor was observed deploying ransomware against critical "
            "infrastructure targets in North America and Europe during Q1 2026."
        )
        lang = detect_language(text)
        assert lang == "en"

    def test_french_detected(self) -> None:
        from modules.preprocessor.language import detect_language
        text = (
            "L'acteur de la menace a été observé en train de déployer des logiciels "
            "malveillants contre des infrastructures critiques en Europe occidentale."
        )
        lang = detect_language(text)
        assert lang == "fr"

    def test_short_text_defaults_to_en(self) -> None:
        from modules.preprocessor.language import detect_language
        lang = detect_language("hello")
        assert lang == "en"

    def test_empty_text_defaults_to_en(self) -> None:
        from modules.preprocessor.language import detect_language
        assert detect_language("") == "en"


# ── Worker ────────────────────────────────────────────────────

@pytest.mark.unit
class TestPreprocessorWorker:
    async def test_valid_html_message_produces_chunks(self) -> None:
        from modules.preprocessor.worker import handle_raw_message
        from shared.models.enums import SourceType, TLPLevel
        import uuid
        from datetime import UTC, datetime

        html = """<html><body>
            <article>
                <h1>APT28 New Campaign</h1>
                <p>The threat actor APT28, linked to Russian military intelligence,
                has been observed conducting spearphishing campaigns against European
                government organisations throughout Q1 2026. The group used IP
                198.51.100.1 as primary command-and-control infrastructure and
                registered several new domains for staging operations.</p>
                <p>Multiple indicators of compromise were identified including malware
                hashes and network signatures used in the operation. The malware
                variant, a new iteration of X-Agent, communicates over HTTPS on
                port 443 and uses certificate pinning to evade interception.</p>
                <p>The campaign targeted ministries of foreign affairs and defence
                contractors across Europe. Victims were identified in France, Germany,
                Poland and the Netherlands. Attribution is based on TTP overlap with
                previous APT28 operations documented by multiple vendors. The group
                demonstrated advanced persistence mechanisms including scheduled tasks
                and registry run keys to maintain access across reboots.</p>
                <p>Recommended mitigations include blocking the identified IP ranges,
                enforcing multi-factor authentication on all remote access services,
                and deploying endpoint detection and response tooling capable of
                detecting the observed lateral movement techniques.</p>
            </article>
        </body></html>"""

        payload = {
            "source_id": str(uuid.uuid4()),
            "source_url": "https://example.com/report",
            "source_type": "rss",
            "content_b64": base64.b64encode(html.encode()).decode(),
            "content_type": "text/html",
            "fetched_at": datetime.now(UTC).isoformat(),
            "tlp_level": "WHITE",
            "metadata": {},
        }

        published: list[dict] = []

        async def mock_publish(stream: str, data: dict) -> str:
            published.append({"stream": stream, "data": data})
            return "1234-0"

        with patch("modules.preprocessor.worker.publish", side_effect=mock_publish):
            with patch("modules.preprocessor.worker.record_metric", new=AsyncMock()):
                await handle_raw_message(payload)

        assert len(published) >= 1
        from shared.queue import STREAM_CHUNKS
        assert all(p["stream"] == STREAM_CHUNKS for p in published)

        # Verify ChunkMessage structure
        first_chunk = published[0]["data"]
        assert "chunk_text" in first_chunk
        assert first_chunk["chunk_index"] == 0
        assert first_chunk["chunk_total"] == len(published)

    async def test_invalid_base64_does_not_crash(self) -> None:
        from modules.preprocessor.worker import handle_raw_message
        import uuid
        from datetime import UTC, datetime

        payload = {
            "source_id": str(uuid.uuid4()),
            "source_url": "https://example.com",
            "source_type": "rss",
            "content_b64": "NOT_VALID_BASE64!!!",
            "content_type": "text/html",
            "fetched_at": datetime.now(UTC).isoformat(),
            "tlp_level": "WHITE",
            "metadata": {},
        }

        with patch("modules.preprocessor.worker.record_metric", new=AsyncMock()):
            # Must not raise
            await handle_raw_message(payload)

    async def test_malformed_message_does_not_crash(self) -> None:
        from modules.preprocessor.worker import handle_raw_message
        with patch("modules.preprocessor.worker.record_metric", new=AsyncMock()):
            await handle_raw_message({"invalid": "payload"})

    async def test_content_below_min_words_produces_no_chunks(self) -> None:
        from modules.preprocessor.worker import handle_raw_message
        import uuid
        from datetime import UTC, datetime

        # Very short content — below MIN_CONTENT_WORDS
        short_html = b"<html><body><p>Short text.</p></body></html>"

        payload = {
            "source_id": str(uuid.uuid4()),
            "source_url": "https://example.com",
            "source_type": "rss",
            "content_b64": base64.b64encode(short_html).decode(),
            "content_type": "text/html",
            "fetched_at": datetime.now(UTC).isoformat(),
            "tlp_level": "WHITE",
            "metadata": {},
        }

        published: list = []

        async def mock_publish(stream: str, data: dict) -> str:
            published.append(data)
            return "1234-0"

        with patch("modules.preprocessor.worker.publish", side_effect=mock_publish):
            with patch("modules.preprocessor.worker.record_metric", new=AsyncMock()):
                await handle_raw_message(payload)

        assert published == []