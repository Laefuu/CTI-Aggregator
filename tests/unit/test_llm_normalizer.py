"""
Unit tests for LLM Normalizer — prompt building, JSON parsing, worker logic.
Ollama HTTP calls are mocked.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── JSON parsing ──────────────────────────────────────────────

@pytest.mark.unit
class TestParseJsonResponse:
    def test_clean_json_parsed(self) -> None:
        from modules.llm_normalizer.client import _parse_json_response
        raw = '{"objects": [{"type": "indicator"}]}'
        result = _parse_json_response(raw)
        assert result == {"objects": [{"type": "indicator"}]}

    def test_markdown_fences_stripped(self) -> None:
        from modules.llm_normalizer.client import _parse_json_response
        raw = '```json\n{"objects": []}\n```'
        result = _parse_json_response(raw)
        assert result == {"objects": []}

    def test_fences_without_language_stripped(self) -> None:
        from modules.llm_normalizer.client import _parse_json_response
        raw = '```\n{"objects": []}\n```'
        result = _parse_json_response(raw)
        assert result == {"objects": []}

    def test_leading_prose_ignored(self) -> None:
        from modules.llm_normalizer.client import _parse_json_response
        raw = 'Here is the extracted CTI:\n{"objects": [{"type": "threat-actor"}]}'
        result = _parse_json_response(raw)
        assert result is not None
        assert result["objects"][0]["type"] == "threat-actor"

    def test_trailing_prose_ignored(self) -> None:
        from modules.llm_normalizer.client import _parse_json_response
        raw = '{"objects": []} Let me know if you need more.'
        result = _parse_json_response(raw)
        assert result == {"objects": []}

    def test_completely_invalid_returns_none(self) -> None:
        from modules.llm_normalizer.client import _parse_json_response
        assert _parse_json_response("I cannot process this request.") is None

    def test_empty_string_returns_none(self) -> None:
        from modules.llm_normalizer.client import _parse_json_response
        assert _parse_json_response("") is None

    def test_truncated_json_returns_none(self) -> None:
        from modules.llm_normalizer.client import _parse_json_response
        assert _parse_json_response('{"objects": [{"type":') is None

    def test_nested_objects_parsed(self) -> None:
        from modules.llm_normalizer.client import _parse_json_response
        raw = json.dumps({
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--abc",
                    "pattern": "[ipv4-addr:value = '1.2.3.4']",
                    "x_cti_source_url": "https://example.com",
                }
            ]
        })
        result = _parse_json_response(raw)
        assert result is not None
        assert len(result["objects"]) == 1


# ── Prompt building ───────────────────────────────────────────

@pytest.mark.unit
class TestPromptBuilding:
    def test_source_url_injected(self) -> None:
        from modules.llm_normalizer.prompt import build_user_prompt
        prompt = build_user_prompt(
            chunk_text="APT28 used 198.51.100.1",
            source_url="https://example.com/report",
            published_at="2026-01-15T10:00:00Z",
        )
        assert "https://example.com/report" in prompt

    def test_published_at_injected(self) -> None:
        from modules.llm_normalizer.prompt import build_user_prompt
        prompt = build_user_prompt(
            chunk_text="Some CTI text",
            source_url="https://example.com",
            published_at="2026-01-15T10:00:00Z",
        )
        assert "2026-01-15T10:00:00Z" in prompt

    def test_chunk_text_injected(self) -> None:
        from modules.llm_normalizer.prompt import build_user_prompt
        chunk = "APT28 deployed X-Agent malware"
        prompt = build_user_prompt(
            chunk_text=chunk,
            source_url="https://example.com",
            published_at="2026-01-15T00:00:00Z",
        )
        assert chunk in prompt

    def test_non_english_note_added(self) -> None:
        from modules.llm_normalizer.prompt import build_user_prompt
        prompt = build_user_prompt(
            chunk_text="L'acteur APT28 a utilisé ce domaine",
            source_url="https://example.com",
            published_at="2026-01-15T00:00:00Z",
            language="fr",
        )
        assert "fr" in prompt

    def test_english_no_language_note(self) -> None:
        from modules.llm_normalizer.prompt import build_user_prompt
        prompt = build_user_prompt(
            chunk_text="APT28 used this domain",
            source_url="https://example.com",
            published_at="2026-01-15T00:00:00Z",
            language="en",
        )
        # No extra language note for English
        assert "Note: The text is in en" not in prompt

    def test_system_prompt_contains_rules(self) -> None:
        from modules.llm_normalizer.prompt import SYSTEM_PROMPT
        assert "x_cti_source_url" in SYSTEM_PROMPT
        assert "x_cti_published_at" in SYSTEM_PROMPT
        assert "RFC 1918" in SYSTEM_PROMPT or "192.168" in SYSTEM_PROMPT
        assert "objects" in SYSTEM_PROMPT


# ── OllamaClient ──────────────────────────────────────────────

@pytest.mark.unit
class TestOllamaClient:
    async def test_successful_call_returns_objects(self) -> None:
        from modules.llm_normalizer.client import OllamaClient

        good_response = json.dumps({
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--12345678-1234-4234-8234-123456789012",
                    "pattern": "[ipv4-addr:value = '198.51.100.1']",
                    "x_cti_source_url": "https://example.com",
                }
            ]
        })

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={
            "message": {"content": good_response}
        })

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_resp)
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock()

        with patch("modules.llm_normalizer.client.httpx.AsyncClient", return_value=mock_http):
            client = OllamaClient()
            async with client:
                objects, model, duration_ms = await client.extract_stix(
                    system_prompt="sys",
                    user_prompt="user",
                )

        assert len(objects) == 1
        assert objects[0]["type"] == "indicator"
        assert duration_ms >= 0

    async def test_invalid_json_triggers_retry(self) -> None:
        from modules.llm_normalizer.client import OllamaClient

        good_response = '{"objects": [{"type": "threat-actor", "name": "APT28"}]}'
        call_count = 0

        def make_response(content: str) -> MagicMock:
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json = MagicMock(return_value={"message": {"content": content}})
            return mock_resp

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock()

        async def fake_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return make_response("This is not valid JSON at all.")
            return make_response(good_response)

        mock_http.post = fake_post

        with patch("modules.llm_normalizer.client.httpx.AsyncClient", return_value=mock_http):
            client = OllamaClient()
            async with client:
                objects, model, _ = await client.extract_stix("sys", "user")

        assert call_count == 2  # One retry
        assert len(objects) == 1

    async def test_timeout_triggers_fallback(self) -> None:
        import httpx
        from modules.llm_normalizer.client import OllamaClient

        fallback_response = '{"objects": []}'
        call_count = 0

        def make_ok_response() -> MagicMock:
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json = MagicMock(return_value={"message": {"content": fallback_response}})
            return mock_resp

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock()

        async def fake_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            # First two calls (primary model with retries) → timeout
            if call_count <= 2:
                raise httpx.TimeoutException("timeout")
            # Fallback model → success
            return make_ok_response()

        mock_http.post = fake_post

        with patch("modules.llm_normalizer.client.httpx.AsyncClient", return_value=mock_http):
            client = OllamaClient()
            async with client:
                objects, model, _ = await client.extract_stix("sys", "user")

        # Fallback model was used
        settings_model = client._fallback_model
        assert model == settings_model

    async def test_empty_objects_list_on_no_cti(self) -> None:
        from modules.llm_normalizer.client import OllamaClient

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={
            "message": {"content": '{"objects": []}'}
        })

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_resp)
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock()

        with patch("modules.llm_normalizer.client.httpx.AsyncClient", return_value=mock_http):
            client = OllamaClient()
            async with client:
                objects, _, _ = await client.extract_stix("sys", "user")

        assert objects == []


# ── Worker ────────────────────────────────────────────────────

@pytest.mark.unit
class TestLLMNormalizerWorker:
    async def test_valid_chunk_publishes_stix_raw(self) -> None:
        import uuid
        from modules.llm_normalizer.worker import handle_chunk_message

        stix_objects = [
            {"type": "indicator", "id": "indicator--abc", "pattern": "[ipv4-addr:value = '1.2.3.4']"}
        ]

        payload = {
            "source_id": str(uuid.uuid4()),
            "source_url": "https://example.com/report",
            "source_type": "rss",
            "chunk_index": 0,
            "chunk_total": 1,
            "chunk_text": "APT28 used 198.51.100.1 as C2",
            "language": "en",
            "tlp_level": "WHITE",
            "fetched_at": datetime.now(UTC).isoformat(),
            "published_at": None,
        }

        published: list[dict] = []

        async def mock_publish(stream: str, data: dict) -> str:
            published.append({"stream": stream, "data": data})
            return "1234-0"

        mock_client = AsyncMock()
        mock_client.extract_stix = AsyncMock(
            return_value=(stix_objects, "mistral:7b-instruct-q4_K_M", 5000)
        )

        with patch("modules.llm_normalizer.worker.publish", side_effect=mock_publish):
            with patch("modules.llm_normalizer.worker.record_metric", new=AsyncMock()):
                with patch("modules.llm_normalizer.worker._get_client", return_value=mock_client):
                    await handle_chunk_message(payload)

        from shared.queue import STREAM_STIX_RAW
        assert len(published) == 1
        assert published[0]["stream"] == STREAM_STIX_RAW
        assert "stix_objects" in published[0]["data"]
        assert published[0]["data"]["stix_objects"] == stix_objects

    async def test_empty_llm_response_does_not_publish(self) -> None:
        import uuid
        from modules.llm_normalizer.worker import handle_chunk_message

        payload = {
            "source_id": str(uuid.uuid4()),
            "source_url": "https://example.com",
            "source_type": "rss",
            "chunk_index": 0,
            "chunk_total": 1,
            "chunk_text": "No CTI here, just marketing text",
            "language": "en",
            "tlp_level": "WHITE",
            "fetched_at": datetime.now(UTC).isoformat(),
            "published_at": None,
        }

        published: list = []

        mock_client = AsyncMock()
        mock_client.extract_stix = AsyncMock(return_value=([], "mistral:7b", 3000))

        with patch("modules.llm_normalizer.worker.publish", side_effect=lambda *a, **k: published.append(a)):
            with patch("modules.llm_normalizer.worker.record_metric", new=AsyncMock()):
                with patch("modules.llm_normalizer.worker._get_client", return_value=mock_client):
                    await handle_chunk_message(payload)

        assert published == []

    async def test_malformed_message_does_not_crash(self) -> None:
        from modules.llm_normalizer.worker import handle_chunk_message
        with patch("modules.llm_normalizer.worker.record_metric", new=AsyncMock()):
            await handle_chunk_message({"invalid": "data"})
