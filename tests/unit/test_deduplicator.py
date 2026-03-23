"""
Unit tests for Deduplicator — exact dedup, semantic dedup, embedding utils, worker.
Redis and pgvector calls are mocked.
"""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Exact dedup ───────────────────────────────────────────────

@pytest.mark.unit
class TestExactDedup:
    async def test_lookup_returns_none_when_absent(self) -> None:
        from modules.deduplicator.exact import lookup_exact

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)

        with patch("modules.deduplicator.exact.get_redis", return_value=mock_redis):
            result = await lookup_exact("[ipv4-addr:value = '198.51.100.1']")

        assert result is None

    async def test_lookup_returns_stix_id_when_found(self) -> None:
        from modules.deduplicator.exact import lookup_exact

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=b"indicator--abc-123")

        with patch("modules.deduplicator.exact.get_redis", return_value=mock_redis):
            result = await lookup_exact("[ipv4-addr:value = '198.51.100.1']")

        assert result == "indicator--abc-123"

    async def test_mark_exact_calls_setex(self) -> None:
        from modules.deduplicator.exact import mark_exact

        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock()

        with patch("modules.deduplicator.exact.get_redis", return_value=mock_redis):
            await mark_exact("[ipv4-addr:value = '198.51.100.1']", "indicator--abc")

        assert mock_redis.setex.called
        # Verify TTL and value are passed
        call_args = mock_redis.setex.call_args
        assert call_args[0][2] == "indicator--abc"

    def test_pattern_hash_is_normalized(self) -> None:
        from modules.deduplicator.exact import _pattern_hash
        # Same pattern, different whitespace → same hash
        h1 = _pattern_hash("[ipv4-addr:value = '198.51.100.1']")
        h2 = _pattern_hash("  [ipv4-addr:value = '198.51.100.1']  ")
        assert h1 == h2

    def test_pattern_hash_case_insensitive(self) -> None:
        from modules.deduplicator.exact import _pattern_hash
        h1 = _pattern_hash("[IPV4-ADDR:VALUE = '198.51.100.1']")
        h2 = _pattern_hash("[ipv4-addr:value = '198.51.100.1']")
        assert h1 == h2

    def test_different_patterns_different_hashes(self) -> None:
        from modules.deduplicator.exact import _pattern_hash
        h1 = _pattern_hash("[ipv4-addr:value = '1.2.3.4']")
        h2 = _pattern_hash("[ipv4-addr:value = '5.6.7.8']")
        assert h1 != h2


# ── Embedding utils ───────────────────────────────────────────

@pytest.mark.unit
class TestEmbeddingUtils:
    def test_cosine_similarity_identical_vectors(self) -> None:
        from modules.deduplicator.embedding import cosine_similarity
        v = [1.0, 0.0, 0.0]
        assert abs(cosine_similarity(v, v) - 1.0) < 1e-6

    def test_cosine_similarity_orthogonal_vectors(self) -> None:
        from modules.deduplicator.embedding import cosine_similarity
        v1 = [1.0, 0.0, 0.0]
        v2 = [0.0, 1.0, 0.0]
        assert abs(cosine_similarity(v1, v2)) < 1e-6

    def test_cosine_similarity_opposite_vectors(self) -> None:
        from modules.deduplicator.embedding import cosine_similarity
        v1 = [1.0, 0.0, 0.0]
        v2 = [-1.0, 0.0, 0.0]
        assert abs(cosine_similarity(v1, v2) - (-1.0)) < 1e-6

    def test_text_for_embedding_indicator(self) -> None:
        from modules.deduplicator.embedding import text_for_embedding
        obj = {
            "type": "indicator",
            "name": "APT28 C2",
            "pattern": "[ipv4-addr:value = '198.51.100.1']",
            "description": "Command and control server",
        }
        text = text_for_embedding(obj)
        assert "APT28 C2" in text
        assert "198.51.100.1" in text
        assert "Command and control" in text

    def test_text_for_embedding_threat_actor(self) -> None:
        from modules.deduplicator.embedding import text_for_embedding
        obj = {
            "type": "threat-actor",
            "name": "APT28",
            "aliases": ["Fancy Bear", "Sofacy"],
            "description": "Russian GRU unit",
        }
        text = text_for_embedding(obj)
        assert "APT28" in text
        assert "Fancy Bear" in text
        assert "Russian GRU" in text

    def test_text_for_embedding_attack_pattern(self) -> None:
        from modules.deduplicator.embedding import text_for_embedding
        obj = {
            "type": "attack-pattern",
            "name": "PowerShell",
            "x_mitre_id": "T1059.001",
            "description": "Adversaries abuse PowerShell",
        }
        text = text_for_embedding(obj)
        assert "PowerShell" in text
        assert "T1059.001" in text

    def test_embed_returns_list_of_floats(self) -> None:
        from modules.deduplicator.embedding import embed

        mock_vector = [0.1] * 1024

        mock_model = MagicMock()
        mock_model.encode = MagicMock(return_value=mock_vector)

        with patch("modules.deduplicator.embedding._model", mock_model):
            result = embed("APT28 used 198.51.100.1")

        assert isinstance(result, list)
        assert len(result) == 1024
        assert all(isinstance(v, float) for v in result)


# ── Worker ────────────────────────────────────────────────────

@pytest.mark.unit
class TestDeduplicatorWorker:
    def _make_valid_message(self, pattern: str = "[ipv4-addr:value = '198.51.100.1']") -> dict:
        import uuid
        return {
            "source_id": str(uuid.uuid4()),
            "source_url": "https://example.com/report",
            "source_type": "rss",
            "source_category": "known",
            "tlp_level": "WHITE",
            "published_at": "2026-01-15T10:00:00+00:00",
            "fetched_at": datetime.now(UTC).isoformat(),
            "llm_model": "mistral:7b-instruct-q4_K_M",
            "llm_duration_ms": 5000,
            "confidence": 50,
            "stix_object": {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--12345678-1234-4234-8234-123456789012",
                "created": "2026-01-15T10:00:00Z",
                "modified": "2026-01-15T10:00:00Z",
                "name": "C2 IP",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": "2026-01-15T10:00:00Z",
                "x_cti_source_url": "https://example.com/report",
                "x_cti_published_at": "2026-01-15T10:00:00Z",
            },
        }

    async def test_new_object_published_as_insert(self) -> None:
        from modules.deduplicator.worker import handle_stix_valid_message
        from shared.models.enums import DedupAction
        from shared.queue import STREAM_STIX_FINAL

        payload = self._make_valid_message()
        published: list[dict] = []

        async def mock_publish(stream: str, data: dict) -> str:
            published.append({"stream": stream, "data": data})
            return "1234-0"

        with patch("modules.deduplicator.worker.lookup_exact", new=AsyncMock(return_value=None)):
            with patch("modules.deduplicator.worker.find_semantic_duplicate", new=AsyncMock(return_value=None)):
                with patch("modules.deduplicator.worker.embed", return_value=[0.1] * 1024):
                    with patch("modules.deduplicator.worker.mark_exact", new=AsyncMock()):
                        with patch("modules.deduplicator.worker.publish", side_effect=mock_publish):
                            with patch("modules.deduplicator.worker.record_metric", new=AsyncMock()):
                                await handle_stix_valid_message(payload)

        assert len(published) == 1
        assert published[0]["stream"] == STREAM_STIX_FINAL
        assert published[0]["data"]["action"] == DedupAction.INSERT
        assert published[0]["data"]["target_stix_id"] is None

    async def test_exact_duplicate_published_as_merge(self) -> None:
        from modules.deduplicator.worker import handle_stix_valid_message
        from shared.models.enums import DedupAction
        from shared.queue import STREAM_STIX_FINAL

        payload = self._make_valid_message()
        existing_id = "indicator--existing-canonical-id"
        published: list[dict] = []

        async def mock_publish(stream: str, data: dict) -> str:
            published.append({"stream": stream, "data": data})
            return "1234-0"

        with patch("modules.deduplicator.worker.lookup_exact", new=AsyncMock(return_value=existing_id)):
            with patch("modules.deduplicator.worker.publish", side_effect=mock_publish):
                with patch("modules.deduplicator.worker.record_metric", new=AsyncMock()):
                    await handle_stix_valid_message(payload)

        assert len(published) == 1
        assert published[0]["data"]["action"] == DedupAction.MERGE
        assert published[0]["data"]["target_stix_id"] == existing_id
        assert published[0]["data"]["merge_method"] == "exact"

    async def test_semantic_duplicate_published_as_merge(self) -> None:
        from modules.deduplicator.worker import handle_stix_valid_message
        from shared.models.enums import DedupAction

        payload = self._make_valid_message()
        semantic_id = "indicator--semantic-match-id"
        published: list[dict] = []

        async def mock_publish(stream: str, data: dict) -> str:
            published.append({"stream": stream, "data": data})
            return "1234-0"

        with patch("modules.deduplicator.worker.lookup_exact", new=AsyncMock(return_value=None)):
            with patch("modules.deduplicator.worker.find_semantic_duplicate", new=AsyncMock(return_value=semantic_id)):
                with patch("modules.deduplicator.worker.embed", return_value=[0.1] * 1024):
                    with patch("modules.deduplicator.worker.publish", side_effect=mock_publish):
                        with patch("modules.deduplicator.worker.record_metric", new=AsyncMock()):
                            await handle_stix_valid_message(payload)

        assert len(published) == 1
        assert published[0]["data"]["action"] == DedupAction.MERGE
        assert published[0]["data"]["target_stix_id"] == semantic_id
        assert published[0]["data"]["merge_method"] == "semantic"

    async def test_embed_failure_still_publishes_insert(self) -> None:
        from modules.deduplicator.worker import handle_stix_valid_message
        from shared.models.enums import DedupAction

        payload = self._make_valid_message()
        published: list[dict] = []

        async def mock_publish(stream: str, data: dict) -> str:
            published.append({"stream": stream, "data": data})
            return "1234-0"

        with patch("modules.deduplicator.worker.lookup_exact", new=AsyncMock(return_value=None)):
            with patch("modules.deduplicator.worker.embed", side_effect=RuntimeError("model unavailable")):
                with patch("modules.deduplicator.worker.publish", side_effect=mock_publish):
                    with patch("modules.deduplicator.worker.record_metric", new=AsyncMock()):
                        await handle_stix_valid_message(payload)

        assert len(published) == 1
        assert published[0]["data"]["action"] == DedupAction.INSERT

    async def test_malformed_message_does_not_crash(self) -> None:
        from modules.deduplicator.worker import handle_stix_valid_message
        with patch("modules.deduplicator.worker.record_metric", new=AsyncMock()):
            await handle_stix_valid_message({"bad": "payload"})

    async def test_insert_registers_exact_dedup(self) -> None:
        from modules.deduplicator.worker import handle_stix_valid_message

        payload = self._make_valid_message()
        mark_called: list[tuple] = []

        async def mock_mark(pattern: str, stix_id: str) -> None:
            mark_called.append((pattern, stix_id))

        with patch("modules.deduplicator.worker.lookup_exact", new=AsyncMock(return_value=None)):
            with patch("modules.deduplicator.worker.find_semantic_duplicate", new=AsyncMock(return_value=None)):
                with patch("modules.deduplicator.worker.embed", return_value=[0.1] * 1024):
                    with patch("modules.deduplicator.worker.mark_exact", side_effect=mock_mark):
                        with patch("modules.deduplicator.worker.publish", new=AsyncMock()):
                            with patch("modules.deduplicator.worker.record_metric", new=AsyncMock()):
                                await handle_stix_valid_message(payload)

        assert len(mark_called) == 1
        assert "198.51.100.1" in mark_called[0][0]
