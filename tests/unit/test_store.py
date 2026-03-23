"""
Unit tests for Store — perimeter matching, enrichment trigger, worker routing.
DB calls are mocked — no PostgreSQL required.
"""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Perimeter matching ────────────────────────────────────────

@pytest.mark.unit
class TestPerimeterMatching:
    def test_extract_ioc_value_ipv4(self) -> None:
        from modules.store.perimeter import extract_ioc_value
        assert extract_ioc_value("[ipv4-addr:value = '198.51.100.1']") == "198.51.100.1"

    def test_extract_ioc_value_domain(self) -> None:
        from modules.store.perimeter import extract_ioc_value
        assert extract_ioc_value("[domain-name:value = 'evil.example.com']") == "evil.example.com"

    def test_extract_ioc_value_hash(self) -> None:
        from modules.store.perimeter import extract_ioc_value
        h = "a" * 64
        assert extract_ioc_value(f"[file:hashes.SHA256 = '{h}']") == h

    def test_extract_ioc_value_invalid(self) -> None:
        from modules.store.perimeter import extract_ioc_value
        assert extract_ioc_value("not a pattern") is None

    async def test_non_indicator_skipped(self) -> None:
        from modules.store.perimeter import match_perimeters
        count = await match_perimeters(
            stix_object_id="uuid-123",
            stix_object={"type": "threat-actor", "name": "APT28"},
            source_url="https://example.com",
        )
        assert count == 0

    async def test_no_pattern_skipped(self) -> None:
        from modules.store.perimeter import match_perimeters
        count = await match_perimeters(
            stix_object_id="uuid-123",
            stix_object={"type": "indicator", "pattern": ""},
            source_url="https://example.com",
        )
        assert count == 0

    async def test_match_creates_alert(self) -> None:
        from modules.store.perimeter import match_perimeters

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session.commit = AsyncMock()

        # Simulate one matching perimeter
        mock_row = MagicMock()
        mock_row.__getitem__ = lambda self, k: "test-perimeter" if k == "name" else "peri-uuid"
        mock_result = MagicMock()
        mock_result.mappings.return_value.all.return_value = [mock_row]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch("modules.store.perimeter.get_session", return_value=mock_session):
            count = await match_perimeters(
                stix_object_id="obj-uuid-123",
                stix_object={
                    "type": "indicator",
                    "id": "indicator--abc",
                    "pattern": "[ipv4-addr:value = '198.51.100.1']",
                },
                source_url="https://example.com",
            )

        assert count == 1
        assert mock_session.commit.called

    async def test_no_match_no_alert(self) -> None:
        from modules.store.perimeter import match_perimeters

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session.commit = AsyncMock()

        mock_result = MagicMock()
        mock_result.mappings.return_value.all.return_value = []
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch("modules.store.perimeter.get_session", return_value=mock_session):
            count = await match_perimeters(
                stix_object_id="obj-uuid-123",
                stix_object={
                    "type": "indicator",
                    "pattern": "[ipv4-addr:value = '198.51.100.1']",
                },
                source_url="https://example.com",
            )

        assert count == 0
        assert not mock_session.commit.called


# ── Enrichment trigger ────────────────────────────────────────

@pytest.mark.unit
class TestEnrichmentTrigger:
    def test_parse_pattern_ipv4(self) -> None:
        from modules.store.enrichment import _parse_pattern
        result = _parse_pattern("[ipv4-addr:value = '198.51.100.1']")
        assert result == ("ipv4-addr", "198.51.100.1")

    def test_parse_pattern_domain(self) -> None:
        from modules.store.enrichment import _parse_pattern
        result = _parse_pattern("[domain-name:value = 'evil.com']")
        assert result == ("domain-name", "evil.com")

    def test_parse_pattern_sha256(self) -> None:
        from modules.store.enrichment import _parse_pattern
        h = "a" * 64
        result = _parse_pattern(f"[file:hashes.SHA256 = '{h}']")
        assert result == ("file", h)

    def test_parse_pattern_url_not_enriched(self) -> None:
        from modules.store.enrichment import _parse_pattern
        result = _parse_pattern("[url:value = 'https://evil.com/path']")
        assert result is None

    def test_parse_pattern_email_not_enriched(self) -> None:
        from modules.store.enrichment import _parse_pattern
        result = _parse_pattern("[email-addr:value = 'bad@evil.com']")
        assert result is None

    async def test_enrichment_triggered_for_ip(self) -> None:
        from modules.store.enrichment import maybe_trigger_enrichment

        published: list = []

        async def mock_publish(stream: str, data: dict) -> str:
            published.append(data)
            return "1234-0"

        with patch("modules.store.enrichment.get_settings") as mock_settings:
            mock_settings.return_value.enrichment_enabled = True
            with patch("modules.store.enrichment.publish", side_effect=mock_publish):
                triggered = await maybe_trigger_enrichment({
                    "type": "indicator",
                    "id": "indicator--abc",
                    "pattern": "[ipv4-addr:value = '198.51.100.1']",
                })

        assert triggered is True
        assert len(published) == 1
        assert published[0]["ioc_type"] == "ipv4-addr"
        assert published[0]["ioc_value"] == "198.51.100.1"

    async def test_enrichment_skipped_when_disabled(self) -> None:
        from modules.store.enrichment import maybe_trigger_enrichment

        with patch("modules.store.enrichment.get_settings") as mock_settings:
            mock_settings.return_value.enrichment_enabled = False
            triggered = await maybe_trigger_enrichment({
                "type": "indicator",
                "pattern": "[ipv4-addr:value = '198.51.100.1']",
            })

        assert triggered is False

    async def test_enrichment_skipped_for_non_indicator(self) -> None:
        from modules.store.enrichment import maybe_trigger_enrichment

        with patch("modules.store.enrichment.get_settings") as mock_settings:
            mock_settings.return_value.enrichment_enabled = True
            triggered = await maybe_trigger_enrichment({
                "type": "threat-actor",
                "name": "APT28",
            })

        assert triggered is False


# ── Worker routing ────────────────────────────────────────────

@pytest.mark.unit
class TestStoreWorker:
    def _make_final_message(self, action: str = "insert", target: str | None = None) -> dict:
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
                "pattern": "[ipv4-addr:value = '198.51.100.1']",
                "pattern_type": "stix",
                "valid_from": "2026-01-15T10:00:00Z",
                "name": "C2 IP",
                "x_cti_source_url": "https://example.com/report",
                "x_cti_published_at": "2026-01-15T10:00:00Z",
            },
            "action": action,
            "target_stix_id": target,
            "embedding": [0.1] * 1024,
            "merge_method": None,
        }

    async def test_insert_calls_insert_object(self) -> None:
        from modules.store.worker import handle_stix_final_message

        payload = self._make_final_message(action="insert")

        with patch("modules.store.worker.get_source_category", new=AsyncMock(return_value="known")):
            with patch("modules.store.worker.insert_object", new=AsyncMock(return_value="uuid-123")) as mock_insert:
                with patch("modules.store.worker.merge_object", new=AsyncMock()) as mock_merge:
                    with patch("modules.store.worker.match_perimeters", new=AsyncMock(return_value=0)):
                        with patch("modules.store.worker.maybe_trigger_enrichment", new=AsyncMock(return_value=False)):
                            with patch("modules.store.worker.record_metric", new=AsyncMock()):
                                await handle_stix_final_message(payload)

        assert mock_insert.called
        assert not mock_merge.called

    async def test_merge_calls_merge_object(self) -> None:
        from modules.store.worker import handle_stix_final_message

        payload = self._make_final_message(
            action="merge",
            target="indicator--existing-canonical",
        )

        with patch("modules.store.worker.get_source_category", new=AsyncMock(return_value="known")):
            with patch("modules.store.worker.insert_object", new=AsyncMock()) as mock_insert:
                with patch("modules.store.worker.merge_object", new=AsyncMock()) as mock_merge:
                    with patch("modules.store.worker.record_metric", new=AsyncMock()):
                        await handle_stix_final_message(payload)

        assert mock_merge.called
        assert not mock_insert.called
        assert mock_merge.call_args[0][1] == "indicator--existing-canonical"

    async def test_merge_without_target_does_not_crash(self) -> None:
        from modules.store.worker import handle_stix_final_message

        payload = self._make_final_message(action="merge", target=None)

        with patch("modules.store.worker.get_source_category", new=AsyncMock(return_value="known")):
            with patch("modules.store.worker.merge_object", new=AsyncMock()) as mock_merge:
                with patch("modules.store.worker.record_metric", new=AsyncMock()):
                    await handle_stix_final_message(payload)

        assert not mock_merge.called

    async def test_malformed_message_does_not_crash(self) -> None:
        from modules.store.worker import handle_stix_final_message
        with patch("modules.store.worker.record_metric", new=AsyncMock()):
            await handle_stix_final_message({"bad": "payload"})

    async def test_db_error_does_not_crash_worker(self) -> None:
        from modules.store.worker import handle_stix_final_message

        payload = self._make_final_message(action="insert")

        with patch("modules.store.worker.get_source_category", new=AsyncMock(return_value="known")):
            with patch("modules.store.worker.insert_object", new=AsyncMock(side_effect=Exception("DB down"))):
                with patch("modules.store.worker.record_metric", new=AsyncMock()):
                    # Must not raise
                    await handle_stix_final_message(payload)
