"""
Unit tests for Validator — confidence scoring, hallucination detection,
STIX validation dispatch, worker.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest


# ── Confidence scoring ────────────────────────────────────────

@pytest.mark.unit
class TestConfidenceScore:
    def test_trusted_fresh_single_source(self) -> None:
        from modules.validator.confidence import compute_confidence
        score = compute_confidence(
            source_category="trusted",
            published_at=datetime.now(UTC) - timedelta(hours=1),
            fetched_at=datetime.now(UTC),
        )
        assert score == 70  # 40 + 30 + 0

    def test_trusted_fresh_three_sources(self) -> None:
        from modules.validator.confidence import compute_confidence
        score = compute_confidence(
            source_category="trusted",
            published_at=datetime.now(UTC) - timedelta(hours=1),
            fetched_at=datetime.now(UTC),
            source_count=3,
        )
        assert score == 100  # 40 + 30 + 30

    def test_known_week_old_two_sources(self) -> None:
        from modules.validator.confidence import compute_confidence
        score = compute_confidence(
            source_category="known",
            published_at=datetime.now(UTC) - timedelta(days=3),
            fetched_at=datetime.now(UTC),
            source_count=2,
        )
        assert score == 55  # 20 + 20 + 15

    def test_unknown_old_single_source(self) -> None:
        from modules.validator.confidence import compute_confidence
        score = compute_confidence(
            source_category="unknown",
            published_at=datetime.now(UTC) - timedelta(days=45),
            fetched_at=datetime.now(UTC),
        )
        assert score == 0  # 0 + 0 + 0

    def test_known_30_day_boundary(self) -> None:
        from modules.validator.confidence import compute_confidence
        # Exactly 29 days → still gets 10pts freshness
        score = compute_confidence(
            source_category="known",
            published_at=datetime.now(UTC) - timedelta(days=29),
            fetched_at=datetime.now(UTC),
        )
        assert score == 30  # 20 + 10 + 0

    def test_published_at_none_uses_fetched_at(self) -> None:
        from modules.validator.confidence import compute_confidence
        # fetched_at is now → 30pts freshness
        score = compute_confidence(
            source_category="trusted",
            published_at=None,
            fetched_at=datetime.now(UTC),
        )
        assert score == 70  # 40 + 30 + 0

    def test_score_capped_at_100(self) -> None:
        from modules.validator.confidence import compute_confidence
        score = compute_confidence(
            source_category="trusted",
            published_at=datetime.now(UTC),
            fetched_at=datetime.now(UTC),
            source_count=10,
        )
        assert score <= 100

    def test_score_minimum_zero(self) -> None:
        from modules.validator.confidence import compute_confidence
        score = compute_confidence(
            source_category="unknown",
            published_at=datetime.now(UTC) - timedelta(days=365),
            fetched_at=datetime.now(UTC),
        )
        assert score >= 0


# ── Hallucination detection ───────────────────────────────────

@pytest.mark.unit
class TestHallucinationCheck:
    def test_correct_url_no_warning(self) -> None:
        from modules.validator.hallucination import validate_and_fix_metadata
        obj = {
            "type": "indicator",
            "x_cti_source_url": "https://example.com/report",
            "x_cti_published_at": "2026-01-15T10:00:00Z",
        }
        corrected, warnings = validate_and_fix_metadata(
            obj, "https://example.com/report", "2026-01-15T10:00:00Z"
        )
        assert warnings == []
        assert corrected["x_cti_source_url"] == "https://example.com/report"

    def test_missing_url_corrected(self) -> None:
        from modules.validator.hallucination import validate_and_fix_metadata
        obj = {"type": "indicator", "x_cti_published_at": "2026-01-15T10:00:00Z"}
        corrected, warnings = validate_and_fix_metadata(
            obj, "https://example.com/report", "2026-01-15T10:00:00Z"
        )
        assert len(warnings) == 1
        assert corrected["x_cti_source_url"] == "https://example.com/report"

    def test_hallucinated_url_corrected(self) -> None:
        from modules.validator.hallucination import validate_and_fix_metadata
        obj = {
            "type": "indicator",
            "x_cti_source_url": "https://hallucinated.evil.com/fake",
            "x_cti_published_at": "2026-01-15T10:00:00Z",
        }
        corrected, warnings = validate_and_fix_metadata(
            obj, "https://example.com/report", "2026-01-15T10:00:00Z"
        )
        assert len(warnings) == 1
        assert "mismatch" in warnings[0]
        assert corrected["x_cti_source_url"] == "https://example.com/report"

    def test_missing_published_at_corrected(self) -> None:
        from modules.validator.hallucination import validate_and_fix_metadata
        obj = {"type": "indicator", "x_cti_source_url": "https://example.com/report"}
        corrected, warnings = validate_and_fix_metadata(
            obj, "https://example.com/report", "2026-01-15T10:00:00Z"
        )
        assert len(warnings) == 1
        assert corrected["x_cti_published_at"] == "2026-01-15T10:00:00Z"

    def test_url_trailing_slash_normalized(self) -> None:
        from modules.validator.hallucination import validate_and_fix_metadata
        obj = {
            "type": "indicator",
            "x_cti_source_url": "https://example.com/report/",  # trailing slash
            "x_cti_published_at": "2026-01-15T10:00:00Z",
        }
        corrected, warnings = validate_and_fix_metadata(
            obj, "https://example.com/report", "2026-01-15T10:00:00Z"
        )
        # Trailing slash difference → no warning (normalized)
        assert warnings == []

    def test_original_object_not_mutated(self) -> None:
        from modules.validator.hallucination import validate_and_fix_metadata
        obj = {"type": "indicator", "x_cti_source_url": "https://wrong.com"}
        original = dict(obj)
        validate_and_fix_metadata(obj, "https://example.com", "2026-01-15T00:00:00Z")
        assert obj == original  # Original dict unchanged


# ── STIX validation dispatch ──────────────────────────────────

@pytest.mark.unit
class TestStixValidatorDispatch:
    def _valid_indicator(self) -> dict:
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--12345678-1234-4234-8234-123456789012",
            "created": "2026-01-15T10:00:00Z",
            "modified": "2026-01-15T10:00:00Z",
            "name": "C2 IP",
            "pattern": "[ipv4-addr:value = '198.51.100.1']",
            "pattern_type": "stix",
            "valid_from": "2026-01-15T10:00:00Z",
            "x_cti_source_url": "https://example.com",
            "x_cti_published_at": "2026-01-15T10:00:00Z",
        }

    def test_valid_indicator_passes(self) -> None:
        from modules.validator.stix_validator import validate_stix_object
        result = validate_stix_object(self._valid_indicator())
        assert result.valid
        assert result.obj is not None
        assert result.obj["type"] == "indicator"

    def test_invalid_indicator_fails(self) -> None:
        from modules.validator.stix_validator import validate_stix_object
        bad = self._valid_indicator()
        bad["pattern"] = "[ipv4-addr:value = '10.0.0.1']"  # Private IP
        result = validate_stix_object(bad)
        assert not result.valid
        assert result.error is not None

    def test_missing_type_fails(self) -> None:
        from modules.validator.stix_validator import validate_stix_object
        result = validate_stix_object({"spec_version": "2.1", "id": "indicator--abc"})
        assert not result.valid

    def test_unsupported_type_skipped(self) -> None:
        from modules.validator.stix_validator import validate_stix_object
        result = validate_stix_object({"type": "malware", "id": "malware--abc"})
        assert result.skipped
        assert not result.valid

    def test_valid_threat_actor_passes(self) -> None:
        from modules.validator.stix_validator import validate_stix_object
        result = validate_stix_object({
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": "threat-actor--12345678-1234-4234-8234-123456789012",
            "created": "2026-01-15T10:00:00Z",
            "modified": "2026-01-15T10:00:00Z",
            "name": "APT28",
            "x_cti_source_url": "https://example.com",
            "x_cti_published_at": "2026-01-15T10:00:00Z",
        })
        assert result.valid

    def test_valid_attack_pattern_passes(self) -> None:
        from modules.validator.stix_validator import validate_stix_object
        result = validate_stix_object({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--12345678-1234-4234-8234-123456789012",
            "created": "2026-01-15T10:00:00Z",
            "modified": "2026-01-15T10:00:00Z",
            "name": "PowerShell",
            "x_mitre_id": "T1059",
            "x_cti_source_url": "https://example.com",
            "x_cti_published_at": "2026-01-15T10:00:00Z",
        })
        assert result.valid


# ── Worker ────────────────────────────────────────────────────

@pytest.mark.unit
class TestValidatorWorker:
    def _make_raw_message(self, stix_objects: list) -> dict:
        import uuid
        return {
            "source_id": str(uuid.uuid4()),
            "source_url": "https://example.com/report",
            "source_type": "rss",
            "tlp_level": "WHITE",
            "published_at": "2026-01-15T10:00:00+00:00",
            "fetched_at": datetime.now(UTC).isoformat(),
            "llm_model": "mistral:7b-instruct-q4_K_M",
            "llm_duration_ms": 5000,
            "stix_objects": stix_objects,
        }

    def _valid_indicator(self) -> dict:
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--12345678-1234-4234-8234-123456789012",
            "created": "2026-01-15T10:00:00Z",
            "modified": "2026-01-15T10:00:00Z",
            "name": "C2 IP",
            "pattern": "[ipv4-addr:value = '198.51.100.1']",
            "pattern_type": "stix",
            "valid_from": "2026-01-15T10:00:00Z",
            "x_cti_source_url": "https://example.com/report",
            "x_cti_published_at": "2026-01-15T10:00:00Z",
        }

    async def test_valid_object_published_to_stix_valid(self) -> None:
        from modules.validator.worker import handle_stix_raw_message
        from shared.queue import STREAM_STIX_VALID

        payload = self._make_raw_message([self._valid_indicator()])
        published: list[dict] = []

        async def mock_publish(stream: str, data: dict) -> str:
            published.append({"stream": stream, "data": data})
            return "1234-0"

        with patch("modules.validator.worker.publish", side_effect=mock_publish):
            with patch("modules.validator.worker.record_metric", new=AsyncMock()):
                await handle_stix_raw_message(payload)

        valid_msgs = [p for p in published if p["stream"] == STREAM_STIX_VALID]
        assert len(valid_msgs) == 1
        assert "stix_object" in valid_msgs[0]["data"]
        assert valid_msgs[0]["data"]["confidence"] >= 0

    async def test_invalid_object_published_to_stix_rejected(self) -> None:
        from modules.validator.worker import handle_stix_raw_message
        from shared.queue import STREAM_STIX_REJECTED

        bad_indicator = self._valid_indicator()
        bad_indicator["pattern"] = "[ipv4-addr:value = '192.168.1.1']"  # Private IP

        payload = self._make_raw_message([bad_indicator])
        published: list[dict] = []

        async def mock_publish(stream: str, data: dict) -> str:
            published.append({"stream": stream, "data": data})
            return "1234-0"

        with patch("modules.validator.worker.publish", side_effect=mock_publish):
            with patch("modules.validator.worker.record_metric", new=AsyncMock()):
                await handle_stix_raw_message(payload)

        rejected_msgs = [p for p in published if p["stream"] == STREAM_STIX_REJECTED]
        assert len(rejected_msgs) == 1
        assert "reason" in rejected_msgs[0]["data"]

    async def test_mixed_objects_routed_correctly(self) -> None:
        from modules.validator.worker import handle_stix_raw_message
        from shared.queue import STREAM_STIX_VALID, STREAM_STIX_REJECTED

        bad = self._valid_indicator()
        bad["pattern"] = "[ipv4-addr:value = '10.0.0.1']"

        payload = self._make_raw_message([self._valid_indicator(), bad])
        published: list[dict] = []

        async def mock_publish(stream: str, data: dict) -> str:
            published.append({"stream": stream, "data": data})
            return "1234-0"

        with patch("modules.validator.worker.publish", side_effect=mock_publish):
            with patch("modules.validator.worker.record_metric", new=AsyncMock()):
                await handle_stix_raw_message(payload)

        assert sum(1 for p in published if p["stream"] == STREAM_STIX_VALID) == 1
        assert sum(1 for p in published if p["stream"] == STREAM_STIX_REJECTED) == 1

    async def test_malformed_message_does_not_crash(self) -> None:
        from modules.validator.worker import handle_stix_raw_message
        with patch("modules.validator.worker.record_metric", new=AsyncMock()):
            await handle_stix_raw_message({"bad": "payload"})
