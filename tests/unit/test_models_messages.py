"""
Unit tests for inter-module message schemas (shared/models/messages.py).

Verifies that message models are correctly frozen (immutable)
and that all required fields are validated.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from shared.models.enums import DedupAction, SourceType, TLPLevel
from shared.models.messages import (
    ChunkMessage,
    RawMessage,
    StixFinalMessage,
    StixRawMessage,
    StixValidMessage,
)

_NOW = datetime.now(UTC)
_SOURCE_ID = uuid.uuid4()


@pytest.mark.unit
class TestRawMessage:
    def test_valid_raw_message(self) -> None:
        msg = RawMessage(
            source_id=_SOURCE_ID,
            source_url="https://example.com/report",
            source_type=SourceType.RSS,
            content_b64="SGVsbG8gV29ybGQ=",
            content_type="text/html",
            fetched_at=_NOW,
            tlp_level=TLPLevel.WHITE,
        )
        assert msg.source_type == SourceType.RSS
        assert msg.tlp_level == TLPLevel.WHITE

    def test_raw_message_is_frozen(self) -> None:
        msg = RawMessage(
            source_id=_SOURCE_ID,
            source_url="https://example.com",
            source_type=SourceType.HTML,
            content_b64="dGVzdA==",
            content_type="text/html",
            fetched_at=_NOW,
            tlp_level=TLPLevel.GREEN,
        )
        with pytest.raises(Exception):  # ValidationError or TypeError on frozen model
            msg.source_url = "https://other.com"  # type: ignore[misc]

    def test_metadata_defaults_to_empty_dict(self) -> None:
        msg = RawMessage(
            source_id=_SOURCE_ID,
            source_url="https://example.com",
            source_type=SourceType.PDF_URL,
            content_b64="dGVzdA==",
            content_type="application/pdf",
            fetched_at=_NOW,
            tlp_level=TLPLevel.WHITE,
        )
        assert msg.metadata == {}


@pytest.mark.unit
class TestChunkMessage:
    def test_valid_chunk(self) -> None:
        msg = ChunkMessage(
            source_id=_SOURCE_ID,
            source_url="https://example.com/report",
            source_type=SourceType.RSS,
            chunk_index=0,
            chunk_total=3,
            chunk_text="APT28 used 198.51.100.1 as C2 infrastructure.",
            fetched_at=_NOW,
            tlp_level=TLPLevel.WHITE,
        )
        assert msg.chunk_index == 0
        assert msg.chunk_total == 3
        assert msg.language == "en"  # default

    def test_chunk_is_frozen(self) -> None:
        msg = ChunkMessage(
            source_id=_SOURCE_ID,
            source_url="https://example.com",
            source_type=SourceType.RSS,
            chunk_index=0,
            chunk_total=1,
            chunk_text="text",
            fetched_at=_NOW,
            tlp_level=TLPLevel.WHITE,
        )
        with pytest.raises(Exception):
            msg.chunk_text = "modified"  # type: ignore[misc]


@pytest.mark.unit
class TestStixFinalMessage:
    def test_insert_action(self) -> None:
        msg = StixFinalMessage(
            source_id=_SOURCE_ID,
            source_url="https://example.com",
            source_type=SourceType.RSS,
            source_category="known",
            tlp_level=TLPLevel.WHITE,
            fetched_at=_NOW,
            llm_model="llama3.3:70b-instruct-q4_K_M",
            llm_duration_ms=24300,
            confidence=65,
            stix_object={"type": "indicator", "id": "indicator--abc"},
            action=DedupAction.INSERT,
        )
        assert msg.action == DedupAction.INSERT
        assert msg.target_stix_id is None

    def test_merge_action_with_target(self) -> None:
        target_id = "indicator--12345678-1234-4234-8234-123456789012"
        msg = StixFinalMessage(
            source_id=_SOURCE_ID,
            source_url="https://example.com",
            source_type=SourceType.RSS,
            source_category="trusted",
            tlp_level=TLPLevel.WHITE,
            fetched_at=_NOW,
            llm_model="llama3.3:70b-instruct-q4_K_M",
            llm_duration_ms=18000,
            confidence=80,
            stix_object={"type": "indicator", "id": "indicator--abc"},
            action=DedupAction.MERGE,
            target_stix_id=target_id,
        )
        assert msg.action == DedupAction.MERGE
        assert msg.target_stix_id == target_id

    def test_confidence_bounds_enforced(self) -> None:
        with pytest.raises(Exception):  # ValidationError
            StixFinalMessage(
                source_id=_SOURCE_ID,
                source_url="https://example.com",
                source_type=SourceType.RSS,
                source_category="known",
                tlp_level=TLPLevel.WHITE,
                fetched_at=_NOW,
                llm_model="model",
                llm_duration_ms=1000,
                confidence=150,  # Out of bounds
                stix_object={},
                action=DedupAction.INSERT,
            )
