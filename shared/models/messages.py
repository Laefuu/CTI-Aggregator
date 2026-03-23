"""
Pydantic models for messages exchanged between modules via Redis Streams.

Rules:
- All message models are frozen (immutable) — never mutate a received message.
- Every module reads the schema for the stream it consumes from this file.
- Never define message schemas inside individual modules.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from shared.models.enums import DedupAction, SourceType, TLPLevel


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True)


# ── cti:raw ───────────────────────────────────────────────────
# Produced by: Collector
# Consumed by: Preprocessor


class RawMessage(_FrozenModel):
    """Raw content collected from a source, before any text extraction."""

    source_id: uuid.UUID
    source_url: str
    source_type: SourceType
    # Base64-encoded raw bytes (HTML, PDF, JSON...)
    content_b64: str
    content_type: str  # MIME type: text/html, application/pdf, application/json
    fetched_at: datetime
    tlp_level: TLPLevel
    metadata: dict[str, Any] = Field(default_factory=dict)


# ── cti:chunks ────────────────────────────────────────────────
# Produced by: Preprocessor
# Consumed by: LLM Normalizer


class ChunkMessage(_FrozenModel):
    """A single text chunk ready for LLM inference."""

    source_id: uuid.UUID
    source_url: str
    source_type: SourceType
    chunk_index: int
    chunk_total: int
    chunk_text: str
    language: str = "en"
    tlp_level: TLPLevel
    published_at: datetime | None = None
    fetched_at: datetime


# ── cti:stix_raw ─────────────────────────────────────────────
# Produced by: LLM Normalizer
# Consumed by: Validator


class StixRawMessage(_FrozenModel):
    """STIX objects as produced by the LLM — not yet validated."""

    source_id: uuid.UUID
    source_url: str
    source_type: SourceType
    tlp_level: TLPLevel
    published_at: datetime | None = None
    fetched_at: datetime
    llm_model: str
    llm_duration_ms: int
    # Raw list of dicts as returned by JSON parsing the LLM output
    stix_objects: list[dict[str, Any]]


# ── cti:stix_valid ────────────────────────────────────────────
# Produced by: Validator
# Consumed by: Deduplicator


class StixValidMessage(_FrozenModel):
    """A single validated STIX object with computed confidence."""

    source_id: uuid.UUID
    source_url: str
    source_type: SourceType
    source_category: str  # trusted / known / unknown
    tlp_level: TLPLevel
    published_at: datetime | None = None
    fetched_at: datetime
    llm_model: str
    llm_duration_ms: int
    confidence: int = Field(ge=0, le=100)
    # The validated STIX object dict
    stix_object: dict[str, Any]


# ── cti:stix_final ────────────────────────────────────────────
# Produced by: Deduplicator
# Consumed by: Store


class StixFinalMessage(_FrozenModel):
    """A STIX object with dedup decision — ready for persistence."""

    source_id: uuid.UUID
    source_url: str
    source_type: SourceType
    source_category: str
    tlp_level: TLPLevel
    published_at: datetime | None = None
    fetched_at: datetime
    llm_model: str
    llm_duration_ms: int
    confidence: int = Field(ge=0, le=100)
    stix_object: dict[str, Any]
    action: DedupAction
    # Populated when action=merge: the stix_id of the existing canonical object
    target_stix_id: str | None = None
    # Embedding vector (1024 dims) — empty list on merge (Store uses target's)
    embedding: list[float] = []
    # "exact" or "semantic" — populated on merge for metrics
    merge_method: str | None = None


# ── cti:enrichment ────────────────────────────────────────────
# Produced by: Store (automatic) or API (manual)
# Consumed by: Enricher


class EnrichmentRequest(_FrozenModel):
    """Request to enrich an indicator with external APIs."""

    stix_id: str
    ioc_type: str   # ipv4-addr, ipv6-addr, file
    ioc_value: str
    requested_by: str = "auto"  # "auto" or user email


# ── cti:alerts ────────────────────────────────────────────────
# Produced by: Store
# Consumed by: API (alerting worker)


class AlertNotification(_FrozenModel):
    """Notification payload for a triggered perimeter alert."""

    alert_id: uuid.UUID
    perimeter_id: uuid.UUID
    perimeter_name: str
    stix_id: str
    ioc_value: str
    ioc_type: str
    confidence: int
    source_url: str
    triggered_at: datetime
    webhook_url: str | None = None
