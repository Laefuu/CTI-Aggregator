"""
BaseConnector — abstract base class for all CTI source connectors.

Each connector type (RSS, HTML, PDF, MISP, TAXII) subclasses this.
One BaseConnector instance is created per configured source row.

Lifecycle:
    connector = RSSConnector(source)
    async with connector:          # __aenter__ sets up httpx client
        raw = await connector.fetch()
    # __aexit__ closes client

The fetch() method returns a list of RawDocument objects.
The Scheduler calls fetch() and publishes each document to cti:raw.
"""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict

from shared.models.enums import SourceType, TLPLevel

log = structlog.get_logger()


class SourceMeta(BaseModel):
    """Immutable snapshot of a sources row — passed to each connector instance."""

    model_config = ConfigDict(frozen=True)

    id: str                         # UUID as string
    name: str
    type: SourceType
    url: str | None
    config: dict[str, Any]
    category: str                   # trusted / known / unknown
    tlp_level: TLPLevel
    frequency_min: int


class RawDocument(BaseModel):
    """
    A single raw document produced by a connector.

    content_bytes is the raw bytes of the document (HTML, PDF, JSON feed item…).
    The Preprocessor will handle text extraction and language detection.
    """

    model_config = ConfigDict(frozen=True)

    source_id: str
    source_url: str
    source_type: SourceType
    content_bytes: bytes
    content_type: str               # MIME: text/html, application/pdf, application/json
    tlp_level: TLPLevel
    fetched_at: datetime
    published_at: datetime | None = None
    metadata: dict[str, Any] = {}

    def content_hash(self) -> str:
        """SHA-256 of the raw content — used for fetch deduplication."""
        return hashlib.sha256(self.content_bytes).hexdigest()


class BaseConnector(ABC):
    """
    Abstract base class for all source connectors.

    Subclasses must implement:
        - fetch() → list[RawDocument]

    Subclasses may override:
        - setup()    — called once on __aenter__
        - teardown() — called once on __aexit__
    """

    def __init__(self, source: SourceMeta) -> None:
        self.source = source
        self._log = log.bind(
            connector=type(self).__name__,
            source_id=source.id,
            source_name=source.name,
        )

    async def __aenter__(self) -> "BaseConnector":
        await self.setup()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.teardown()

    async def setup(self) -> None:
        """Override to initialise resources (HTTP client, auth session…)."""

    async def teardown(self) -> None:
        """Override to release resources."""

    @abstractmethod
    async def fetch(self) -> list[RawDocument]:
        """
        Fetch documents from the source.

        Returns a list of RawDocument objects ready to publish to cti:raw.
        Must be idempotent — the Scheduler may call this multiple times.
        Must NOT raise — catch exceptions internally and return [] on failure.
        """

    def _now(self) -> datetime:
        return datetime.now(UTC)
