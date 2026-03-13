"""
RSSConnector — fetches items from an RSS/Atom feed.

For each feed entry, fetches the full article HTML from entry.link
(not the feed excerpt). Falls back to entry.summary if the HTTP fetch fails.

Config keys (source.config):
    user_agent:     str  — override default User-Agent
    timeout:        int  — HTTP timeout in seconds (default: 30)
    max_items:      int  — max items per run (default: 20, 0 = unlimited)
    fetch_content:  bool — fetch full article HTML (default: true)
"""
from __future__ import annotations

import base64
from datetime import UTC, datetime, timezone
from email.utils import parsedate_to_datetime

import feedparser
import httpx
import structlog

from modules.collector.base import BaseConnector, RawDocument, SourceMeta
from shared.models.enums import SourceType

log = structlog.get_logger()

_DEFAULT_UA = (
    "CTI-Aggregator/0.1 (internal threat intelligence platform; "
    "contact: security@your-org.internal)"
)


class RSSConnector(BaseConnector):
    """Fetches full article content from RSS/Atom feeds."""

    def __init__(self, source: SourceMeta) -> None:
        super().__init__(source)
        self._client: httpx.AsyncClient | None = None
        self._timeout = source.config.get("timeout", 30)
        self._max_items: int = source.config.get("max_items", 20)
        self._fetch_content: bool = source.config.get("fetch_content", True)
        self._user_agent: str = source.config.get("user_agent", _DEFAULT_UA)

    async def setup(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,
            headers={"User-Agent": self._user_agent},
            limits=httpx.Limits(max_connections=5),
        )

    async def teardown(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def fetch(self) -> list[RawDocument]:
        if not self.source.url:
            self._log.error("rss_no_url")
            return []

        # 1. Fetch and parse the feed
        try:
            assert self._client is not None
            resp = await self._client.get(self.source.url)
            resp.raise_for_status()
            feed = feedparser.parse(resp.text)
        except Exception as exc:
            self._log.error("rss_feed_fetch_failed", url=self.source.url, error=str(exc))
            return []

        if feed.bozo and not feed.entries:
            self._log.warning("rss_feed_parse_error", url=self.source.url)
            return []

        entries = feed.entries
        if self._max_items > 0:
            entries = entries[: self._max_items]

        self._log.info("rss_feed_fetched", url=self.source.url, entry_count=len(entries))

        # 2. For each entry, fetch the full article or fall back to summary
        documents: list[RawDocument] = []
        for entry in entries:
            doc = await self._process_entry(entry)
            if doc is not None:
                documents.append(doc)

        self._log.info("rss_documents_produced", count=len(documents))
        return documents

    async def _process_entry(self, entry: object) -> RawDocument | None:
        entry_url: str = getattr(entry, "link", "") or ""
        summary: str = getattr(entry, "summary", "") or ""
        published_at = self._parse_published(entry)

        if not entry_url and not summary:
            return None

        # Try to fetch the full article HTML
        content_bytes: bytes | None = None
        content_type = "text/html"

        if self._fetch_content and entry_url and self._client:
            try:
                resp = await self._client.get(entry_url)
                resp.raise_for_status()
                content_bytes = resp.content
                content_type = resp.headers.get("content-type", "text/html").split(";")[0]
            except Exception as exc:
                self._log.debug(
                    "rss_article_fetch_failed",
                    url=entry_url,
                    error=str(exc),
                )

        # Fall back to feed summary
        if content_bytes is None:
            if not summary:
                return None
            content_bytes = summary.encode("utf-8")
            content_type = "text/html"

        # Enforce minimum content size
        if len(content_bytes) < 100:
            self._log.debug("rss_content_too_short", url=entry_url, size=len(content_bytes))
            return None

        return RawDocument(
            source_id=self.source.id,
            source_url=entry_url or self.source.url or "",
            source_type=SourceType.RSS,
            content_bytes=content_bytes,
            content_type=content_type,
            tlp_level=self.source.tlp_level,
            fetched_at=datetime.now(UTC),
            published_at=published_at,
            metadata={
                "feed_url": self.source.url,
                "entry_title": getattr(entry, "title", ""),
            },
        )

    @staticmethod
    def _parse_published(entry: object) -> datetime | None:
        """Parse the published/updated date from a feedparser entry."""
        # feedparser provides parsed time tuples
        for attr in ("published_parsed", "updated_parsed"):
            t = getattr(entry, attr, None)
            if t is not None:
                try:
                    return datetime(*t[:6], tzinfo=UTC)
                except Exception:
                    pass

        # Fallback: raw string
        for attr in ("published", "updated"):
            s = getattr(entry, attr, None)
            if s:
                try:
                    return parsedate_to_datetime(s).astimezone(UTC)
                except Exception:
                    pass

        return None
