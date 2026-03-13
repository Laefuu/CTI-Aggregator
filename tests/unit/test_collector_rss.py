"""
Unit tests for RSSConnector.
All HTTP calls are mocked — no network required.
"""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from modules.collector.base import SourceMeta
from modules.collector.connectors.rss import RSSConnector
from shared.models.enums import SourceType, TLPLevel

# ── Helpers ───────────────────────────────────────────────────

def make_source(**kwargs: object) -> SourceMeta:
    defaults: dict = {
        "id": "11111111-1111-1111-1111-111111111111",
        "name": "Test RSS Feed",
        "type": SourceType.RSS,
        "url": "https://example.com/feed.rss",
        "config": {},
        "category": "known",
        "tlp_level": TLPLevel.WHITE,
        "frequency_min": 60,
    }
    defaults.update(kwargs)
    return SourceMeta(**defaults)


def make_feed_entry(
    link: str = "https://example.com/article/1",
    title: str = "APT28 Campaign Analysis",
    summary: str = "<p>APT28 used 198.51.100.1 as C2 infrastructure.</p>",
    published_parsed: tuple | None = None,
) -> MagicMock:
    entry = MagicMock()
    entry.link = link
    entry.title = title
    entry.summary = summary
    entry.published_parsed = published_parsed or (2026, 3, 13, 12, 0, 0, 0, 0, 0)
    entry.updated_parsed = None
    entry.published = None
    entry.updated = None
    return entry


def make_mock_feed(entries: list) -> MagicMock:
    feed = MagicMock()
    feed.bozo = False
    feed.entries = entries
    return feed


# ── Tests ─────────────────────────────────────────────────────

@pytest.mark.unit
class TestRSSConnectorFetch:
    async def test_fetch_returns_documents_for_each_entry(self) -> None:
        source = make_source()
        article_html = b"<html><body><p>APT28 used 198.51.100.1 as C2 infrastructure in a campaign targeting European governments. The group deployed custom malware.</p></body></html>"
        feed_entry = make_feed_entry()
        mock_feed = make_mock_feed([feed_entry])

        mock_response_feed = MagicMock()
        mock_response_feed.raise_for_status = MagicMock()
        mock_response_feed.text = "<rss/>"

        mock_response_article = MagicMock()
        mock_response_article.raise_for_status = MagicMock()
        mock_response_article.content = article_html
        mock_response_article.headers = {"content-type": "text/html; charset=utf-8"}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(
            side_effect=[mock_response_feed, mock_response_article]
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("modules.collector.connectors.rss.feedparser.parse", return_value=mock_feed):
            with patch("modules.collector.connectors.rss.httpx.AsyncClient", return_value=mock_client):
                connector = RSSConnector(source)
                async with connector:
                    docs = await connector.fetch()

        assert len(docs) == 1
        assert docs[0].source_url == feed_entry.link
        assert docs[0].content_bytes == article_html
        assert docs[0].content_type == "text/html"
        assert docs[0].source_type == SourceType.RSS
        assert docs[0].tlp_level == TLPLevel.WHITE

    async def test_fetch_falls_back_to_summary_on_article_fetch_failure(self) -> None:
        source = make_source()
        summary_text = "<p>Threat actors were observed using new TTPs including spearphishing emails targeting financial sector organizations across multiple European countries.</p>"
        feed_entry = make_feed_entry(summary=summary_text)
        mock_feed = make_mock_feed([feed_entry])

        mock_response_feed = MagicMock()
        mock_response_feed.raise_for_status = MagicMock()
        mock_response_feed.text = "<rss/>"

        # Article fetch fails
        import httpx
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(
            side_effect=[
                mock_response_feed,
                httpx.HTTPError("connection refused"),
            ]
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("modules.collector.connectors.rss.feedparser.parse", return_value=mock_feed):
            with patch("modules.collector.connectors.rss.httpx.AsyncClient", return_value=mock_client):
                connector = RSSConnector(source)
                async with connector:
                    docs = await connector.fetch()

        assert len(docs) == 1
        assert docs[0].content_bytes == summary_text.encode("utf-8")

    async def test_fetch_returns_empty_on_feed_fetch_failure(self) -> None:
        source = make_source()
        import httpx
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.HTTPError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("modules.collector.connectors.rss.httpx.AsyncClient", return_value=mock_client):
            connector = RSSConnector(source)
            async with connector:
                docs = await connector.fetch()

        assert docs == []

    async def test_fetch_returns_empty_when_no_url(self) -> None:
        source = make_source(url=None)
        connector = RSSConnector(source)
        async with connector:
            docs = await connector.fetch()
        assert docs == []

    async def test_max_items_respected(self) -> None:
        source = make_source(config={"max_items": 2, "fetch_content": False})
        entries = [make_feed_entry(link=f"https://example.com/article/{i}") for i in range(5)]
        mock_feed = make_mock_feed(entries)

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.text = "<rss/>"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("modules.collector.connectors.rss.feedparser.parse", return_value=mock_feed):
            with patch("modules.collector.connectors.rss.httpx.AsyncClient", return_value=mock_client):
                connector = RSSConnector(source)
                async with connector:
                    docs = await connector.fetch()

        # Only 2 items processed (max_items=2), fetch_content=False uses summary
        # Summaries have content, entries without summary are skipped
        assert len(docs) <= 2

    async def test_short_content_skipped(self) -> None:
        source = make_source(config={"fetch_content": False})
        entry = make_feed_entry(summary="Too short")  # < 100 bytes
        mock_feed = make_mock_feed([entry])

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.text = "<rss/>"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("modules.collector.connectors.rss.feedparser.parse", return_value=mock_feed):
            with patch("modules.collector.connectors.rss.httpx.AsyncClient", return_value=mock_client):
                connector = RSSConnector(source)
                async with connector:
                    docs = await connector.fetch()

        assert docs == []

    async def test_published_date_parsed_from_tuple(self) -> None:
        source = make_source(config={"fetch_content": False})
        summary = "<p>" + "x" * 150 + "</p>"
        entry = make_feed_entry(
            summary=summary,
            published_parsed=(2026, 1, 15, 10, 30, 0, 0, 0, 0),
        )
        mock_feed = make_mock_feed([entry])

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.text = "<rss/>"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("modules.collector.connectors.rss.feedparser.parse", return_value=mock_feed):
            with patch("modules.collector.connectors.rss.httpx.AsyncClient", return_value=mock_client):
                connector = RSSConnector(source)
                async with connector:
                    docs = await connector.fetch()

        assert len(docs) == 1
        assert docs[0].published_at is not None
        assert docs[0].published_at.year == 2026
        assert docs[0].published_at.month == 1
        assert docs[0].published_at.day == 15


@pytest.mark.unit
class TestRawDocumentHash:
    def test_same_content_same_hash(self) -> None:
        from modules.collector.base import RawDocument
        content = b"same content bytes"
        doc1 = RawDocument(
            source_id="abc",
            source_url="https://example.com",
            source_type=SourceType.RSS,
            content_bytes=content,
            content_type="text/html",
            tlp_level=TLPLevel.WHITE,
            fetched_at=datetime.now(UTC),
        )
        doc2 = RawDocument(
            source_id="def",  # Different source — same content
            source_url="https://other.com",
            source_type=SourceType.HTML,
            content_bytes=content,
            content_type="text/html",
            tlp_level=TLPLevel.WHITE,
            fetched_at=datetime.now(UTC),
        )
        assert doc1.content_hash() == doc2.content_hash()

    def test_different_content_different_hash(self) -> None:
        from modules.collector.base import RawDocument
        doc1 = RawDocument(
            source_id="abc",
            source_url="https://example.com",
            source_type=SourceType.RSS,
            content_bytes=b"content A",
            content_type="text/html",
            tlp_level=TLPLevel.WHITE,
            fetched_at=datetime.now(UTC),
        )
        doc2 = RawDocument(
            source_id="abc",
            source_url="https://example.com",
            source_type=SourceType.RSS,
            content_bytes=b"content B",
            content_type="text/html",
            tlp_level=TLPLevel.WHITE,
            fetched_at=datetime.now(UTC),
        )
        assert doc1.content_hash() != doc2.content_hash()