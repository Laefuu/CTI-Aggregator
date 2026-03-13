"""
HTMLConnector — fetches a single static HTML page.

Used for sources that don't have an RSS feed but publish at a stable URL
(e.g. a vendor blog index page, a government advisory page).

The full HTML bytes are passed to the Preprocessor for content extraction.

Config keys (source.config):
    user_agent: str — override default User-Agent
    timeout:    int — HTTP timeout in seconds (default: 30)
"""
from __future__ import annotations

from datetime import UTC, datetime

import httpx
import structlog

from modules.collector.base import BaseConnector, RawDocument, SourceMeta
from shared.models.enums import SourceType

log = structlog.get_logger()

_DEFAULT_UA = (
    "CTI-Aggregator/0.1 (internal threat intelligence platform; "
    "contact: security@your-org.internal)"
)


class HTMLConnector(BaseConnector):
    """Fetches a single HTML page per run."""

    def __init__(self, source: SourceMeta) -> None:
        super().__init__(source)
        self._client: httpx.AsyncClient | None = None
        self._timeout = source.config.get("timeout", 30)
        self._user_agent: str = source.config.get("user_agent", _DEFAULT_UA)

    async def setup(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,
            headers={"User-Agent": self._user_agent},
        )

    async def teardown(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def fetch(self) -> list[RawDocument]:
        if not self.source.url:
            self._log.error("html_no_url")
            return []

        try:
            assert self._client is not None
            resp = await self._client.get(self.source.url)
            resp.raise_for_status()
        except Exception as exc:
            self._log.error("html_fetch_failed", url=self.source.url, error=str(exc))
            return []

        content_type = resp.headers.get("content-type", "text/html").split(";")[0]

        if len(resp.content) < 100:
            self._log.warning("html_content_too_short", url=self.source.url)
            return []

        return [
            RawDocument(
                source_id=self.source.id,
                source_url=self.source.url,
                source_type=SourceType.HTML,
                content_bytes=resp.content,
                content_type=content_type,
                tlp_level=self.source.tlp_level,
                fetched_at=datetime.now(UTC),
            )
        ]
