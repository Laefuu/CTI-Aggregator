"""
PDFUrlConnector — downloads a PDF from a URL.

Used for sources that publish threat reports as PDF files at stable URLs.
Enforces MAX_PDF_SIZE_MB limit before downloading.

Config keys (source.config):
    timeout:    int — HTTP timeout in seconds (default: 60)
    user_agent: str — override default User-Agent
"""
from __future__ import annotations

from datetime import UTC, datetime

import httpx
import structlog

from modules.collector.base import BaseConnector, RawDocument, SourceMeta
from shared.config import get_settings
from shared.models.enums import SourceType

log = structlog.get_logger()

_DEFAULT_UA = (
    "CTI-Aggregator/0.1 (internal threat intelligence platform; "
    "contact: security@your-org.internal)"
)


class PDFUrlConnector(BaseConnector):
    """Downloads a single PDF from a URL per run."""

    def __init__(self, source: SourceMeta) -> None:
        super().__init__(source)
        self._client: httpx.AsyncClient | None = None
        self._timeout = source.config.get("timeout", 60)
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
            self._log.error("pdf_url_no_url")
            return []

        settings = get_settings()
        max_bytes = settings.max_pdf_size_mb * 1024 * 1024

        try:
            assert self._client is not None
            # Stream the response to check size before loading into memory
            async with self._client.stream("GET", self.source.url) as resp:
                resp.raise_for_status()

                content_type = resp.headers.get("content-type", "").split(";")[0]
                content_length = int(resp.headers.get("content-length", 0))

                if content_length > max_bytes:
                    self._log.warning(
                        "pdf_too_large",
                        url=self.source.url,
                        size_mb=content_length // (1024 * 1024),
                        limit_mb=settings.max_pdf_size_mb,
                    )
                    return []

                chunks: list[bytes] = []
                total = 0
                async for chunk in resp.aiter_bytes(chunk_size=65536):
                    total += len(chunk)
                    if total > max_bytes:
                        self._log.warning(
                            "pdf_too_large_streaming",
                            url=self.source.url,
                            limit_mb=settings.max_pdf_size_mb,
                        )
                        return []
                    chunks.append(chunk)

                content_bytes = b"".join(chunks)

        except Exception as exc:
            self._log.error("pdf_url_fetch_failed", url=self.source.url, error=str(exc))
            return []

        # Basic PDF magic bytes check
        if not content_bytes.startswith(b"%PDF"):
            self._log.warning(
                "pdf_invalid_magic_bytes",
                url=self.source.url,
                first_bytes=content_bytes[:8],
            )
            return []

        return [
            RawDocument(
                source_id=self.source.id,
                source_url=self.source.url,
                source_type=SourceType.PDF_URL,
                content_bytes=content_bytes,
                content_type="application/pdf",
                tlp_level=self.source.tlp_level,
                fetched_at=datetime.now(UTC),
            )
        ]
