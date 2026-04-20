"""
PDFUploadConnector — reads a previously uploaded file from the local filesystem.

The source URL is a file:// URI pointing to the upload directory:
    file:///data/uploads/{uuid}.{ext}

Supports PDF, plain text, and HTML uploads.
The scheduler may call fetch() again on subsequent runs — fetch-level deduplication
(content hash via Redis) in the publisher will skip already-processed files.

Config keys: none required.
"""
from __future__ import annotations

import mimetypes
from datetime import UTC, datetime
from pathlib import Path

import structlog

from modules.collector.base import BaseConnector, RawDocument, SourceMeta
from shared.config import get_settings
from shared.models.enums import SourceType

log = structlog.get_logger()

_SUPPORTED_SUFFIXES = {".pdf", ".txt", ".html", ".htm"}

_SUFFIX_TO_MIME: dict[str, str] = {
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".html": "text/html",
    ".htm": "text/html",
}


class PDFUploadConnector(BaseConnector):
    """Reads an uploaded file from the local filesystem and produces one RawDocument."""

    def __init__(self, source: SourceMeta) -> None:
        super().__init__(source)

    async def fetch(self) -> list[RawDocument]:
        if not self.source.url:
            self._log.error("pdf_upload_no_url")
            return []

        # Strip file:// scheme prefix
        raw_url = self.source.url
        if raw_url.startswith("file://"):
            file_path = Path(raw_url[7:])
        else:
            file_path = Path(raw_url)

        if not file_path.exists():
            self._log.error("pdf_upload_file_not_found", path=str(file_path))
            return []

        suffix = file_path.suffix.lower()
        if suffix not in _SUPPORTED_SUFFIXES:
            self._log.error(
                "pdf_upload_unsupported_extension",
                path=str(file_path),
                suffix=suffix,
            )
            return []

        settings = get_settings()
        max_bytes = settings.max_pdf_size_mb * 1024 * 1024

        try:
            content_bytes = file_path.read_bytes()
        except OSError as exc:
            self._log.error("pdf_upload_read_failed", path=str(file_path), error=str(exc))
            return []

        if len(content_bytes) > max_bytes:
            self._log.warning(
                "pdf_upload_too_large",
                path=str(file_path),
                size_mb=len(content_bytes) // (1024 * 1024),
                limit_mb=settings.max_pdf_size_mb,
            )
            return []

        content_type = _SUFFIX_TO_MIME.get(suffix, "application/octet-stream")

        return [
            RawDocument(
                source_id=self.source.id,
                source_url=self.source.url,
                source_type=SourceType.PDF_UPLOAD,
                content_bytes=content_bytes,
                content_type=content_type,
                tlp_level=self.source.tlp_level,
                fetched_at=datetime.now(UTC),
            )
        ]
