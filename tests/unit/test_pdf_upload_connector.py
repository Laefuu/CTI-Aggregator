"""Unit tests for PDFUploadConnector — filesystem reads, no network."""
from __future__ import annotations

import pytest

from modules.collector.base import SourceMeta
from shared.models.enums import SourceType, TLPLevel


def make_source(url: str | None = None) -> SourceMeta:
    return SourceMeta(
        id="22222222-2222-2222-2222-222222222222",
        name="Test Upload",
        type=SourceType.PDF_UPLOAD,
        url=url,
        config={},
        category="known",
        tlp_level=TLPLevel.WHITE,
        frequency_min=525600,
    )


@pytest.mark.unit
class TestPDFUploadConnector:
    async def test_fetch_pdf_file(self, tmp_path) -> None:
        from modules.collector.connectors.pdf_upload import PDFUploadConnector
        pdf = tmp_path / "report.pdf"
        pdf.write_bytes(b"%PDF-1.4 fake pdf content")

        connector = PDFUploadConnector(make_source(f"file://{pdf}"))
        docs = await connector.fetch()

        assert len(docs) == 1
        assert docs[0].content_type == "application/pdf"
        assert docs[0].content_bytes == b"%PDF-1.4 fake pdf content"
        assert docs[0].source_type == SourceType.PDF_UPLOAD

    async def test_fetch_txt_file(self, tmp_path) -> None:
        from modules.collector.connectors.pdf_upload import PDFUploadConnector
        txt = tmp_path / "iocs.txt"
        txt.write_bytes(b"1.2.3.4\nevil.com\n")

        connector = PDFUploadConnector(make_source(f"file://{txt}"))
        docs = await connector.fetch()

        assert len(docs) == 1
        assert docs[0].content_type == "text/plain"

    async def test_fetch_html_file(self, tmp_path) -> None:
        from modules.collector.connectors.pdf_upload import PDFUploadConnector
        html = tmp_path / "report.html"
        html.write_bytes(b"<html><body>threat report</body></html>")

        connector = PDFUploadConnector(make_source(f"file://{html}"))
        docs = await connector.fetch()

        assert len(docs) == 1
        assert docs[0].content_type == "text/html"

    async def test_missing_file_returns_empty(self, tmp_path) -> None:
        from modules.collector.connectors.pdf_upload import PDFUploadConnector
        connector = PDFUploadConnector(make_source(f"file://{tmp_path}/nonexistent.pdf"))
        docs = await connector.fetch()
        assert docs == []

    async def test_no_url_returns_empty(self) -> None:
        from modules.collector.connectors.pdf_upload import PDFUploadConnector
        connector = PDFUploadConnector(make_source(url=None))
        docs = await connector.fetch()
        assert docs == []

    async def test_unsupported_extension_returns_empty(self, tmp_path) -> None:
        from modules.collector.connectors.pdf_upload import PDFUploadConnector
        exe = tmp_path / "malware.exe"
        exe.write_bytes(b"MZ\x90\x00")

        connector = PDFUploadConnector(make_source(f"file://{exe}"))
        docs = await connector.fetch()
        assert docs == []

    async def test_oversized_file_returns_empty(self, tmp_path, monkeypatch) -> None:
        from modules.collector.connectors.pdf_upload import PDFUploadConnector
        from shared.config import get_settings

        # Patch max size to 1 byte
        settings = get_settings()
        monkeypatch.setattr(settings, "max_pdf_size_mb", 0)

        big = tmp_path / "big.pdf"
        big.write_bytes(b"%PDF" + b"x" * 1024)

        connector = PDFUploadConnector(make_source(f"file://{big}"))
        docs = await connector.fetch()
        assert docs == []
