"""
CONNECTOR_REGISTRY — maps SourceType values to connector classes.

Usage:
    from modules.collector.registry import CONNECTOR_REGISTRY
    ConnectorClass = CONNECTOR_REGISTRY[source.type]
    connector = ConnectorClass(source)

Adding a new connector type:
    1. Create modules/collector/connectors/<type>.py with a class extending BaseConnector
    2. Add an entry here
    3. Add the type to SourceType enum in shared/models/enums.py if not present
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from shared.models.enums import SourceType

if TYPE_CHECKING:
    from modules.collector.base import BaseConnector, SourceMeta

# Lazy imports to avoid circular dependencies and speed up startup
# The actual import happens in get_connector()


def get_connector(source_type: SourceType) -> type["BaseConnector"]:
    """
    Return the connector class for a given source type.
    Raises KeyError for unknown types.
    """
    match source_type:
        case SourceType.RSS:
            from modules.collector.connectors.rss import RSSConnector
            return RSSConnector
        case SourceType.HTML:
            from modules.collector.connectors.html import HTMLConnector
            return HTMLConnector
        case SourceType.PDF_URL:
            from modules.collector.connectors.pdf_url import PDFUrlConnector
            return PDFUrlConnector
        case SourceType.PDF_UPLOAD:
            from modules.collector.connectors.pdf_upload import PDFUploadConnector
            return PDFUploadConnector
        case SourceType.MISP:
            from modules.collector.connectors.misp import MISPConnector
            return MISPConnector
        case SourceType.TAXII:
            from modules.collector.connectors.taxii import TAXIIConnector
            return TAXIIConnector
        case _:
            raise KeyError(f"No connector registered for source type: {source_type!r}")
