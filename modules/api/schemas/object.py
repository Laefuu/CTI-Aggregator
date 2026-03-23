"""Pydantic schemas for /objects endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StixObjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    stix_id: str
    stix_type: str
    stix_data: dict[str, Any]
    confidence: int
    tlp_level: str
    is_merged: bool
    merged_into: str | None
    created_at: datetime
    modified_at: datetime
    source_count: int = 0


class StixObjectListResponse(BaseModel):
    items: list[StixObjectResponse]
    total: int
    page: int
    page_size: int
