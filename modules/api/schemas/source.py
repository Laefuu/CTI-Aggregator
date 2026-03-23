"""Pydantic schemas for /sources endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    type: str = Field(pattern="^(rss|html|pdf_url|pdf_upload|misp|taxii)$")
    url: str | None = None
    config: dict[str, Any] = {}
    frequency_min: int = Field(default=60, ge=5, le=10080)
    category: str = Field(default="unknown", pattern="^(trusted|known|unknown)$")
    tlp_level: str = Field(default="WHITE", pattern="^(WHITE|GREEN)$")
    enabled: bool = True


class SourceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    url: str | None = None
    config: dict[str, Any] | None = None
    frequency_min: int | None = Field(default=None, ge=5, le=10080)
    category: str | None = Field(default=None, pattern="^(trusted|known|unknown)$")
    tlp_level: str | None = Field(default=None, pattern="^(WHITE|GREEN)$")
    enabled: bool | None = None


class SourceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    type: str
    url: str | None
    config: dict[str, Any]
    frequency_min: int
    category: str
    tlp_level: str
    enabled: bool
    last_run_at: datetime | None
    last_status: str | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime
