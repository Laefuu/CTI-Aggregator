"""Pydantic schemas for /perimeters and /alerts endpoints."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

_SEVERITY_PATTERN = "^(low|medium|high|critical)$"


class PerimeterCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    ioc_values: list[str] = []
    sectors: list[str] = []
    geo_countries: list[str] = []
    software_products: list[str] = []
    ip_ranges: list[str] = []
    severity: str = Field(default="medium", pattern=_SEVERITY_PATTERN)
    enabled: bool = True
    webhook_url: str | None = None


class PerimeterUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    ioc_values: list[str] | None = None
    sectors: list[str] | None = None
    geo_countries: list[str] | None = None
    software_products: list[str] | None = None
    ip_ranges: list[str] | None = None
    severity: str | None = Field(default=None, pattern=_SEVERITY_PATTERN)
    enabled: bool | None = None
    webhook_url: str | None = None


class PerimeterResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: str | None
    ioc_values: list[str]
    sectors: list[str]
    geo_countries: list[str]
    software_products: list[str]
    ip_ranges: list[str]
    severity: str
    enabled: bool
    webhook_url: str | None
    created_at: datetime
    updated_at: datetime


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    perimeter_id: str
    perimeter_name: str
    stix_object_id: str
    stix_id: str
    source_url: str | None
    triggered_at: datetime
    status: str
    severity: str
    notified: bool
    acked_by: str | None
    acked_at: datetime | None


class AlertAck(BaseModel):
    """
    PATCH /alerts/{id} body.
    At least one of status or severity must be provided.
    """
    status: str | None = Field(default=None, pattern="^(acked|false_positive)$")
    severity: str | None = Field(default=None, pattern=_SEVERITY_PATTERN)
