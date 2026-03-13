"""
Pydantic models for STIX 2.1 object validation.

Used by the Validator module to parse and validate LLM output.
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ── Regex patterns ────────────────────────────────────────────

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
_SHA1_RE   = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
_MD5_RE    = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
_EMAIL_RE  = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_UUID_RE   = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# RFC 1918 + loopback — reject as offensive IoC
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


# ── Base STIX object ──────────────────────────────────────────

class _BaseSTIX(BaseModel):
    model_config = ConfigDict(extra="allow")  # Allow x_cti_* extension fields

    type: str
    spec_version: Literal["2.1"]
    id: str
    created: datetime
    modified: datetime
    # Extension fields injected by the LLM prompt
    x_cti_source_url: str = ""
    x_cti_published_at: str = ""

    @field_validator("id")
    @classmethod
    def validate_id_prefix(cls, v: str, info: Any) -> str:
        # The type may not be set yet during validation — rely on subclass prefix checks
        return v


# ── Indicator ─────────────────────────────────────────────────

class IndicatorSTIX(_BaseSTIX):
    type: Literal["indicator"]
    name: str
    pattern: str
    pattern_type: Literal["stix"]
    valid_from: datetime
    confidence: int = Field(default=50, ge=0, le=100)

    @field_validator("id")
    @classmethod
    def validate_indicator_id(cls, v: str) -> str:
        if not v.startswith("indicator--"):
            raise ValueError("Indicator id must start with 'indicator--'")
        suffix = v.removeprefix("indicator--")
        if not _UUID_RE.match(suffix):
            raise ValueError(f"Indicator id suffix is not a valid UUID v4: {suffix}")
        return v

    @field_validator("pattern")
    @classmethod
    def validate_pattern_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("pattern must not be empty")
        return v

    def extract_ioc_type_and_value(self) -> tuple[str, str] | None:
        """
        Parse the STIX pattern and return (ioc_type, ioc_value).
        Returns None if the pattern cannot be parsed.

        Supports patterns like:
          [ipv4-addr:value = '1.2.3.4']
          [domain-name:value = 'evil.com']
          [file:hashes.SHA256 = 'abc...']
          [url:value = 'http://...']
          [email-addr:value = 'phish@evil.com']
        """
        p = self.pattern.strip().lstrip("[").rstrip("]")
        try:
            type_part, rest = p.split(":", 1)
            _, value_part = rest.split("=", 1)
            value = value_part.strip().strip("'\"")
            return type_part.strip(), value
        except ValueError:
            return None

    @model_validator(mode="after")
    def validate_ioc_value(self) -> "IndicatorSTIX":
        parsed = self.extract_ioc_type_and_value()
        if parsed is None:
            raise ValueError(f"Cannot parse STIX pattern: {self.pattern}")

        ioc_type, value = parsed

        match ioc_type:
            case "ipv4-addr":
                try:
                    ipaddress.IPv4Address(value)
                except ValueError as e:
                    raise ValueError(f"Invalid IPv4 address: {value}") from e
                if _is_private_ip(value):
                    raise ValueError(f"Private IP address rejected as IoC: {value}")

            case "ipv6-addr":
                try:
                    ipaddress.IPv6Address(value)
                except ValueError as e:
                    raise ValueError(f"Invalid IPv6 address: {value}") from e
                if _is_private_ip(value):
                    raise ValueError(f"Private IPv6 address rejected as IoC: {value}")

            case "domain-name":
                if not _DOMAIN_RE.match(value):
                    raise ValueError(f"Invalid domain name: {value}")
                if len(value) < 5:
                    raise ValueError(f"Domain name too short: {value}")

            case "url":
                if not (value.startswith("http://") or value.startswith("https://")):
                    raise ValueError(f"URL must start with http:// or https://: {value}")

            case "email-addr":
                if not _EMAIL_RE.match(value):
                    raise ValueError(f"Invalid email address: {value}")

            case "file":
                # For file patterns, value contains the hash — validated separately
                # The pattern looks like: [file:hashes.SHA256 = 'abc...']
                if _SHA256_RE.match(value):
                    pass
                elif _SHA1_RE.match(value):
                    pass
                elif _MD5_RE.match(value):
                    pass
                else:
                    raise ValueError(f"File hash does not match MD5/SHA1/SHA256 format: {value}")

        return self


# ── Threat Actor ─────────────────────────────────────────────

class ThreatActorSTIX(_BaseSTIX):
    type: Literal["threat-actor"]
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    threat_actor_types: list[str] = Field(default_factory=list)
    confidence: int = Field(default=50, ge=0, le=100)

    @field_validator("id")
    @classmethod
    def validate_threat_actor_id(cls, v: str) -> str:
        if not v.startswith("threat-actor--"):
            raise ValueError("ThreatActor id must start with 'threat-actor--'")
        return v

    @field_validator("name")
    @classmethod
    def validate_name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Threat actor name must not be empty")
        return v


# ── Attack Pattern ────────────────────────────────────────────

class AttackPatternSTIX(_BaseSTIX):
    type: Literal["attack-pattern"]
    name: str
    description: str = ""
    # MITRE ATT&CK ID (e.g. "T1059")
    x_mitre_id: str = ""
    x_mitre_tactic: str = ""
    kill_chain_phases: list[dict[str, str]] = Field(default_factory=list)
    confidence: int = Field(default=50, ge=0, le=100)

    @field_validator("id")
    @classmethod
    def validate_attack_pattern_id(cls, v: str) -> str:
        if not v.startswith("attack-pattern--"):
            raise ValueError("AttackPattern id must start with 'attack-pattern--'")
        return v

    @field_validator("x_mitre_id")
    @classmethod
    def validate_mitre_id_format(cls, v: str) -> str:
        if v and not re.match(r"^T\d{4}(\.\d{3})?$", v):
            raise ValueError(f"Invalid MITRE ATT&CK ID format: {v} (expected T1234 or T1234.001)")
        return v


# ── Relationship ─────────────────────────────────────────────

_VALID_RELATIONSHIP_TYPES = frozenset({
    "uses", "indicates", "attributed-to", "targets", "related-to",
})


class RelationshipSTIX(_BaseSTIX):
    type: Literal["relationship"]
    relationship_type: str
    source_ref: str
    target_ref: str

    @field_validator("id")
    @classmethod
    def validate_relationship_id(cls, v: str) -> str:
        if not v.startswith("relationship--"):
            raise ValueError("Relationship id must start with 'relationship--'")
        return v

    @field_validator("relationship_type")
    @classmethod
    def validate_relationship_type(cls, v: str) -> str:
        if v not in _VALID_RELATIONSHIP_TYPES:
            raise ValueError(
                f"Invalid relationship_type '{v}'. "
                f"Valid types: {sorted(_VALID_RELATIONSHIP_TYPES)}"
            )
        return v
