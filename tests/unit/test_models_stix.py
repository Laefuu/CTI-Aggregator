"""
Unit tests for STIX 2.1 Pydantic models (shared/models/stix.py).

These tests cover:
- Valid object acceptance
- Invalid IoC rejection (bad format, private IPs, etc.)
- ID prefix validation
- MITRE ATT&CK ID format validation
- Relationship type validation
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from shared.models.stix import (
    AttackPatternSTIX,
    IndicatorSTIX,
    RelationshipSTIX,
    ThreatActorSTIX,
)

# ── Helpers ───────────────────────────────────────────────────

_NOW = datetime.now(UTC).isoformat()
_BASE = {
    "spec_version": "2.1",
    "created": _NOW,
    "modified": _NOW,
    "x_cti_source_url": "https://example.com/report",
    "x_cti_published_at": _NOW,
}


def make_indicator(pattern: str, **kwargs: object) -> dict:
    return {
        **_BASE,
        "type": "indicator",
        "id": "indicator--12345678-1234-4234-8234-123456789012",
        "name": "Test IoC",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": _NOW,
        **kwargs,
    }


# ── IndicatorSTIX — valid cases ───────────────────────────────

@pytest.mark.unit
class TestIndicatorValid:
    def test_valid_ipv4(self) -> None:
        obj = IndicatorSTIX(**make_indicator("[ipv4-addr:value = '198.51.100.1']"))
        assert obj.type == "indicator"

    def test_valid_ipv6(self) -> None:
        obj = IndicatorSTIX(**make_indicator("[ipv6-addr:value = '2001:db8::1']"))
        assert obj.type == "indicator"

    def test_valid_domain(self) -> None:
        obj = IndicatorSTIX(**make_indicator("[domain-name:value = 'evil-c2.example.com']"))
        assert obj.type == "indicator"

    def test_valid_url(self) -> None:
        obj = IndicatorSTIX(**make_indicator("[url:value = 'https://evil.example.com/payload']"))
        assert obj.type == "indicator"

    def test_valid_sha256(self) -> None:
        sha = "a" * 64
        obj = IndicatorSTIX(**make_indicator(f"[file:hashes.SHA256 = '{sha}']"))
        assert obj.type == "indicator"

    def test_valid_sha1(self) -> None:
        sha = "b" * 40
        obj = IndicatorSTIX(**make_indicator(f"[file:hashes.SHA1 = '{sha}']"))
        assert obj.type == "indicator"

    def test_valid_md5(self) -> None:
        md5 = "c" * 32
        obj = IndicatorSTIX(**make_indicator(f"[file:hashes.MD5 = '{md5}']"))
        assert obj.type == "indicator"

    def test_valid_email(self) -> None:
        obj = IndicatorSTIX(**make_indicator("[email-addr:value = 'phish@evil.com']"))
        assert obj.type == "indicator"

    def test_confidence_bounds(self) -> None:
        obj = IndicatorSTIX(**make_indicator("[ipv4-addr:value = '198.51.100.1']", confidence=100))
        assert obj.confidence == 100
        obj2 = IndicatorSTIX(**make_indicator("[ipv4-addr:value = '198.51.100.1']", confidence=0))
        assert obj2.confidence == 0

    def test_extension_fields_preserved(self) -> None:
        obj = IndicatorSTIX(**make_indicator("[ipv4-addr:value = '198.51.100.1']"))
        assert obj.x_cti_source_url == "https://example.com/report"


# ── IndicatorSTIX — invalid IoC values ───────────────────────

@pytest.mark.unit
class TestIndicatorInvalidIoC:
    def test_private_ip_10_rejected(self) -> None:
        with pytest.raises(ValueError, match="Private IP"):
            IndicatorSTIX(**make_indicator("[ipv4-addr:value = '10.0.0.1']"))

    def test_private_ip_192_168_rejected(self) -> None:
        with pytest.raises(ValueError, match="Private IP"):
            IndicatorSTIX(**make_indicator("[ipv4-addr:value = '192.168.1.1']"))

    def test_private_ip_172_16_rejected(self) -> None:
        with pytest.raises(ValueError, match="Private IP"):
            IndicatorSTIX(**make_indicator("[ipv4-addr:value = '172.16.0.1']"))

    def test_loopback_rejected(self) -> None:
        with pytest.raises(ValueError, match="Private IP"):
            IndicatorSTIX(**make_indicator("[ipv4-addr:value = '127.0.0.1']"))

    def test_malformed_ipv4_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid IPv4"):
            IndicatorSTIX(**make_indicator("[ipv4-addr:value = '999.999.999.999']"))

    def test_invalid_domain_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid domain"):
            IndicatorSTIX(**make_indicator("[domain-name:value = 'not_a_domain']"))

    def test_domain_too_short_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid domain"):
            IndicatorSTIX(**make_indicator("[domain-name:value = 'a.b']"))

    def test_url_no_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="http"):
            IndicatorSTIX(**make_indicator("[url:value = 'ftp://evil.com/payload']"))

    def test_invalid_hash_length_rejected(self) -> None:
        with pytest.raises(ValueError, match="MD5/SHA1/SHA256"):
            IndicatorSTIX(**make_indicator("[file:hashes.SHA256 = 'tooshort']"))

    def test_invalid_email_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid email"):
            IndicatorSTIX(**make_indicator("[email-addr:value = 'not-an-email']"))

    def test_empty_pattern_rejected(self) -> None:
        with pytest.raises(ValueError):
            IndicatorSTIX(**make_indicator(""))


# ── IndicatorSTIX — ID validation ────────────────────────────

@pytest.mark.unit
class TestIndicatorId:
    def test_wrong_prefix_rejected(self) -> None:
        data = make_indicator("[ipv4-addr:value = '198.51.100.1']")
        data["id"] = "threat-actor--12345678-1234-4234-8234-123456789012"
        with pytest.raises(ValueError, match="must start with 'indicator--'"):
            IndicatorSTIX(**data)

    def test_invalid_uuid_suffix_rejected(self) -> None:
        data = make_indicator("[ipv4-addr:value = '198.51.100.1']")
        data["id"] = "indicator--not-a-uuid"
        with pytest.raises(ValueError, match="UUID v4"):
            IndicatorSTIX(**data)


# ── ThreatActorSTIX ───────────────────────────────────────────

@pytest.mark.unit
class TestThreatActorSTIX:
    def test_valid_threat_actor(self) -> None:
        obj = ThreatActorSTIX(**{
            **_BASE,
            "type": "threat-actor",
            "id": "threat-actor--12345678-1234-4234-8234-123456789012",
            "name": "APT28",
            "aliases": ["Fancy Bear", "Sofacy", "Strontium"],
        })
        assert obj.name == "APT28"
        assert len(obj.aliases) == 3

    def test_wrong_id_prefix_rejected(self) -> None:
        with pytest.raises(ValueError, match="must start with 'threat-actor--'"):
            ThreatActorSTIX(**{
                **_BASE,
                "type": "threat-actor",
                "id": "indicator--12345678-1234-4234-8234-123456789012",
                "name": "APT28",
            })

    def test_empty_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            ThreatActorSTIX(**{
                **_BASE,
                "type": "threat-actor",
                "id": "threat-actor--12345678-1234-4234-8234-123456789012",
                "name": "   ",
            })


# ── AttackPatternSTIX ─────────────────────────────────────────

@pytest.mark.unit
class TestAttackPatternSTIX:
    def test_valid_attack_pattern(self) -> None:
        obj = AttackPatternSTIX(**{
            **_BASE,
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-4234-8234-123456789012",
            "name": "PowerShell",
            "x_mitre_id": "T1059",
            "x_mitre_tactic": "execution",
        })
        assert obj.x_mitre_id == "T1059"

    def test_valid_mitre_subtechnique(self) -> None:
        obj = AttackPatternSTIX(**{
            **_BASE,
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-4234-8234-123456789012",
            "name": "PowerShell",
            "x_mitre_id": "T1059.001",
        })
        assert obj.x_mitre_id == "T1059.001"

    def test_invalid_mitre_id_format_rejected(self) -> None:
        with pytest.raises(ValueError, match="MITRE ATT&CK ID"):
            AttackPatternSTIX(**{
                **_BASE,
                "type": "attack-pattern",
                "id": "attack-pattern--12345678-1234-4234-8234-123456789012",
                "name": "PowerShell",
                "x_mitre_id": "T059",  # Too short
            })

    def test_mitre_id_optional(self) -> None:
        obj = AttackPatternSTIX(**{
            **_BASE,
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-4234-8234-123456789012",
            "name": "Spearphishing",
        })
        assert obj.x_mitre_id == ""


# ── RelationshipSTIX ──────────────────────────────────────────

@pytest.mark.unit
class TestRelationshipSTIX:
    def test_valid_relationship(self) -> None:
        obj = RelationshipSTIX(**{
            **_BASE,
            "type": "relationship",
            "id": "relationship--12345678-1234-4234-8234-123456789012",
            "relationship_type": "uses",
            "source_ref": "threat-actor--12345678-1234-4234-8234-123456789012",
            "target_ref": "attack-pattern--12345678-1234-4234-8234-123456789012",
        })
        assert obj.relationship_type == "uses"

    @pytest.mark.parametrize("rel_type", [
        "uses", "indicates", "attributed-to", "targets", "related-to"
    ])
    def test_all_valid_relationship_types(self, rel_type: str) -> None:
        obj = RelationshipSTIX(**{
            **_BASE,
            "type": "relationship",
            "id": "relationship--12345678-1234-4234-8234-123456789012",
            "relationship_type": rel_type,
            "source_ref": "threat-actor--12345678-1234-4234-8234-123456789012",
            "target_ref": "attack-pattern--12345678-1234-4234-8234-123456789012",
        })
        assert obj.relationship_type == rel_type

    def test_invalid_relationship_type_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid relationship_type"):
            RelationshipSTIX(**{
                **_BASE,
                "type": "relationship",
                "id": "relationship--12345678-1234-4234-8234-123456789012",
                "relationship_type": "hacks",  # Not in valid set
                "source_ref": "threat-actor--aaa",
                "target_ref": "attack-pattern--bbb",
            })