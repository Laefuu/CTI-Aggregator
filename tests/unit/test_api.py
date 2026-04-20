"""Unit tests for API — auth, schemas, route logic. No DB required."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Auth utilities ────────────────────────────────────────────

@pytest.mark.unit
class TestAuthUtilities:
    def test_hash_and_verify_password(self) -> None:
        from modules.api.auth import hash_password, verify_password
        hashed = hash_password("secret123")
        assert verify_password("secret123", hashed)
        assert not verify_password("wrong", hashed)

    def test_create_and_decode_token(self) -> None:
        from modules.api.auth import create_access_token, decode_access_token
        token, expires_in = create_access_token("user-uuid-123", "analyst@org.internal")
        assert isinstance(token, str) and len(token) > 20
        assert expires_in == 8 * 3600
        payload = decode_access_token(token)
        assert payload["sub"] == "user-uuid-123"
        assert payload["email"] == "analyst@org.internal"

    def test_expired_token_raises(self) -> None:
        from jose import JWTError, jwt
        from modules.api.auth import decode_access_token
        from shared.config import get_settings
        settings = get_settings()
        expired_token = jwt.encode(
            {"sub": "u", "email": "e@e.com", "exp": datetime.now(UTC) - timedelta(hours=1)},
            settings.jwt_secret, algorithm="HS256",
        )
        with pytest.raises(JWTError):
            decode_access_token(expired_token)

    def test_tampered_token_raises(self) -> None:
        from jose import JWTError
        from modules.api.auth import create_access_token, decode_access_token
        token, _ = create_access_token("u", "e@e.com")
        with pytest.raises(JWTError):
            decode_access_token(token[:-5] + "XXXXX")


# ── Schemas ───────────────────────────────────────────────────

@pytest.mark.unit
class TestSourceSchemas:
    def test_valid_source_create(self) -> None:
        from modules.api.schemas.source import SourceCreate
        s = SourceCreate(name="ANSSI RSS", type="rss", url="https://cert.ssi.gouv.fr/feed/",
                         frequency_min=60, category="trusted")
        assert s.category == "trusted"
        assert s.tlp_level == "WHITE"

    def test_invalid_source_type(self) -> None:
        from pydantic import ValidationError
        from modules.api.schemas.source import SourceCreate
        with pytest.raises(ValidationError):
            SourceCreate(name="Test", type="unknown_type")

    def test_invalid_frequency(self) -> None:
        from pydantic import ValidationError
        from modules.api.schemas.source import SourceCreate
        with pytest.raises(ValidationError):
            SourceCreate(name="Test", type="rss", frequency_min=1)

    def test_source_update_partial(self) -> None:
        from modules.api.schemas.source import SourceUpdate
        u = SourceUpdate(enabled=False)
        assert u.model_dump(exclude_none=True) == {"enabled": False}


@pytest.mark.unit
class TestPerimeterSchemas:
    def test_valid_perimeter(self) -> None:
        from modules.api.schemas.perimeter import PerimeterCreate
        p = PerimeterCreate(name="Finance", ioc_values=["1.2.3.4", "evil.com"])
        assert len(p.ioc_values) == 2

    def test_perimeter_new_fields_default(self) -> None:
        from modules.api.schemas.perimeter import PerimeterCreate
        p = PerimeterCreate(name="Energy")
        assert p.geo_countries == []
        assert p.software_products == []
        assert p.ip_ranges == []
        assert p.severity == "medium"

    def test_perimeter_severity_valid(self) -> None:
        from modules.api.schemas.perimeter import PerimeterCreate
        for sev in ("low", "medium", "high", "critical"):
            p = PerimeterCreate(name="Test", severity=sev)
            assert p.severity == sev

    def test_perimeter_severity_invalid(self) -> None:
        from pydantic import ValidationError
        from modules.api.schemas.perimeter import PerimeterCreate
        with pytest.raises(ValidationError):
            PerimeterCreate(name="Test", severity="extreme")

    def test_alert_ack_valid(self) -> None:
        from modules.api.schemas.perimeter import AlertAck
        assert AlertAck(status="acked").status == "acked"

    def test_alert_ack_severity_only(self) -> None:
        from modules.api.schemas.perimeter import AlertAck
        a = AlertAck(severity="critical")
        assert a.severity == "critical"
        assert a.status is None

    def test_alert_ack_invalid(self) -> None:
        from pydantic import ValidationError
        from modules.api.schemas.perimeter import AlertAck
        with pytest.raises(ValidationError):
            AlertAck(status="deleted")

    def test_alert_ack_severity_invalid(self) -> None:
        from pydantic import ValidationError
        from modules.api.schemas.perimeter import AlertAck
        with pytest.raises(ValidationError):
            AlertAck(severity="extreme")


@pytest.mark.unit
class TestObjectSchemas:
    def test_source_count_defaults_to_zero(self) -> None:
        from modules.api.schemas.object import StixObjectResponse
        obj = StixObjectResponse(
            id="uuid", stix_id="indicator--abc", stix_type="indicator",
            stix_data={}, confidence=70, tlp_level="WHITE", is_merged=False,
            merged_into=None, created_at=datetime.now(UTC), modified_at=datetime.now(UTC),
        )
        assert obj.source_count == 0

    def test_list_response(self) -> None:
        from modules.api.schemas.object import StixObjectListResponse
        r = StixObjectListResponse(items=[], total=100, page=2, page_size=50)
        assert r.total == 100


# ── HTTP endpoints ────────────────────────────────────────────

@pytest.mark.unit
class TestAPIEndpoints:
    def _app(self):
        # Import after patch_settings fixture has injected test settings
        import modules.api.main  # ensure module is loaded
        from modules.api.main import create_app
        return create_app()

    def test_health(self) -> None:
        from fastapi.testclient import TestClient
        client = TestClient(self._app())
        assert client.get("/health").json() == {"status": "ok"}

    def test_login_bad_credentials(self) -> None:
        from fastapi.testclient import TestClient
        from modules.api.deps import get_db

        mock_result = MagicMock()
        mock_result.mappings.return_value.first.return_value = None
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session.execute = AsyncMock(return_value=mock_result)

        async def fake_db():
            yield mock_session

        app = self._app()
        app.dependency_overrides[get_db] = fake_db

        with TestClient(app) as client:
            resp = client.post("/auth/login", json={"email": "x@x.com", "password": "bad"})
        assert resp.status_code == 401

    def test_sources_requires_auth(self) -> None:
        from fastapi.testclient import TestClient
        client = TestClient(self._app())
        assert client.get("/sources").status_code == 401

    def test_objects_requires_auth(self) -> None:
        from fastapi.testclient import TestClient
        client = TestClient(self._app())
        assert client.get("/objects").status_code == 401

    def test_perimeters_requires_auth(self) -> None:
        from fastapi.testclient import TestClient
        client = TestClient(self._app())
        assert client.get("/perimeters").status_code == 401

    def test_alerts_requires_auth(self) -> None:
        from fastapi.testclient import TestClient
        client = TestClient(self._app())
        assert client.get("/alerts").status_code == 401

    def test_upload_requires_auth(self) -> None:
        from fastapi.testclient import TestClient
        client = TestClient(self._app())
        assert client.post("/sources/upload").status_code == 401

    def test_enrich_requires_auth(self) -> None:
        from fastapi.testclient import TestClient
        client = TestClient(self._app())
        assert client.post("/objects/indicator--abc/enrich").status_code == 401


# ── _extract_ioc helper ───────────────────────────────────────

@pytest.mark.unit
class TestExtractIoc:
    def test_ipv4_indicator_pattern(self) -> None:
        from modules.api.routers.objects import _extract_ioc
        ioc_type, ioc_value = _extract_ioc(
            "indicator",
            {"pattern": "[ipv4-addr:value = '198.51.100.1']"},
        )
        assert ioc_type == "ipv4-addr"
        assert ioc_value == "198.51.100.1"

    def test_domain_indicator_pattern(self) -> None:
        from modules.api.routers.objects import _extract_ioc
        ioc_type, ioc_value = _extract_ioc(
            "indicator",
            {"pattern": "[domain-name:value = 'evil.example.com']"},
        )
        assert ioc_type == "domain-name"
        assert ioc_value == "evil.example.com"

    def test_threat_actor_uses_name(self) -> None:
        from modules.api.routers.objects import _extract_ioc
        ioc_type, ioc_value = _extract_ioc(
            "threat-actor",
            {"name": "APT28"},
        )
        assert ioc_type == "threat-actor"
        assert ioc_value == "APT28"

    def test_indicator_without_pattern_falls_back(self) -> None:
        from modules.api.routers.objects import _extract_ioc
        ioc_type, ioc_value = _extract_ioc(
            "indicator",
            {"name": "suspicious IP", "pattern": ""},
        )
        assert ioc_type == "indicator"
        assert ioc_value == "suspicious IP"