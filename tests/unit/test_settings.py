"""
Unit tests for Settings (shared/config/settings.py).
"""
from __future__ import annotations

import pytest

from shared.config import Settings


@pytest.mark.unit
class TestSettings:
    def test_database_url_construction(self) -> None:
        s = Settings(
            postgres_host="db-host",
            postgres_port=5433,
            postgres_db="mydb",
            postgres_user="myuser",
            postgres_password="mypass",
            redis_password="rpass",
            jwt_secret="secret",
        )
        assert s.database_url == (
            "postgresql+asyncpg://myuser:mypass@db-host:5433/mydb"
        )

    def test_database_url_sync_uses_psycopg2(self) -> None:
        s = Settings(
            postgres_password="p",
            redis_password="r",
            jwt_secret="s",
        )
        assert "psycopg2" in s.database_url_sync

    def test_redis_url_construction(self) -> None:
        s = Settings(
            redis_host="redis-host",
            redis_port=6380,
            redis_password="myredispass",
            postgres_password="p",
            jwt_secret="s",
        )
        assert s.redis_url == "redis://:myredispass@redis-host:6380/0"

    def test_trusted_categories_parsed(self) -> None:
        s = Settings(
            trusted_source_categories="trusted, cert",
            postgres_password="p",
            redis_password="r",
            jwt_secret="s",
        )
        assert s.trusted_categories == ["trusted", "cert"]

    def test_known_categories_parsed(self) -> None:
        s = Settings(
            known_source_categories="known, blog",
            postgres_password="p",
            redis_password="r",
            jwt_secret="s",
        )
        assert s.known_categories == ["known", "blog"]

    def test_enrichment_disabled_when_no_api_keys(self) -> None:
        s = Settings(
            postgres_password="p",
            redis_password="r",
            jwt_secret="s",
        )
        assert s.enrichment_enabled is False

    def test_enrichment_enabled_with_vt_key(self) -> None:
        s = Settings(
            virustotal_api_key="vt-key-abc",
            postgres_password="p",
            redis_password="r",
            jwt_secret="s",
        )
        assert s.enrichment_enabled is True

    def test_enrichment_enabled_with_shodan_key(self) -> None:
        s = Settings(
            shodan_api_key="shodan-key-abc",
            postgres_password="p",
            redis_password="r",
            jwt_secret="s",
        )
        assert s.enrichment_enabled is True
