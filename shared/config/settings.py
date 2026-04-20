from __future__ import annotations

import os
from functools import lru_cache

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central configuration loaded from environment variables / .env file.
    All modules import from here — never read os.environ directly.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Module identity ───────────────────────────────────────
    module_name: str = Field(default="unknown", description="Injected by docker-compose per service")

    # ── PostgreSQL ────────────────────────────────────────────
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "cti"
    postgres_user: str = "cti"
    postgres_password: str

    @computed_field  # type: ignore[misc]
    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @computed_field  # type: ignore[misc]
    @property
    def database_url_sync(self) -> str:
        """For Alembic (sync driver)."""
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # ── Redis ─────────────────────────────────────────────────
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_password: str

    @computed_field  # type: ignore[misc]
    @property
    def redis_url(self) -> str:
        return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/0"

    # ── LLM ───────────────────────────────────────────────────
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_bearer_token: str = ""
    llm_model: str = "llama3.3:70b-instruct-q4_K_M"
    llm_fallback_model: str = "mistral:7b-instruct-q4_K_M"
    llm_timeout_seconds: int = 600
    llm_num_ctx: int = 8192

    # ── Embeddings ────────────────────────────────────────────
    embedding_model: str = "BAAI/bge-m3"
    semantic_dedup_threshold: float = 0.92

    # ── JWT ───────────────────────────────────────────────────
    jwt_secret: str
    jwt_expire_hours: int = 8

    # ── Application ───────────────────────────────────────────
    base_url: str = "https://localhost"
    log_level: str = "INFO"

    # ── Collector ─────────────────────────────────────────────
    fetch_dedup_ttl_seconds: int = 604800  # 7 days
    max_pdf_size_mb: int = 50
    min_content_words: int = 100
    chunk_max_tokens: int = 3000
    chunk_overlap_tokens: int = 200
    ocr_enabled: bool = True

    # ── Confidence scoring ────────────────────────────────────
    trusted_source_categories: str = "trusted"
    known_source_categories: str = "known"

    # ── Retention ─────────────────────────────────────────────
    retention_days: int = 60
    purge_cron: str = "0 2 * * *"

    # ── SMTP ──────────────────────────────────────────────────
    smtp_host: str = ""
    smtp_port: int = 25
    smtp_from: str = ""
    alert_recipients: str = ""

    # ── File uploads ──────────────────────────────────────────
    upload_dir: str = "/data/uploads"

    # ── External APIs (optional) ──────────────────────────────
    virustotal_api_key: str = ""
    shodan_api_key: str = ""
    misp_base_url: str = ""
    misp_api_key: str = ""

    # ── Grafana (optional — incident counters on dashboard) ───
    grafana_url: str = ""          # e.g. https://grafana.internal
    grafana_api_key: str = ""      # Service account token (Bearer)

    # ── Derived helpers ───────────────────────────────────────
    @property
    def trusted_categories(self) -> list[str]:
        return [c.strip() for c in self.trusted_source_categories.split(",") if c.strip()]

    @property
    def known_categories(self) -> list[str]:
        return [c.strip() for c in self.known_source_categories.split(",") if c.strip()]

    @property
    def enrichment_enabled(self) -> bool:
        return bool(self.virustotal_api_key or self.shodan_api_key)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return cached settings instance.
    Call get_settings() everywhere — never instantiate Settings() directly.
    """
    return Settings()

@computed_field
@property
def database_url(self) -> str:
    return (
        f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
        f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        f"?ssl=disable"
    )