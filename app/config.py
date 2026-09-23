"""Pydantic settings for the N2 License Server."""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "N2 License Server"
    app_version: str = "1.0.0"
    debug: bool = False

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # Database
    database_url: str = "sqlite:///./data/license_server.db"

    # Paths
    data_dir: Path = Path("./data")
    keys_dir: Path = Path("./data/keys")

    # Security
    admin_username: str = "admin"
    admin_password_hash: str = ""  # bcrypt hash; generate with init_admin.py
    secret_key: str = "change-me-in-production-32-byte-secret-key"
    session_cookie_name: str = "n2ls_session"
    session_max_age_seconds: int = 8 * 3600  # 8 hours

    # License defaults
    default_offline_grace_days: int = 10
    default_activation_limit: int = 1
    client_rate_limit_per_minute: int = 60

    # Optional external integrations
    sentry_dsn: str | None = None

    def model_post_init(self, __context: object, /) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
