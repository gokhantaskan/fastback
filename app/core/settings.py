"""Application settings using Pydantic Settings for typed configuration.

This module centralizes all configuration and provides type-safe access to settings.
Settings are loaded from environment variables with sensible defaults.
"""

from datetime import timedelta
from functools import lru_cache

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Environment
    env_name: str = Field(default="development", alias="ENV_NAME")

    # Database
    database_url: str = Field(alias="DATABASE_URL")

    # Admin panel
    session_secret_key: str = Field(alias="SESSION_SECRET_KEY")
    admin_username: str = Field(alias="ADMIN_USERNAME")
    admin_password: str = Field(alias="ADMIN_PASSWORD")

    # CORS
    cors_origins: str = Field(default="*", alias="CORS_ORIGINS")

    # Email (Resend)
    resend_api_key: str | None = Field(default=None, alias="RESEND_API_KEY")
    app_domain: str = Field(default="resend.dev", alias="APP_DOMAIN")
    client_url: str = Field(default="http://localhost:3000", alias="CLIENT_URL")

    # Firebase / Auth
    session_expires_days: int = Field(
        default=5, alias="SESSION_EXPIRES_DAYS", ge=1, le=14
    )
    firebase_api_key: str | None = Field(default=None, alias="FIREBASE_API_KEY")

    @computed_field
    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS_ORIGINS into a list."""
        origins = []
        for o in self.cors_origins.split(","):
            trimmed = o.strip()
            if trimmed:
                origins.append(trimmed)
        return origins

    @computed_field
    @property
    def is_secure_cookie(self) -> bool:
        """Determine if cookies should be set with Secure flag."""
        return self.env_name.lower() not in {"dev", "development", "local"}

    @computed_field
    @property
    def session_expires_in(self) -> timedelta:
        """Get session expiration as timedelta."""
        return timedelta(days=self.session_expires_days)

    @computed_field
    @property
    def identity_toolkit_base_url(self) -> str:
        """Google Identity Toolkit API base URL."""
        return "https://identitytoolkit.googleapis.com"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance.

    Uses lru_cache to ensure settings are only loaded once.
    """
    return Settings()
