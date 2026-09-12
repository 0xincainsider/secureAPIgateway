"""
Application configuration management.

All configuration values are loaded from environment variables
via Pydantic Settings. No secrets are hardcoded.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---
    app_name: str = "SecureAPI Gateway"
    app_version: str = "1.0.0"
    app_debug: bool = False
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    secret_key: str = "change-this-to-a-long-random-secret-key-in-production"

    # --- JWT ---
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "secure-api-gateway"
    jwt_audience: str = "secure-api-gateway-client"
    # Dedicated signing secrets. Fall back to SECRET_KEY when not set,
    # so existing deployments keep working without changes.
    access_token_secret: Optional[str] = None
    refresh_token_secret: Optional[str] = None

    # --- Email verification ---
    email_verification_token_expire_minutes: int = 60

    # --- Database ---
    database_url: str = "postgresql+asyncpg://gateway:gateway_secret@localhost:5432/secure_gateway"
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # --- Redis ---
    redis_url: str = "redis://localhost:6379/0"

    # --- Rate Limiting ---
    rate_limit_default: int = 100
    rate_limit_per_user: int = 200
    rate_limit_window_seconds: int = 60
    enable_rate_limit: bool = True

    # --- Logging ---
    log_level: str = "INFO"
    log_format: str = "json"

    # --- Security ---
    bcrypt_rounds: int = 12
    enable_security_headers: bool = True
    allowed_hosts: str = "*"

    # --- CORS ---
    cors_origins: str = "http://localhost:3000,http://localhost:5173"
    cors_allow_credentials: bool = True

    # --- Prometheus ---
    prometheus_enabled: bool = True

    @property
    def cors_origin_list(self) -> list[str]:
        """Parse comma-separated CORS origins into a list."""
        if self.cors_origins:
            return [origin.strip() for origin in self.cors_origins.split(",")]
        return ["*"]

    @property
    def allowed_hosts_list(self) -> list[str]:
        """Parse comma-separated allowed hosts into a list."""
        if self.allowed_hosts:
            return [host.strip() for host in self.allowed_hosts.split(",")]
        return ["*"]

    @property
    def access_token_expire_seconds(self) -> int:
        """Access token expiry in seconds."""
        return self.access_token_expire_minutes * 60

    @property
    def refresh_token_expire_seconds(self) -> int:
        """Refresh token expiry in seconds."""
        return self.refresh_token_expire_days * 24 * 3600

    @property
    def email_verification_token_expire_seconds(self) -> int:
        """Email verification token expiry in seconds."""
        return self.email_verification_token_expire_minutes * 60

    @property
    def jwt_access_secret(self) -> str:
        """Secret used to sign access (and verification) tokens."""
        return self.access_token_secret or self.secret_key

    @property
    def jwt_refresh_secret(self) -> str:
        """Secret used to sign refresh tokens."""
        return self.refresh_token_secret or self.secret_key


@lru_cache()
def get_settings() -> Settings:
    """Get cached application settings."""
    return Settings()
