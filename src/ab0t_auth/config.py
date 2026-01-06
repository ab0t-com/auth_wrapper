"""
Configuration management for Ab0t Auth.

Uses pydantic-settings for environment variable loading with validation.
Provides pure functions for configuration creation and validation.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ab0t_auth.core import AuthConfig


class AuthSettings(BaseSettings):
    """
    Authentication settings loaded from environment variables.

    Follows 12-factor app principles - configuration from environment.
    """

    model_config = SettingsConfigDict(
        env_prefix="AB0T_AUTH_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Required settings
    auth_url: str = Field(
        default="https://auth.service.ab0t.com",
        description="Ab0t auth service URL",
    )

    # Optional organization context
    org_id: str | None = Field(
        default=None,
        description="Default organization ID",
    )

    # JWT settings
    algorithms: list[str] = Field(
        default=["RS256", "RS384", "RS512"],
        description="Allowed JWT signing algorithms",
    )
    audience: str | None = Field(
        default=None,
        description="Expected JWT audience",
    )
    issuer: str | None = Field(
        default=None,
        description="Expected JWT issuer",
    )
    verify_exp: bool = Field(
        default=True,
        description="Verify token expiration",
    )
    verify_aud: bool = Field(
        default=True,
        description="Verify token audience",
    )
    leeway_seconds: int = Field(
        default=10,
        ge=0,
        le=300,
        description="Clock skew leeway in seconds",
    )

    # Cache settings
    jwks_cache_ttl: int = Field(
        default=300,
        ge=60,
        le=3600,
        description="JWKS cache TTL in seconds",
    )
    token_cache_ttl: int = Field(
        default=60,
        ge=0,
        le=300,
        description="Token validation cache TTL in seconds",
    )
    token_cache_max_size: int = Field(
        default=1000,
        ge=100,
        le=10000,
        description="Maximum number of cached token validations",
    )

    # Header configuration
    header_name: str = Field(
        default="Authorization",
        description="HTTP header containing the token",
    )
    header_prefix: str = Field(
        default="Bearer",
        description="Token prefix in header",
    )
    api_key_header: str = Field(
        default="X-API-Key",
        description="HTTP header for API key authentication",
    )

    # Feature flags
    enable_api_key_auth: bool = Field(
        default=True,
        description="Enable API key authentication",
    )
    enable_jwt_auth: bool = Field(
        default=True,
        description="Enable JWT authentication",
    )

    # Debug
    debug: bool = Field(
        default=False,
        description="Enable debug logging",
    )

    @field_validator("auth_url")
    @classmethod
    def validate_auth_url(cls, v: str) -> str:
        """Ensure auth URL is valid and normalized."""
        if not v:
            raise ValueError("auth_url is required")
        return v.rstrip("/")

    @field_validator("algorithms")
    @classmethod
    def validate_algorithms(cls, v: list[str]) -> list[str]:
        """Validate JWT algorithms."""
        allowed = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
        for alg in v:
            if alg not in allowed:
                raise ValueError(f"Unsupported algorithm: {alg}")
        return v


# =============================================================================
# Pure Functions for Configuration
# =============================================================================


def settings_to_config(settings: AuthSettings) -> AuthConfig:
    """
    Convert settings to immutable AuthConfig.

    Pure function - no side effects.
    """
    audience: str | tuple[str, ...] | None = None
    if settings.audience:
        if "," in settings.audience:
            audience = tuple(s.strip() for s in settings.audience.split(","))
        else:
            audience = settings.audience

    return AuthConfig(
        auth_url=settings.auth_url,
        org_id=settings.org_id,
        algorithms=tuple(settings.algorithms),
        audience=audience,
        issuer=settings.issuer,
        jwks_cache_ttl=settings.jwks_cache_ttl,
        token_cache_ttl=settings.token_cache_ttl,
        token_cache_max_size=settings.token_cache_max_size,
        verify_exp=settings.verify_exp,
        verify_aud=settings.verify_aud,
        leeway_seconds=settings.leeway_seconds,
        header_name=settings.header_name,
        header_prefix=settings.header_prefix,
        api_key_header=settings.api_key_header,
        enable_api_key_auth=settings.enable_api_key_auth,
        enable_jwt_auth=settings.enable_jwt_auth,
        debug=settings.debug,
    )


def create_config(
    auth_url: str,
    *,
    org_id: str | None = None,
    audience: str | tuple[str, ...] | None = None,
    issuer: str | None = None,
    algorithms: tuple[str, ...] = ("RS256",),
    jwks_cache_ttl: int = 300,
    token_cache_ttl: int = 60,
    verify_exp: bool = True,
    debug: bool = False,
    **kwargs: Any,
) -> AuthConfig:
    """
    Create AuthConfig with explicit parameters.

    Pure function - preferred for programmatic configuration.
    """
    return AuthConfig(
        auth_url=auth_url.rstrip("/"),
        org_id=org_id,
        algorithms=algorithms,
        audience=audience,
        issuer=issuer,
        jwks_cache_ttl=jwks_cache_ttl,
        token_cache_ttl=token_cache_ttl,
        verify_exp=verify_exp,
        debug=debug,
        **kwargs,
    )


@lru_cache(maxsize=1)
def get_settings() -> AuthSettings:
    """
    Get cached settings instance.

    Singleton pattern for settings - loaded once from environment.
    """
    return AuthSettings()


def get_config() -> AuthConfig:
    """
    Get config from environment settings.

    Convenience function combining settings loading and conversion.
    """
    return settings_to_config(get_settings())


def validate_config(config: AuthConfig) -> list[str]:
    """
    Validate configuration and return list of issues.

    Pure function - returns empty list if valid.
    """
    issues: list[str] = []

    if not config.auth_url:
        issues.append("auth_url is required")

    if not config.enable_jwt_auth and not config.enable_api_key_auth:
        issues.append("At least one auth method must be enabled")

    if config.jwks_cache_ttl < 60:
        issues.append("jwks_cache_ttl should be at least 60 seconds")

    if config.token_cache_ttl > config.jwks_cache_ttl:
        issues.append("token_cache_ttl should not exceed jwks_cache_ttl")

    return issues
