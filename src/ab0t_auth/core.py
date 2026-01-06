"""
Core types and schemas for Ab0t Auth.

Pure data structures with no behavior - following functional principles.
All types are immutable dataclasses with full type hints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal


# =============================================================================
# Enums
# =============================================================================


class TokenType(str, Enum):
    """Token type enumeration."""

    BEARER = "Bearer"
    API_KEY = "ApiKey"


class AuthMethod(str, Enum):
    """Authentication method used."""

    JWT = "jwt"
    API_KEY = "api_key"
    OAUTH = "oauth"


# =============================================================================
# Token Claims
# =============================================================================


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """
    Parsed and validated JWT claims.

    Immutable dataclass representing token payload.
    """

    sub: str | None = None
    email: str | None = None
    org_id: str | None = None
    user_id: str | None = None
    permissions: tuple[str, ...] = field(default_factory=tuple)
    roles: tuple[str, ...] = field(default_factory=tuple)
    exp: int | None = None
    iat: int | None = None
    nbf: int | None = None
    iss: str | None = None
    aud: str | tuple[str, ...] | None = None
    jti: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Permission:
    """
    Permission definition.

    Represents a single permission with metadata.
    """

    name: str
    description: str | None = None
    category: str | None = None
    is_sensitive: bool = False


# =============================================================================
# User Context
# =============================================================================


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """
    Authenticated user context.

    Carries all authentication state through the request lifecycle.
    Immutable to prevent accidental mutations.
    """

    user_id: str
    email: str | None = None
    org_id: str | None = None
    permissions: tuple[str, ...] = field(default_factory=tuple)
    roles: tuple[str, ...] = field(default_factory=tuple)
    auth_method: AuthMethod = AuthMethod.JWT
    token_type: TokenType = TokenType.BEARER
    claims: TokenClaims | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        return permission in self.permissions

    def has_any_permission(self, *permissions: str) -> bool:
        """Check if user has any of the specified permissions."""
        return any(p in self.permissions for p in permissions)

    def has_all_permissions(self, *permissions: str) -> bool:
        """Check if user has all specified permissions."""
        return all(p in self.permissions for p in permissions)

    def has_role(self, role: str) -> bool:
        """Check if user has a specific role."""
        return role in self.roles


@dataclass(frozen=True, slots=True)
class AuthContext:
    """
    Full authentication context for a request.

    Contains user info plus request-specific metadata.
    """

    user: AuthenticatedUser | None
    is_authenticated: bool
    token: str | None = None
    token_type: TokenType | None = None
    request_id: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error: str | None = None


# =============================================================================
# Configuration
# =============================================================================


@dataclass(frozen=True, slots=True)
class AuthConfig:
    """
    Authentication configuration.

    Immutable configuration passed to auth functions.
    """

    auth_url: str
    org_id: str | None = None
    algorithms: tuple[str, ...] = ("RS256", "RS384", "RS512")
    audience: str | tuple[str, ...] | None = None
    issuer: str | None = None
    jwks_cache_ttl: int = 300  # 5 minutes
    token_cache_ttl: int = 60  # 1 minute
    token_cache_max_size: int = 1000
    verify_exp: bool = True
    verify_aud: bool = True
    leeway_seconds: int = 10
    header_name: str = "Authorization"
    header_prefix: str = "Bearer"
    api_key_header: str = "X-API-Key"
    enable_api_key_auth: bool = True
    enable_jwt_auth: bool = True
    debug: bool = False


# =============================================================================
# API Response Types
# =============================================================================


@dataclass(frozen=True, slots=True)
class LoginResponse:
    """Response from Ab0t login endpoint."""

    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int | None = None
    user_id: str | None = None
    email: str | None = None
    org_id: str | None = None
    permissions: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class TokenValidationResponse:
    """Response from Ab0t token validation."""

    valid: bool
    user_id: str | None = None
    email: str | None = None
    org_id: str | None = None
    permissions: tuple[str, ...] = field(default_factory=tuple)
    expires_at: int | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class PermissionCheckResponse:
    """Response from Ab0t permission check."""

    allowed: bool
    permission: str
    user_id: str | None = None
    resource_id: str | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class ApiKeyValidationResponse:
    """Response from Ab0t API key validation."""

    valid: bool
    user_id: str | None = None
    email: str | None = None
    org_id: str | None = None
    permissions: tuple[str, ...] = field(default_factory=tuple)
    error: str | None = None


# =============================================================================
# Request Types
# =============================================================================


@dataclass(frozen=True, slots=True)
class PermissionCheckRequest:
    """Request to check permission."""

    user_id: str
    permission: str
    org_id: str | None = None
    resource_id: str | None = None
    resource_type: str | None = None


# =============================================================================
# Result Types (for functional error handling)
# =============================================================================


@dataclass(frozen=True, slots=True)
class AuthResult:
    """
    Result of an authentication operation.

    Functional approach to error handling - contains either
    success value or error information, never both.
    """

    success: bool
    user: AuthenticatedUser | None = None
    error_code: str | None = None
    error_message: str | None = None

    @classmethod
    def ok(cls, user: AuthenticatedUser) -> "AuthResult":
        """Create successful result."""
        return cls(success=True, user=user)

    @classmethod
    def fail(cls, code: str, message: str) -> "AuthResult":
        """Create failed result."""
        return cls(success=False, error_code=code, error_message=message)


@dataclass(frozen=True, slots=True)
class PermissionResult:
    """Result of a permission check operation."""

    allowed: bool
    permission: str
    reason: str | None = None

    @classmethod
    def grant(cls, permission: str) -> "PermissionResult":
        """Create granted result."""
        return cls(allowed=True, permission=permission)

    @classmethod
    def deny(cls, permission: str, reason: str) -> "PermissionResult":
        """Create denied result."""
        return cls(allowed=False, permission=permission, reason=reason)
