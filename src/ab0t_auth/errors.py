"""
Error types for Ab0t Auth.

Hierarchy of exceptions for authentication and authorization errors.
Each error type carries structured information for logging and response formatting.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ErrorDetail:
    """Structured error detail for logging and responses."""

    code: str
    message: str
    details: dict[str, Any] | None = None


class AuthError(Exception):
    """
    Base authentication error.

    All auth-related errors inherit from this for unified handling.
    """

    error_code: str = "AUTH_ERROR"
    status_code: int = 401

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or self.error_code
        self.details = details or {}

    def to_detail(self) -> ErrorDetail:
        """Convert to structured error detail."""
        return ErrorDetail(
            code=self.code,
            message=self.message,
            details=self.details if self.details else None,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON response."""
        result: dict[str, Any] = {
            "error": self.code,
            "message": self.message,
        }
        if self.details:
            result["details"] = self.details
        return result


class TokenExpiredError(AuthError):
    """Token has expired."""

    error_code = "TOKEN_EXPIRED"
    status_code = 401

    def __init__(
        self,
        message: str = "Token has expired",
        *,
        expired_at: int | None = None,
    ) -> None:
        details = {"expired_at": expired_at} if expired_at else None
        super().__init__(message, details=details)


class TokenInvalidError(AuthError):
    """Token is malformed or signature invalid."""

    error_code = "TOKEN_INVALID"
    status_code = 401

    def __init__(
        self,
        message: str = "Invalid token",
        *,
        reason: str | None = None,
    ) -> None:
        details = {"reason": reason} if reason else None
        super().__init__(message, details=details)


class TokenNotFoundError(AuthError):
    """No token provided in request."""

    error_code = "TOKEN_NOT_FOUND"
    status_code = 401

    def __init__(
        self,
        message: str = "Authentication token not provided",
        *,
        expected_header: str | None = None,
    ) -> None:
        details = {"expected_header": expected_header} if expected_header else None
        super().__init__(message, details=details)


class PermissionDeniedError(AuthError):
    """User lacks required permission."""

    error_code = "PERMISSION_DENIED"
    status_code = 403

    def __init__(
        self,
        message: str = "Permission denied",
        *,
        required_permission: str | None = None,
        user_permissions: list[str] | None = None,
    ) -> None:
        details: dict[str, Any] = {}
        if required_permission:
            details["required"] = required_permission
        if user_permissions is not None:
            details["user_permissions"] = user_permissions
        super().__init__(message, details=details if details else None)


class InsufficientScopeError(AuthError):
    """Token lacks required scope."""

    error_code = "INSUFFICIENT_SCOPE"
    status_code = 403

    def __init__(
        self,
        message: str = "Insufficient scope",
        *,
        required_scopes: list[str] | None = None,
        token_scopes: list[str] | None = None,
    ) -> None:
        details: dict[str, Any] = {}
        if required_scopes:
            details["required"] = required_scopes
        if token_scopes:
            details["provided"] = token_scopes
        super().__init__(message, details=details if details else None)


class AuthServiceError(AuthError):
    """Error communicating with Ab0t auth service."""

    error_code = "AUTH_SERVICE_ERROR"
    status_code = 503

    def __init__(
        self,
        message: str = "Authentication service unavailable",
        *,
        service_url: str | None = None,
        original_error: str | None = None,
    ) -> None:
        details: dict[str, Any] = {}
        if service_url:
            details["service_url"] = service_url
        if original_error:
            details["original_error"] = original_error
        super().__init__(message, details=details if details else None)


class JWKSFetchError(AuthError):
    """Error fetching JWKS keys."""

    error_code = "JWKS_FETCH_ERROR"
    status_code = 503

    def __init__(
        self,
        message: str = "Failed to fetch JWKS",
        *,
        jwks_url: str | None = None,
    ) -> None:
        details = {"jwks_url": jwks_url} if jwks_url else None
        super().__init__(message, details=details)


class ConfigurationError(AuthError):
    """Invalid auth configuration."""

    error_code = "CONFIGURATION_ERROR"
    status_code = 500

    def __init__(
        self,
        message: str = "Invalid authentication configuration",
        *,
        config_key: str | None = None,
    ) -> None:
        details = {"config_key": config_key} if config_key else None
        super().__init__(message, details=details)


class RateLimitError(AuthError):
    """Rate limit exceeded."""

    error_code = "RATE_LIMIT_EXCEEDED"
    status_code = 429

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        *,
        retry_after: int | None = None,
    ) -> None:
        details = {"retry_after": retry_after} if retry_after else None
        super().__init__(message, details=details)


# =============================================================================
# Error Mapping Functions (Pure)
# =============================================================================


def map_jwt_error(error: Exception) -> AuthError:
    """
    Map PyJWT exceptions to AuthError types.

    Pure function - no side effects.
    """
    error_str = str(error).lower()

    if "expired" in error_str:
        return TokenExpiredError(str(error))
    if "signature" in error_str:
        return TokenInvalidError(str(error), reason="invalid_signature")
    if "decode" in error_str or "malformed" in error_str:
        return TokenInvalidError(str(error), reason="malformed_token")
    if "audience" in error_str:
        return TokenInvalidError(str(error), reason="invalid_audience")
    if "issuer" in error_str:
        return TokenInvalidError(str(error), reason="invalid_issuer")

    return TokenInvalidError(str(error))


def map_http_error(status_code: int, message: str) -> AuthError:
    """
    Map HTTP status codes to AuthError types.

    Pure function - no side effects.
    """
    if status_code == 401:
        return TokenInvalidError(message)
    if status_code == 403:
        return PermissionDeniedError(message)
    if status_code == 429:
        return RateLimitError(message)
    if status_code >= 500:
        return AuthServiceError(message)

    return AuthError(message)
