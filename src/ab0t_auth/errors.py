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
# Mesh token-exchange errors (token_for / P3)
# =============================================================================
#
# These are the typed outcomes of token_for — the P3 OAuth 2.0 Token Exchange
# (RFC 8693) that mints a token to act for a signed-in person at another mesh
# service. They are the Python twins of the Go SDK's TokenFor sentinels
# (ErrReauthenticate, ErrNoConnection / *ConsentRequired, ErrScopeNotAllowed,
# ErrClientAuth, ErrClientNotEnabled). "Unavailable" reuses AuthServiceError —
# the library's existing 503 class — so a dependency failure classifies the same
# way everywhere.
#
# Classification uses ONLY the HTTP status and the OAuth `error` / `suberror`
# members — never the free-text `error_description`. Messages carried on these
# exceptions are STATIC; the wire details (code, status, request id) live in
# `.details` for the caller's own logs, never a human-typed reason string.


class MeshTokenError(AuthError):
    """Base for a token_for (P3 token-exchange) failure.

    Carries the wire classification facts (never the free-text description) for
    the caller's own logging.
    """

    error_code = "MESH_TOKEN_ERROR"
    status_code = 400

    def __init__(
        self,
        message: str,
        *,
        wire_error: str | None = None,
        status: int | None = None,
        resource: str | None = None,
        scope: str | None = None,
        request_id: str | None = None,
    ) -> None:
        details: dict[str, Any] = {}
        if wire_error:
            details["wire_error"] = wire_error
        if status is not None:
            details["status"] = status
        if resource is not None:
            details["resource"] = resource
        if scope is not None:
            details["scope"] = scope
        if request_id:
            details["request_id"] = request_id
        super().__init__(message, details=details if details else None)
        self.wire_error = wire_error
        self.status = status
        self.resource = resource
        self.scope = scope
        self.request_id = request_id


class ReauthenticateRequired(MeshTokenError):
    """The person's token was not accepted — expired, revoked, not issued for
    your app, or not acceptable by policy (e.g. they left the organisation).

    Wire: 400 invalid_request or invalid_grant. Get a fresh session (sign the
    person in again) and retry once.
    """

    error_code = "REAUTHENTICATE_REQUIRED"
    status_code = 401

    def __init__(
        self, message: str = "The person's session was not accepted", **kwargs: Any
    ) -> None:
        super().__init__(message, **kwargs)


class NoConnectionError(MeshTokenError):
    """There is no usable connection from your app to that resource, or the
    resource is unknown / malformed.

    Wire: 400 invalid_target (no suberror). An org admin must approve the
    connection; the person cannot fix it.
    """

    error_code = "NO_CONNECTION"
    status_code = 403

    def __init__(
        self, message: str = "No usable connection to that resource", **kwargs: Any
    ) -> None:
        super().__init__(message, **kwargs)


class ConsentRequiredError(MeshTokenError):
    """The person can approve the connection themselves but has not yet done so.

    Wire: 400 invalid_target with ``"suberror": "consent_required"``. Send the
    person through ``authorization_url(...)`` once (a normal authorization
    request with prompt=consent), then call token_for again.

    Deliberately NOT a subclass of NoConnectionError — consent is a different
    outcome (the person can fix it), mirroring the Go SDK where errors.Is for
    ErrNoConnection is false on a consent case.
    """

    error_code = "CONSENT_REQUIRED"
    status_code = 403

    def __init__(
        self,
        message: str = "The person must approve access to that resource",
        *,
        client_id: str | None = None,
        authorization_endpoint: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.client_id = client_id
        self.authorization_endpoint = authorization_endpoint

    def authorization_url(
        self,
        redirect_uri: str,
        *,
        state: str = "",
        code_challenge: str = "",
    ) -> str:
        """Build the authorization request that asks the person to approve:
        response_type=code, your client_id, redirect_uri, the scope, the resource
        (RFC 8707), state, a PKCE S256 code_challenge (RFC 7636) and
        prompt=consent. Create the verifier/challenge with ``new_pkce`` and keep
        the verifier for the code exchange at your redirect URI.
        """
        from urllib.parse import urlencode

        endpoint = self.authorization_endpoint or ""
        params: dict[str, str] = {"response_type": "code"}
        if self.client_id:
            params["client_id"] = self.client_id
        params["redirect_uri"] = redirect_uri
        if self.scope:
            params["scope"] = self.scope
        if self.resource:
            params["resource"] = self.resource
        if state:
            params["state"] = state
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        params["prompt"] = "consent"
        sep = "&" if "?" in endpoint else "?"
        return f"{endpoint}{sep}{urlencode(params)}"


class ScopeNotAllowedError(MeshTokenError):
    """The requested scope exceeds what your app / the connection / the person
    allows.

    Wire: 400 invalid_scope. Ask for less, or have the ceiling widened.
    """

    error_code = "SCOPE_NOT_ALLOWED"
    status_code = 403

    def __init__(self, message: str = "Requested scope is not allowed", **kwargs: Any) -> None:
        super().__init__(message, **kwargs)


class ClientAuthError(MeshTokenError):
    """Your app's OAuth client credentials were rejected.

    Wire: 401 (or 400) invalid_client. Fix or rotate the secret.
    """

    error_code = "CLIENT_AUTH_FAILED"
    status_code = 401

    def __init__(self, message: str = "Client authentication failed", **kwargs: Any) -> None:
        super().__init__(message, **kwargs)


class ClientNotEnabledError(MeshTokenError):
    """Your app is not registered for the grant type this call needs.

    Wire: 400 unauthorized_client. Register the token-exchange grant type.
    """

    error_code = "CLIENT_NOT_ENABLED"
    status_code = 403

    def __init__(
        self, message: str = "Client is not enabled for this grant type", **kwargs: Any
    ) -> None:
        super().__init__(message, **kwargs)


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
