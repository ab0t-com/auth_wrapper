"""
Async HTTP client for Ab0t auth service.

All I/O operations are async for non-blocking performance.
Functions follow functional principles - explicit inputs/outputs.
"""

from __future__ import annotations

from typing import Any

import httpx

from ab0t_auth.cache import bearer_credential
from ab0t_auth.core import (
    ApiKeyValidationResponse,
    AuthConfig,
    IntrospectionResponse,
    LoginResponse,
    PermissionCheckRequest,
    PermissionCheckResponse,
    TokenValidationResponse,
)
from ab0t_auth.errors import AuthServiceError, map_http_error

# =============================================================================
# Helpers
# =============================================================================


def _safe_permissions(value: Any) -> tuple[str, ...]:
    """Coerce permissions from response data to a tuple of strings.

    Handles: list, tuple, comma-separated string, None, or missing.
    Prevents tuple("string") from exploding into individual characters.
    """
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(p) for p in value)
    if isinstance(value, str):
        # Comma-separated or space-separated string
        if "," in value:
            return tuple(p.strip() for p in value.split(",") if p.strip())
        return tuple(value.split()) if value.strip() else ()
    return ()


def _parse_permissions(data: dict[str, Any]) -> tuple[str, ...]:
    """Extract permissions from auth service response data.

    Unified parser used by login(), refresh_token(), and validate_token().
    Checks both 'permissions' (array) and 'scope' (OAuth2 space-separated string).
    Always checks 'permissions' first — it's the canonical field from the
    ab0t auth service. 'scope' is the OAuth2 fallback.
    """
    if "permissions" in data:
        return _safe_permissions(data["permissions"])
    if "scope" in data:
        return _safe_permissions(data["scope"])
    return ()


def _http_error_message(e: httpx.HTTPStatusError) -> str:
    """Client-safe message for an auth-service HTTP error.

    Security hardening: str(HTTPStatusError) contains the internal auth URL
    ("... for url 'http://auth:8001/auth/validate-api-key'"), and that text reached the 401/403 body a
    caller sees (guard → AuthResult → TokenInvalidError). Only the status code is exposed.
    """
    return f"Auth service returned HTTP {e.response.status_code}"


def _is_true(value: Any) -> bool:
    """Strict boolean read of an auth-service decision field: only JSON `true` allows."""
    return value is True


def _bearer_header(token: str) -> str:
    """Authorization value to forward for a token that may or may not carry its scheme.

    The token may be the raw Authorization header (`Bearer <t>`, or `bearer <t>`, which authentication accepts because
    the scheme is case-insensitive, RFC 7235 §2.1 / RFC 6750 §2.1) or a bare token. The scheme is removed
    case-insensitively and re-added in canonical form, so the auth service always receives `Bearer <t>` — never
    `Bearer bearer <t>` (up to 0.1.4 the check was case-sensitive). Same rule as the permission-cache fingerprint.
    """
    return f"Bearer {bearer_credential(token)}"


# =============================================================================
# HTTP Client Factory
# =============================================================================


def create_http_client(
    *,
    timeout: float = 30.0,
    max_keepalive_connections: int = 10,
    max_connections: int = 100,
) -> httpx.AsyncClient:
    """
    Create configured async HTTP client.

    Factory function - creates client with optimal settings for auth service.
    """
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        limits=httpx.Limits(
            max_keepalive_connections=max_keepalive_connections,
            max_connections=max_connections,
        ),
        http2=True,
    )


# =============================================================================
# Login Functions
# =============================================================================


async def login(
    client: httpx.AsyncClient,
    config: AuthConfig,
    email: str,
    password: str,
    *,
    org_id: str | None = None,
) -> LoginResponse:
    """
    Authenticate user with email/password.

    Pure async function - all dependencies passed explicitly.
    """
    payload: dict[str, Any] = {
        "email": email,
        "password": password,
    }
    if org_id or config.org_id:
        payload["org_id"] = org_id or config.org_id

    try:
        response = await client.post(
            f"{config.auth_url}/auth/login",
            json=payload,
        )
        response.raise_for_status()
        data = response.json()

        return LoginResponse(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in"),
            user_id=data.get("user", {}).get("id") or data.get("user_id"),
            email=data.get("user", {}).get("email") or data.get("email"),
            org_id=data.get("org_id"),
            permissions=_parse_permissions(data),
        )

    except httpx.HTTPStatusError as e:
        raise map_http_error(e.response.status_code, _http_error_message(e)) from e
    except httpx.RequestError as e:
        raise AuthServiceError(
            "Failed to connect to auth service",
            service_url=config.auth_url,
            original_error=str(e),
        ) from e


async def refresh_token(
    client: httpx.AsyncClient,
    config: AuthConfig,
    refresh_token_value: str,
) -> LoginResponse:
    """
    Refresh access token using refresh token.

    Pure async function.
    """
    try:
        response = await client.post(
            f"{config.auth_url}/auth/refresh",
            json={"refresh_token": refresh_token_value},
        )
        response.raise_for_status()
        data = response.json()

        return LoginResponse(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in"),
            permissions=_parse_permissions(data),
        )

    except httpx.HTTPStatusError as e:
        raise map_http_error(e.response.status_code, _http_error_message(e)) from e
    except httpx.RequestError as e:
        raise AuthServiceError(
            "Failed to refresh token",
            service_url=config.auth_url,
            original_error=str(e),
        ) from e


# =============================================================================
# Token Validation Functions
# =============================================================================


async def validate_token(
    client: httpx.AsyncClient,
    config: AuthConfig,
    token: str,
) -> TokenValidationResponse:
    """
    Validate token with Ab0t service.

    Server-side validation - authoritative check.
    """
    try:
        # Token may already include a "Bearer " prefix (any case) from the Authorization header
        auth_header = _bearer_header(token)
        response = await client.post(
            f"{config.auth_url}/auth/validate",
            headers={"Authorization": auth_header},
        )
        response.raise_for_status()
        data = response.json()

        return TokenValidationResponse(
            valid=_is_true(data.get("valid")),
            user_id=data.get("user_id"),
            email=data.get("email"),
            org_id=data.get("org_id"),
            permissions=_parse_permissions(data),
            expires_at=data.get("expires_at"),
        )

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            return TokenValidationResponse(
                valid=False,
                error="Token is invalid or expired",
            )
        raise map_http_error(e.response.status_code, _http_error_message(e)) from e
    except httpx.RequestError as e:
        raise AuthServiceError(
            "Failed to validate token",
            service_url=config.auth_url,
            original_error=str(e),
        ) from e


async def validate_api_key(
    client: httpx.AsyncClient,
    config: AuthConfig,
    api_key: str,
) -> ApiKeyValidationResponse:
    """
    Validate API key with Ab0t service.

    Pure async function.
    """
    try:
        response = await client.post(
            f"{config.auth_url}/auth/validate-api-key",
            json={"api_key": api_key},
        )
        response.raise_for_status()
        data = response.json()

        return ApiKeyValidationResponse(
            valid=_is_true(data.get("valid")),
            user_id=data.get("user_id"),
            email=data.get("email"),
            org_id=data.get("org_id"),
            permissions=_safe_permissions(data.get("permissions")),
            error=data.get("error"),
        )

    except httpx.HTTPStatusError as e:
        if e.response.status_code in (401, 403):
            return ApiKeyValidationResponse(
                valid=False,
                error="Invalid API key",
            )
        raise map_http_error(e.response.status_code, _http_error_message(e)) from e
    except httpx.RequestError as e:
        raise AuthServiceError(
            "Failed to validate API key",
            service_url=config.auth_url,
            original_error=str(e),
        ) from e


# =============================================================================
# Permission Functions
# =============================================================================


async def check_permission(
    client: httpx.AsyncClient,
    config: AuthConfig,
    token: str,
    request: PermissionCheckRequest,
    *,
    api_key: str | None = None,
) -> PermissionCheckResponse:
    """
    Check if user has a specific permission.

    Server-side authoritative permission check.

    Supports both Bearer token and API key authentication:
    - If token is provided, uses Authorization: Bearer header with token
    - If api_key is provided (and no token), sends API key as Bearer token
    """
    payload: dict[str, Any] = {
        "user_id": request.user_id,
        "permission": request.permission,
    }
    if request.org_id or config.org_id:
        payload["org_id"] = request.org_id or config.org_id
    if request.resource_id:
        payload["resource_id"] = request.resource_id
    if request.resource_type:
        payload["resource_type"] = request.resource_type

    try:
        # Support both Bearer token and API key authentication
        # Priority: token > api_key (consistent with authentication order)
        # Note: API key is sent as Bearer token since /permissions/check uses HTTPBearer
        # The bearer credential is read with the same rule as the permission-cache fingerprint
        # (cache.bearer_credential), so the credential forwarded here is the one the cached answer is keyed by.
        if bearer_credential(token):
            headers = {"Authorization": _bearer_header(token)}
        elif api_key:
            headers = {"Authorization": f"Bearer {api_key}"}
        else:
            raise AuthServiceError(
                "No credentials for permission check",
                service_url=config.auth_url,
            )

        response = await client.post(
            f"{config.auth_url}/permissions/check",
            json=payload,
            headers=headers,
        )
        response.raise_for_status()
        data = response.json()

        return PermissionCheckResponse(
            allowed=_is_true(data.get("allowed")),
            permission=request.permission,
            user_id=request.user_id,
            resource_id=request.resource_id,
            reason=data.get("reason"),
        )

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 403:
            return PermissionCheckResponse(
                allowed=False,
                permission=request.permission,
                user_id=request.user_id,
                reason="Permission denied",
            )
        raise map_http_error(e.response.status_code, _http_error_message(e)) from e
    except httpx.RequestError as e:
        raise AuthServiceError(
            "Failed to check permission",
            service_url=config.auth_url,
            original_error=str(e),
        ) from e


async def get_user_permissions(
    client: httpx.AsyncClient,
    config: AuthConfig,
    token: str,
    user_id: str,
) -> tuple[str, ...]:
    """
    Get all permissions for a user.

    Pure async function returning immutable tuple.
    """
    try:
        # Token may already include a "Bearer " prefix (any case) from the Authorization header
        auth_header = _bearer_header(token)
        response = await client.get(
            f"{config.auth_url}/permissions/user/{user_id}",
            headers={"Authorization": auth_header},
        )
        response.raise_for_status()
        data = response.json()

        return _safe_permissions(data.get("permissions"))

    except httpx.HTTPStatusError as e:
        raise map_http_error(e.response.status_code, _http_error_message(e)) from e
    except httpx.RequestError as e:
        raise AuthServiceError(
            "Failed to get user permissions",
            service_url=config.auth_url,
            original_error=str(e),
        ) from e


# =============================================================================
# JWKS Functions
# =============================================================================


async def fetch_jwks(
    client: httpx.AsyncClient,
    config: AuthConfig,
) -> dict[str, Any]:
    """
    Fetch JWKS from Ab0t auth service.

    Pure async function.
    """
    if config.org_id:
        url = f"{config.auth_url}/organizations/{config.org_id}/.well-known/jwks.json"
    else:
        url = f"{config.auth_url}/.well-known/jwks.json"

    try:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()

    except httpx.HTTPStatusError as e:
        raise map_http_error(e.response.status_code, _http_error_message(e)) from e
    except httpx.RequestError as e:
        raise AuthServiceError(
            "Failed to fetch JWKS",
            service_url=url,
            original_error=str(e),
        ) from e


async def fetch_openid_configuration(
    client: httpx.AsyncClient,
    config: AuthConfig,
) -> dict[str, Any]:
    """
    Fetch OpenID Connect discovery document.

    Pure async function.
    """
    url = f"{config.auth_url}/.well-known/openid-configuration"

    try:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()

    except httpx.HTTPStatusError as e:
        raise map_http_error(e.response.status_code, _http_error_message(e)) from e
    except httpx.RequestError as e:
        raise AuthServiceError(
            "Failed to fetch OpenID configuration",
            service_url=url,
            original_error=str(e),
        ) from e


# =============================================================================
# Token Introspection (RFC 7662)
# =============================================================================


async def introspect_token(
    client: httpx.AsyncClient,
    config: AuthConfig,
    token: str,
    *,
    token_type_hint: str = "access_token",
) -> IntrospectionResponse:
    """
    Introspect token using RFC 7662.

    For checking token revocation status.
    Returns IntrospectionResponse with active=False as fail-closed default.
    """
    try:
        response = await client.post(
            f"{config.auth_url}/token/introspect",
            data={
                "token": token,
                "token_type_hint": token_type_hint,
            },
        )
        response.raise_for_status()
        data = response.json()

        return IntrospectionResponse(
            active=_is_true(data.get("active")),
            scope=data.get("scope"),
            client_id=data.get("client_id"),
            username=data.get("username"),
            token_type=data.get("token_type"),
            exp=data.get("exp"),
            iat=data.get("iat"),
            sub=data.get("sub"),
            aud=data.get("aud"),
            iss=data.get("iss"),
            jti=data.get("jti"),
            user_id=data.get("user_id"),
            org_id=data.get("org_id"),
            permissions=_safe_permissions(data.get("permissions")),
        )

    except httpx.HTTPStatusError as e:
        raise map_http_error(e.response.status_code, _http_error_message(e)) from e
    except httpx.RequestError as e:
        raise AuthServiceError(
            "Failed to introspect token",
            service_url=config.auth_url,
            original_error=str(e),
        ) from e
