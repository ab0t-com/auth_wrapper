"""
Pytest fixtures for ab0t_auth tests.
"""

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ab0t_auth.core import (
    AuthConfig,
    AuthenticatedUser,
    AuthMethod,
    TokenClaims,
    TokenType,
)
from ab0t_auth.guard import AuthGuard


# =============================================================================
# Configuration Fixtures
# =============================================================================


@pytest.fixture
def auth_config() -> AuthConfig:
    """Create test auth configuration."""
    return AuthConfig(
        auth_url="https://auth.test.ab0t.com",
        org_id="test_org",
        algorithms=("RS256",),
        audience="test-api",
        issuer="https://auth.test.ab0t.com",
        jwks_cache_ttl=300,
        token_cache_ttl=60,
        token_cache_max_size=100,
        verify_exp=True,
        verify_aud=True,
        leeway_seconds=10,
        header_name="Authorization",
        header_prefix="Bearer",
        api_key_header="X-API-Key",
        enable_api_key_auth=True,
        enable_jwt_auth=True,
        debug=True,
    )


# =============================================================================
# User Fixtures
# =============================================================================


@pytest.fixture
def test_user() -> AuthenticatedUser:
    """Create test authenticated user."""
    return AuthenticatedUser(
        user_id="user_123",
        email="test@example.com",
        org_id="test_org",
        permissions=("users:read", "users:write", "reports:read"),
        roles=("user", "editor"),
        auth_method=AuthMethod.JWT,
        token_type=TokenType.BEARER,
    )


@pytest.fixture
def admin_user() -> AuthenticatedUser:
    """Create test admin user."""
    return AuthenticatedUser(
        user_id="admin_456",
        email="admin@example.com",
        org_id="test_org",
        permissions=("admin:access", "users:read", "users:write", "users:delete"),
        roles=("admin", "user"),
        auth_method=AuthMethod.JWT,
        token_type=TokenType.BEARER,
    )


@pytest.fixture
def api_key_user() -> AuthenticatedUser:
    """Create test API key user."""
    return AuthenticatedUser(
        user_id="service_789",
        email="service@example.com",
        org_id="test_org",
        permissions=("api:access",),
        roles=("service",),
        auth_method=AuthMethod.API_KEY,
        token_type=TokenType.API_KEY,
    )


# =============================================================================
# Token Claims Fixtures
# =============================================================================


@pytest.fixture
def test_claims() -> TokenClaims:
    """Create test token claims."""
    return TokenClaims(
        sub="user_123",
        email="test@example.com",
        org_id="test_org",
        user_id="user_123",
        permissions=("users:read", "users:write"),
        roles=("user",),
        exp=int(time.time()) + 3600,
        iat=int(time.time()),
        iss="https://auth.test.ab0t.com",
        aud="test-api",
        jti="token_abc123",
        raw={},
    )


@pytest.fixture
def expired_claims() -> TokenClaims:
    """Create expired token claims."""
    return TokenClaims(
        sub="user_123",
        email="test@example.com",
        exp=int(time.time()) - 100,  # Expired
        iat=int(time.time()) - 3700,
    )


# =============================================================================
# Mock Fixtures
# =============================================================================


@pytest.fixture
def mock_jwk_client() -> MagicMock:
    """Create mock PyJWKClient."""
    mock = MagicMock()
    mock_key = MagicMock()
    mock_key.key = "test_key"
    mock.get_signing_key_from_jwt.return_value = mock_key
    return mock


@pytest.fixture
def mock_http_client() -> AsyncMock:
    """Create mock async HTTP client."""
    return AsyncMock()


# =============================================================================
# AuthGuard Fixtures
# =============================================================================


@pytest.fixture
def auth_guard(auth_config: AuthConfig) -> AuthGuard:
    """Create test AuthGuard (not initialized)."""
    with patch("ab0t_auth.guard.create_jwk_client"):
        guard = AuthGuard(config=auth_config)
        return guard


@pytest.fixture
async def initialized_guard(auth_config: AuthConfig) -> AuthGuard:
    """Create initialized AuthGuard with mocked clients."""
    with patch("ab0t_auth.guard.create_jwk_client") as mock_jwk, \
         patch("ab0t_auth.guard.create_http_client") as mock_http:

        mock_jwk.return_value = MagicMock()
        mock_http.return_value = AsyncMock()

        guard = AuthGuard(config=auth_config)
        await guard.initialize()

        yield guard

        await guard.shutdown()


# =============================================================================
# FastAPI Test App Fixtures
# =============================================================================


@pytest.fixture
def test_app(auth_guard: AuthGuard) -> FastAPI:
    """Create test FastAPI application."""
    app = FastAPI()

    @app.get("/public")
    async def public_route():
        return {"message": "public"}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    return app


@pytest.fixture
def test_client(test_app: FastAPI) -> TestClient:
    """Create test client for FastAPI app."""
    return TestClient(test_app)


# =============================================================================
# Token Fixtures
# =============================================================================


@pytest.fixture
def valid_token() -> str:
    """Return a valid-looking JWT token (for mocking)."""
    return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyJ9.signature"


@pytest.fixture
def valid_api_key() -> str:
    """Return a valid-looking API key."""
    return "ak_test_1234567890abcdef"


# =============================================================================
# Response Mock Helpers
# =============================================================================


def create_mock_response(
    status_code: int = 200,
    json_data: dict[str, Any] | None = None,
) -> MagicMock:
    """Create mock HTTP response."""
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data or {}
    mock.raise_for_status = MagicMock()
    if status_code >= 400:
        from httpx import HTTPStatusError, Request, Response

        mock.raise_for_status.side_effect = HTTPStatusError(
            message="Error",
            request=MagicMock(),
            response=mock,
        )
    return mock
