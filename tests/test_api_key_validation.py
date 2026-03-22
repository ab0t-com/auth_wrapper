"""
Tests for API key validation — covering the valid=True hardcoding bug.

Background: validate_api_key() in client.py previously hardcoded valid=True
for any HTTP 200 response, ignoring the actual valid field from the auth
service. The auth service returns HTTP 200 with {"valid": false} for invalid
keys — it does NOT return 401. This meant any string as X-API-Key passed
authentication.

These tests ensure:
1. The valid field from the auth service response is respected
2. Invalid keys (valid=false) are rejected even on HTTP 200
3. Missing valid field defaults to False (fail-closed)
4. The full guard flow rejects fake API keys
5. Token validation has the same fail-closed default
"""

import httpx
import pytest
import respx

from ab0t_auth.client import validate_api_key, validate_token
from ab0t_auth.core import (
    ApiKeyValidationResponse,
    AuthConfig,
    AuthenticatedUser,
    AuthMethod,
    AuthResult,
    TokenType,
)
from ab0t_auth.guard import AuthGuard

AUTH_URL = "https://auth.test.ab0t.com"
API_KEY_ENDPOINT = f"{AUTH_URL}/auth/validate-api-key"
TOKEN_ENDPOINT = f"{AUTH_URL}/auth/validate"  # Note: /auth/validate, NOT /auth/validate-token


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def auth_config() -> AuthConfig:
    return AuthConfig(
        auth_url=AUTH_URL,
        org_id="test_org",
        algorithms=("RS256",),
        audience="test-api",
        issuer=AUTH_URL,
        api_key_header="X-API-Key",
        enable_api_key_auth=True,
        enable_jwt_auth=True,
        debug=True,
    )


# =============================================================================
# validate_api_key() — client.py unit tests
# =============================================================================


class TestValidateApiKeyClient:
    """Test the validate_api_key function in client.py directly."""

    @pytest.mark.asyncio
    async def test_valid_key_accepted(self, auth_config):
        """Auth service returns valid=true → accepted."""
        with respx.mock:
            respx.post(API_KEY_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "valid": True,
                    "user_id": "user_123",
                    "email": "user@example.com",
                    "org_id": "org_456",
                    "permissions": ["read", "write"],
                })
            )
            async with httpx.AsyncClient() as client:
                result = await validate_api_key(client, auth_config, "real_key")

            assert result.valid is True
            assert result.user_id == "user_123"
            assert result.email == "user@example.com"
            assert result.org_id == "org_456"
            assert result.permissions == ("read", "write")
            assert result.error is None

    @pytest.mark.asyncio
    async def test_invalid_key_rejected_on_http_200(self, auth_config):
        """Auth service returns HTTP 200 with valid=false → MUST be rejected.

        This is the exact scenario that was broken. The auth service returns
        200 (not 401) with valid=false for invalid keys.
        """
        with respx.mock:
            respx.post(API_KEY_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "valid": False,
                    "user_id": None,
                    "org_id": None,
                    "permissions": [],
                    "error": "API key validation failed",
                })
            )
            async with httpx.AsyncClient() as client:
                result = await validate_api_key(client, auth_config, "FAKE_KEY")

            assert result.valid is False
            assert result.error == "API key validation failed"

    @pytest.mark.asyncio
    async def test_missing_valid_field_defaults_to_false(self, auth_config):
        """If auth service response omits the valid field, default to False.

        Fail-closed: missing field = reject. Previously defaulted to True.
        """
        with respx.mock:
            respx.post(API_KEY_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "user_id": "user_123",
                    "email": "user@example.com",
                    "org_id": "org_456",
                    "permissions": ["read"],
                })
            )
            async with httpx.AsyncClient() as client:
                result = await validate_api_key(client, auth_config, "some_key")

            assert result.valid is False  # Fail-closed, not True

    @pytest.mark.asyncio
    async def test_error_field_captured_on_success_path(self, auth_config):
        """Error field from auth service is propagated even on HTTP 200."""
        with respx.mock:
            respx.post(API_KEY_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "valid": False,
                    "error": "Key revoked",
                })
            )
            async with httpx.AsyncClient() as client:
                result = await validate_api_key(client, auth_config, "revoked_key")

            assert result.valid is False
            assert result.error == "Key revoked"

    @pytest.mark.asyncio
    async def test_http_401_returns_invalid(self, auth_config):
        """HTTP 401 from auth service → valid=False."""
        with respx.mock:
            respx.post(API_KEY_ENDPOINT).mock(
                return_value=httpx.Response(401, json={"error": "Unauthorized"})
            )
            async with httpx.AsyncClient() as client:
                result = await validate_api_key(client, auth_config, "bad_key")

            assert result.valid is False
            assert result.error == "Invalid API key"

    @pytest.mark.asyncio
    async def test_http_403_returns_invalid(self, auth_config):
        """HTTP 403 from auth service → valid=False."""
        with respx.mock:
            respx.post(API_KEY_ENDPOINT).mock(
                return_value=httpx.Response(403, json={"error": "Forbidden"})
            )
            async with httpx.AsyncClient() as client:
                result = await validate_api_key(client, auth_config, "bad_key")

            assert result.valid is False

    @pytest.mark.asyncio
    async def test_empty_response_body_defaults_to_invalid(self, auth_config):
        """Empty JSON response → valid=False (fail-closed)."""
        with respx.mock:
            respx.post(API_KEY_ENDPOINT).mock(
                return_value=httpx.Response(200, json={})
            )
            async with httpx.AsyncClient() as client:
                result = await validate_api_key(client, auth_config, "some_key")

            assert result.valid is False
            assert result.user_id is None
            assert result.permissions == ()

    @pytest.mark.asyncio
    async def test_sql_injection_payload_rejected(self, auth_config):
        """SQL injection as API key — auth service returns valid=false, library must reject."""
        with respx.mock:
            respx.post(API_KEY_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "valid": False,
                    "user_id": None,
                    "permissions": [],
                    "error": "API key validation failed",
                })
            )
            async with httpx.AsyncClient() as client:
                result = await validate_api_key(client, auth_config, "' OR 1=1 --")

            assert result.valid is False


# =============================================================================
# Guard._authenticate_api_key() — full flow tests
# Uses respx to mock the HTTP layer so raise_for_status() works correctly.
# =============================================================================


class TestGuardApiKeyFlow:
    """Test the full guard flow for API key authentication."""

    @pytest.mark.asyncio
    async def test_guard_rejects_invalid_api_key(self, auth_config):
        """Full guard flow: fake API key → AuthResult.fail."""
        guard = AuthGuard(
            auth_url=auth_config.auth_url,
            audience=auth_config.audience,
            debug=True,
        )

        with respx.mock:
            respx.post(API_KEY_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "valid": False,
                    "user_id": None,
                    "org_id": None,
                    "permissions": [],
                    "error": "API key validation failed",
                })
            )
            async with httpx.AsyncClient() as client:
                guard._http_client = client
                result = await guard._authenticate_api_key("FAKE_KEY")

            assert not result.success
            assert result.error_code == "INVALID_API_KEY"

    @pytest.mark.asyncio
    async def test_guard_accepts_valid_api_key(self, auth_config):
        """Full guard flow: valid API key → AuthResult.ok with correct user."""
        guard = AuthGuard(
            auth_url=auth_config.auth_url,
            audience=auth_config.audience,
            debug=True,
        )

        with respx.mock:
            respx.post(API_KEY_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "valid": True,
                    "user_id": "svc_123",
                    "email": "svc@example.com",
                    "org_id": "org_789",
                    "permissions": ["read", "write"],
                })
            )
            async with httpx.AsyncClient() as client:
                guard._http_client = client
                result = await guard._authenticate_api_key("real_key")

            assert result.success
            assert result.user.user_id == "svc_123"
            assert result.user.email == "svc@example.com"
            assert result.user.org_id == "org_789"
            assert result.user.auth_method == AuthMethod.API_KEY
            assert result.user.token_type == TokenType.API_KEY

    @pytest.mark.asyncio
    async def test_guard_rejects_null_user_id(self, auth_config):
        """When auth service returns valid=true but user_id=null, reject the key."""
        guard = AuthGuard(
            auth_url=auth_config.auth_url,
            audience=auth_config.audience,
            debug=True,
        )

        with respx.mock:
            respx.post(API_KEY_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "valid": True,
                    "user_id": None,
                    "permissions": [],
                })
            )
            async with httpx.AsyncClient() as client:
                guard._http_client = client
                result = await guard._authenticate_api_key("key_with_no_user")

            assert not result.success
            assert result.error_code == "INVALID_API_KEY"


# =============================================================================
# Token validation — same fail-closed default
# Endpoint is /auth/validate (NOT /auth/validate-token)
# =============================================================================


class TestValidateTokenFailClosed:
    """Ensure token validation also defaults to False when valid field is missing."""

    @pytest.mark.asyncio
    async def test_missing_valid_field_defaults_to_false(self, auth_config):
        """Token validation: missing valid field → False (fail-closed)."""
        with respx.mock:
            respx.post(TOKEN_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "user_id": "user_123",
                    "email": "user@example.com",
                    "permissions": ["read"],
                })
            )
            async with httpx.AsyncClient() as client:
                result = await validate_token(client, auth_config, "some_token")

            assert result.valid is False  # Fail-closed

    @pytest.mark.asyncio
    async def test_explicit_valid_true_accepted(self, auth_config):
        """Token validation: explicit valid=true → accepted."""
        with respx.mock:
            respx.post(TOKEN_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "valid": True,
                    "user_id": "user_123",
                    "email": "user@example.com",
                    "permissions": ["read"],
                })
            )
            async with httpx.AsyncClient() as client:
                result = await validate_token(client, auth_config, "good_token")

            assert result.valid is True

    @pytest.mark.asyncio
    async def test_explicit_valid_false_rejected(self, auth_config):
        """Token validation: explicit valid=false on HTTP 200 → rejected."""
        with respx.mock:
            respx.post(TOKEN_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "valid": False,
                    "error": "Token expired",
                })
            )
            async with httpx.AsyncClient() as client:
                result = await validate_token(client, auth_config, "expired_token")

            assert result.valid is False
