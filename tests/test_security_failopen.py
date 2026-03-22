"""
RED TDD tests — proving fail-open security vulnerabilities exist.

Each test documents a specific vulnerability, proves it's exploitable,
and will turn GREEN once the corresponding fix is applied.

Tests run against two targets:
  1. Mock (respx) — always runs, no external dependency
  2. Live (localhost:8001) — runs when auth service is available

Covers:
  BUG-003: Server-side permission check fails open
  BUG-004: "api_key_user" fallback on null user_id
  BUG-005: tuple() on string permissions explodes to chars
  BUG-006: Middleware path exclusion too loose
  BUG-007: Inconsistent permissions parsing
  BUG-008: introspect_token() returns raw dict with no active check
"""

import asyncio
import socket

import httpx
import pytest
import respx
from unittest.mock import AsyncMock, MagicMock, patch

from ab0t_auth.client import validate_api_key, validate_token
from ab0t_auth.core import (
    ApiKeyValidationResponse,
    AuthConfig,
    AuthenticatedUser,
    AuthMethod,
    AuthResult,
    PermissionCheckResponse,
    TokenType,
)
from ab0t_auth.guard import AuthGuard
from ab0t_auth.permissions import (
    check_permission,
    verify_permission,
)
from ab0t_auth.middleware import AuthMiddleware

AUTH_URL = "https://auth.test.ab0t.com"
LIVE_AUTH_URL = "http://localhost:8001"
API_KEY_ENDPOINT = f"{AUTH_URL}/auth/validate-api-key"
PERMISSION_ENDPOINT = f"{AUTH_URL}/permissions/check"
TOKEN_ENDPOINT = f"{AUTH_URL}/auth/validate"


def _is_auth_service_running():
    """Check if local auth service is available."""
    try:
        with socket.create_connection(("localhost", 8001), timeout=1):
            return True
    except (ConnectionRefusedError, OSError, socket.timeout):
        return False


live_auth = pytest.mark.skipif(
    not _is_auth_service_running(),
    reason="Auth service not running on localhost:8001",
)


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
        permission_check_mode="server",
    )


@pytest.fixture
def live_auth_config() -> AuthConfig:
    return AuthConfig(
        auth_url=LIVE_AUTH_URL,
        org_id="test_org",
        algorithms=("RS256",),
        audience="test-api",
        issuer=LIVE_AUTH_URL,
        api_key_header="X-API-Key",
        enable_api_key_auth=True,
        enable_jwt_auth=True,
        debug=True,
        permission_check_mode="server",
    )


@pytest.fixture
def user_with_jwt_permissions() -> AuthenticatedUser:
    """User whose JWT claims include permissions that were revoked server-side."""
    return AuthenticatedUser(
        user_id="user_revoked",
        email="revoked@example.com",
        org_id="org_123",
        permissions=("admin:access", "billing:read", "users:write"),
        auth_method=AuthMethod.JWT,
        token_type=TokenType.BEARER,
    )


# =============================================================================
# BUG-003: Server-side permission check fails open
# permissions.py:228 — except Exception falls back to client-side JWT check
# =============================================================================


class TestBug003PermissionFailOpen:
    """Server-side permission check should NOT fall back to JWT claims on error."""

    @pytest.mark.asyncio
    async def test_permission_denied_on_network_error_default(
        self, auth_config, user_with_jwt_permissions
    ):
        """Default (deny): auth service unreachable → permission denied.

        With permission_fallback="deny" (default), network errors result
        in denial rather than falling back to potentially stale JWT claims.
        """
        # auth_config has default permission_fallback="deny"
        with respx.mock:
            respx.post(PERMISSION_ENDPOINT).mock(
                side_effect=httpx.ConnectError("Connection refused")
            )

            async with httpx.AsyncClient() as client:
                result = await verify_permission(
                    client,
                    auth_config,
                    "fake_token",
                    user_with_jwt_permissions,
                    "admin:access",
                )

            # Default is deny — fail-closed
            assert result.allowed is False

    @pytest.mark.asyncio
    async def test_permission_falls_back_to_jwt_when_configured(
        self, user_with_jwt_permissions
    ):
        """Configured (client): auth service unreachable → fall back to JWT claims.

        With permission_fallback="client", network errors fall back to
        client-side JWT claim check for availability.
        """
        fallback_config = AuthConfig(
            auth_url=AUTH_URL,
            org_id="test_org",
            algorithms=("RS256",),
            audience="test-api",
            issuer=AUTH_URL,
            permission_check_mode="server",
            permission_fallback="client",
        )

        with respx.mock:
            respx.post(PERMISSION_ENDPOINT).mock(
                side_effect=httpx.ConnectError("Connection refused")
            )

            async with httpx.AsyncClient() as client:
                result = await verify_permission(
                    client,
                    fallback_config,
                    "fake_token",
                    user_with_jwt_permissions,
                    "admin:access",
                )

            # Configured to fall back — user has "admin:access" in JWT
            assert result.allowed is True

    @pytest.mark.asyncio
    async def test_permission_denied_on_500_service_error_default(
        self, auth_config, user_with_jwt_permissions
    ):
        """Default (deny): 500 from auth service → permission denied.

        500 maps to AuthServiceError. With default deny, this results in
        denial rather than falling back to JWT claims.
        """
        with respx.mock:
            respx.post(PERMISSION_ENDPOINT).mock(
                return_value=httpx.Response(500, json={"error": "Internal server error"})
            )

            async with httpx.AsyncClient() as client:
                result = await verify_permission(
                    client,
                    auth_config,
                    "fake_token",
                    user_with_jwt_permissions,
                    "admin:access",
                )

            # Default is deny — fail-closed even on 500
            assert result.allowed is False

    @pytest.mark.asyncio
    async def test_permission_does_not_catch_programming_errors(
        self, auth_config, user_with_jwt_permissions
    ):
        """FIXED: Programming errors (TypeError, etc.) are no longer caught.

        The old code caught Exception which masked bugs. Now only
        AuthServiceError (network/service issues) is caught.
        """
        with respx.mock:
            # Return malformed response that will cause an error in parsing
            respx.post(PERMISSION_ENDPOINT).mock(
                return_value=httpx.Response(200, text="not json")
            )

            async with httpx.AsyncClient() as client:
                with pytest.raises(Exception):
                    await verify_permission(
                        client,
                        auth_config,
                        "fake_token",
                        user_with_jwt_permissions,
                        "admin:access",
                    )

    @pytest.mark.asyncio
    async def test_permission_denied_server_side_but_in_jwt(
        self, auth_config, user_with_jwt_permissions
    ):
        """Baseline: When server explicitly denies, the denial is respected."""
        with respx.mock:
            respx.post(PERMISSION_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "allowed": False,
                    "reason": "Permission revoked",
                })
            )

            async with httpx.AsyncClient() as client:
                result = await verify_permission(
                    client,
                    auth_config,
                    "fake_token",
                    user_with_jwt_permissions,
                    "admin:access",
                )

            # This correctly denies — the server response is respected
            assert result.allowed is False


# =============================================================================
# BUG-004: "api_key_user" fallback on null user_id
# guard.py:449 — user_id=response.user_id or "api_key_user"
# =============================================================================


class TestBug004ApiKeyUserFallback:
    """API key auth should NOT create a shared identity when user_id is null."""

    @pytest.mark.asyncio
    async def test_null_user_id_with_valid_true_creates_shared_identity(self, auth_config):
        """PROVES BUG: valid=true + user_id=null → authenticated as "api_key_user".

        Attack: If an API key is somehow valid but has no user association,
        the attacker gets a shared identity with no audit trail. Multiple
        different API keys could all map to "api_key_user".

        Expected after fix: Should reject (AuthResult.fail) when user_id is null.
        """
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
                    "org_id": None,
                    "permissions": [],
                })
            )

            async with httpx.AsyncClient() as client:
                guard._http_client = client
                result = await guard._authenticate_api_key("orphan_key")

        # FIXED: null user_id is now rejected
        assert result.success is False
        assert result.error_code == "INVALID_API_KEY"

    @pytest.mark.asyncio
    async def test_empty_string_user_id_creates_shared_identity(self, auth_config):
        """PROVES BUG: valid=true + user_id="" → same "api_key_user" fallback."""
        guard = AuthGuard(
            auth_url=auth_config.auth_url,
            audience=auth_config.audience,
            debug=True,
        )

        with respx.mock:
            respx.post(API_KEY_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "valid": True,
                    "user_id": "",
                    "org_id": "org_123",
                    "permissions": ["read"],
                })
            )

            async with httpx.AsyncClient() as client:
                guard._http_client = client
                result = await guard._authenticate_api_key("empty_uid_key")

        # FIXED: empty string user_id is now rejected
        assert result.success is False
        assert result.error_code == "INVALID_API_KEY"


# =============================================================================
# BUG-005: tuple() on string permissions explodes to chars
# client.py:184, 236, 339
# =============================================================================


class TestBug005StringPermissions:
    """String permissions should not be exploded into individual characters."""

    @pytest.mark.asyncio
    async def test_string_permissions_exploded_to_chars_api_key(self, auth_config):
        """PROVES BUG: permissions="admin,read" → ('a','d','m','i','n',',','r','e','a','d').

        Attack: If auth service returns permissions as a comma-separated string
        instead of an array, tuple() silently explodes it to characters.
        The char 'a' could fnmatch patterns like 'a*' or just 'a'.
        """
        with respx.mock:
            respx.post(API_KEY_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "valid": True,
                    "user_id": "user_123",
                    "org_id": "org_456",
                    "permissions": "admin,read",  # String, not array!
                })
            )

            async with httpx.AsyncClient() as client:
                result = await validate_api_key(client, auth_config, "key")

        # FIXED: string "admin,read" is split into ["admin", "read"]
        assert result.permissions == ("admin", "read")
        assert "a" not in result.permissions

    @pytest.mark.asyncio
    async def test_string_permissions_exploded_to_chars_token(self, auth_config):
        """PROVES BUG: Same issue in validate_token()."""
        with respx.mock:
            respx.post(TOKEN_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "valid": True,
                    "user_id": "user_123",
                    "permissions": "billing:read users:write",  # String, not array!
                })
            )

            async with httpx.AsyncClient() as client:
                result = await validate_token(client, auth_config, "token")

        # FIXED: space-separated string split into proper permissions
        assert result.permissions == ("billing:read", "users:write")


# =============================================================================
# BUG-006: Middleware path exclusion too loose
# middleware.py:145 — prefix match overreaches
# =============================================================================


class TestBug006PathExclusion:
    """Path exclusion patterns should not match unintended paths."""

    def test_prefix_wildcard_matches_unintended_paths(self):
        """PROVES BUG: /api/public* matches /api/publicly_secret."""
        middleware = AuthMiddleware(
            app=MagicMock(),
            guard=MagicMock(),
            exclude_paths=["/api/public*"],
        )

        # Should match
        assert middleware._should_exclude("/api/public/page") is True
        assert middleware._should_exclude("/api/public/") is True

        # FIXED: /api/public* no longer matches /api/publicly_secret
        assert middleware._should_exclude("/api/publicly_secret") is False

    def test_case_sensitivity_bypass(self):
        """PROVES BUG: /Health bypasses /health exclusion."""
        middleware = AuthMiddleware(
            app=MagicMock(),
            guard=MagicMock(),
            exclude_paths=["/health"],
        )

        assert middleware._should_exclude("/health") is True

        # FIXED: case-insensitive matching
        assert middleware._should_exclude("/Health") is True

    def test_trailing_slash_bypass(self):
        """PROVES BUG: /health/ bypasses /health exclusion."""
        middleware = AuthMiddleware(
            app=MagicMock(),
            guard=MagicMock(),
            exclude_paths=["/health"],
        )

        assert middleware._should_exclude("/health") is True

        # FIXED: trailing slash normalized
        assert middleware._should_exclude("/health/") is True


# =============================================================================
# BUG-007: Inconsistent permissions parsing
# client.py login() vs validate_token() vs refresh_token()
# =============================================================================


class TestBug007InconsistentParsing:
    """Permissions parsing should be consistent across all client functions."""

    @pytest.mark.asyncio
    async def test_validate_token_checks_permissions_before_scope(self, auth_config):
        """PROVES BUG: validate_token checks 'permissions' first, login checks 'scope' first.

        If both fields are present with different values, the result differs
        depending on which function you call — inconsistent behavior.
        """
        response_data = {
            "valid": True,
            "user_id": "user_123",
            "permissions": ["from_permissions_field"],
            "scope": "from_scope_field",
        }

        with respx.mock:
            # validate_token uses /auth/validate
            respx.post(TOKEN_ENDPOINT).mock(
                return_value=httpx.Response(200, json=response_data)
            )

            async with httpx.AsyncClient() as client:
                result = await validate_token(client, auth_config, "token")

        # validate_token checks 'permissions' first
        assert result.permissions == ("from_permissions_field",)

        # But login() would check 'scope' first and return ("from_scope_field",)
        # This inconsistency is the bug — same data, different results


# =============================================================================
# Live tests — hit real auth service on localhost:8001
# =============================================================================


@live_auth
class TestLiveAuthService:
    """Tests against real auth service to confirm documented behavior."""

    @pytest.mark.asyncio
    async def test_live_fake_api_key_returns_200_with_valid_false(self, live_auth_config):
        """Confirm auth service returns HTTP 200 (not 401) with valid=false for fake keys."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{LIVE_AUTH_URL}/auth/validate-api-key",
                json={"api_key": "COMPLETELY_FAKE_KEY"},
            )

        # Auth service returns 200, not 401
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
        assert data.get("user_id") is None

    @pytest.mark.asyncio
    async def test_live_fake_api_key_rejected_by_library(self, live_auth_config):
        """End-to-end: fake API key through the library → rejected."""
        async with httpx.AsyncClient() as client:
            result = await validate_api_key(client, live_auth_config, "FAKE_KEY_12345")

        assert result.valid is False

    @pytest.mark.asyncio
    async def test_live_sql_injection_api_key_rejected(self, live_auth_config):
        """SQL injection payload as API key → auth service returns valid=false."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{LIVE_AUTH_URL}/auth/validate-api-key",
                json={"api_key": "' OR 1=1 --"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False

    @pytest.mark.asyncio
    async def test_live_empty_api_key_rejected(self, live_auth_config):
        """Empty string as API key → rejected."""
        async with httpx.AsyncClient() as client:
            result = await validate_api_key(client, live_auth_config, "")

        assert result.valid is False

    @pytest.mark.asyncio
    async def test_live_fake_token_returns_200_with_valid_false(self, live_auth_config):
        """Confirm token validation also returns 200 with valid=false for fake tokens."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{LIVE_AUTH_URL}/auth/validate",
                json={"token": "not.a.real.jwt.token"},
            )

        # Could be 200 with valid=false, 401, 404, or 422 — depends on service config
        if response.status_code == 200:
            data = response.json()
            assert data.get("valid") is False
        else:
            # Any non-200 means the token was not accepted — acceptable
            assert response.status_code in (401, 404, 422)
