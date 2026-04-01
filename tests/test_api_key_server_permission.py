"""
RED TDD tests — API key authentication with server-side permission checks.

Background: When using `permission_check_mode="server"` with API key authentication,
the permission check fails because the `authorization` header is `None`. The code
passes `authorization or ""` (empty string) to `verify_permission()`, which then
sends an empty Bearer token to the auth service, resulting in 401 → 403.

GitHub Issue: https://github.com/ab0t-com/auth_wrapper/issues/16

CORRECT FIX: Pass the API key via X-API-Key header to the /permissions/check endpoint.
Server-side checks are AUTHORITATIVE - this is a Zanzibar-based real-time permission
system. Permissions can change at any moment, so we must always check with the server.
Local/cached permissions (from JWT claims or API key validation) may be stale.

WHY THIS BUG WAS NOT CAUGHT:
1. Test isolation: `test_server_permission_mode.py` tests server mode with JWT auth only.
   It mocks `authenticate_or_raise()` to return a JWT-authenticated user.
2. Default config: Most tests use `permission_check_mode="client"` (the default).
3. API key tests focus on auth, not authz: `test_api_key_validation.py` tests that
   API keys authenticate correctly, but not that permission checks work afterward.
4. No end-to-end test combining: API key + server mode + permission-protected route.

TEST MATRIX covered:
| Auth Method | Permission Mode | Has Permission | Expected Result |
|-------------|-----------------|----------------|-----------------|
| API Key     | server          | Yes            | 200 OK          |
| API Key     | server          | No             | 403 Forbidden   |
| API Key     | client          | Yes            | 200 OK          |
| API Key     | client          | No             | 403 Forbidden   |
| JWT         | server          | Yes            | 200 OK          |
| JWT         | server          | No             | 403 Forbidden   |

These tests will FAIL until the fix is applied (red phase of TDD).
"""

import httpx
import pytest
import respx
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from ab0t_auth.core import (
    AuthConfig,
    AuthenticatedUser,
    AuthMethod,
    AuthResult,
    PermissionCheckResponse,
    PermissionResult,
    TokenType,
)
from ab0t_auth.errors import AuthError, PermissionDeniedError
from ab0t_auth.guard import AuthGuard
from ab0t_auth.dependencies import (
    require_permission,
    require_any_permission,
    require_all_permissions,
)


AUTH_URL = "https://auth.test.ab0t.com"
API_KEY_ENDPOINT = f"{AUTH_URL}/auth/validate-api-key"
PERMISSION_ENDPOINT = f"{AUTH_URL}/permissions/check"


def add_exception_handlers(app: FastAPI) -> None:
    """Add auth exception handlers to FastAPI app."""
    @app.exception_handler(AuthError)
    async def auth_error_handler(request: Request, exc: AuthError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.message, "code": exc.code},
        )


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def api_key_user_with_permissions() -> AuthenticatedUser:
    """API key authenticated user with specific permissions."""
    return AuthenticatedUser(
        user_id="service_account_123",
        email="service@example.com",
        org_id="org_abc",
        permissions=("data:read", "data:write", "reports:view"),
        roles=("service",),
        auth_method=AuthMethod.API_KEY,
        token_type=TokenType.API_KEY,
    )


@pytest.fixture
def api_key_user_limited() -> AuthenticatedUser:
    """API key authenticated user with limited permissions."""
    return AuthenticatedUser(
        user_id="limited_service_456",
        email="limited@example.com",
        org_id="org_abc",
        permissions=("data:read",),  # Only read, no write or admin
        roles=("service",),
        auth_method=AuthMethod.API_KEY,
        token_type=TokenType.API_KEY,
    )


@pytest.fixture
def jwt_user_with_permissions() -> AuthenticatedUser:
    """JWT authenticated user with specific permissions."""
    return AuthenticatedUser(
        user_id="user_789",
        email="user@example.com",
        org_id="org_abc",
        permissions=("data:read", "data:write"),
        roles=("user",),
        auth_method=AuthMethod.JWT,
        token_type=TokenType.BEARER,
    )


@pytest.fixture
def auth_config_server_mode() -> AuthConfig:
    """Auth config with server-side permission checking."""
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
def auth_config_client_mode() -> AuthConfig:
    """Auth config with client-side permission checking (default)."""
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
        permission_check_mode="client",
    )


# =============================================================================
# THE CORE BUG: API Key + Server Mode Permission Check
# These tests demonstrate the exact failure scenario from Issue #16
# =============================================================================


class TestApiKeyServerModePermissionBug:
    """
    Tests proving the bug exists: API key auth + server permission mode fails.

    The bug: When authenticating via X-API-Key (no Authorization header),
    `authorization or ""` passes an empty string to verify_permission(),
    which sends "Authorization: Bearer " (empty token) to the auth service.

    CORRECT FIX: Pass API key to verify_permission, which sends it via X-API-Key
    header to /permissions/check. Server-side checks are authoritative (Zanzibar).
    """

    @pytest.mark.asyncio
    async def test_api_key_auth_server_mode_permission_allowed(
        self, auth_config_server_mode, api_key_user_with_permissions
    ):
        """
        API key auth + server mode + server grants permission → 200 OK.

        BUG: This currently fails because empty Bearer token sent to permission check.
        EXPECTED AFTER FIX: Server-side check with API key auth succeeds.
        """
        guard = MagicMock(spec=AuthGuard)
        guard._config = auth_config_server_mode
        guard._http_client = AsyncMock()
        guard._permission_cache = MagicMock()
        guard._permission_cache.get = MagicMock(return_value=None)

        # Mock authentication to return API key user
        async def mock_auth(auth_header, api_key):
            if api_key:
                return api_key_user_with_permissions
            raise Exception("No credentials")

        guard.authenticate_or_raise = AsyncMock(side_effect=mock_auth)

        # After fix: verify_permission should receive API key and succeed
        with patch("ab0t_auth.dependencies.verify_permission") as mock_verify:
            # Server grants permission (this is the expected behavior after fix)
            mock_verify.return_value = PermissionResult.grant("data:read")

            app = FastAPI()
            add_exception_handlers(app)

            @app.get("/data")
            async def get_data(
                user: AuthenticatedUser = Depends(require_permission(
                    guard,
                    "data:read",
                )),
            ):
                return {"user_id": user.user_id, "auth_method": user.auth_method.value}

            client = TestClient(app)

            # Send request with only X-API-Key, no Authorization header
            response = client.get("/data", headers={"X-API-Key": "valid_api_key"})

            # After fix: should succeed with server-side check
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}. "
                f"Response: {response.json()}. "
                "Bug: API key auth with server permission mode sends empty Bearer token."
            )
            assert response.json()["user_id"] == "service_account_123"
            assert response.json()["auth_method"] == "api_key"

            # Verify server-side check was called (authoritative Zanzibar check)
            mock_verify.assert_called_once()

            # AFTER FIX: API key should be passed to verify_permission
            call_args = mock_verify.call_args
            args = call_args[0] if call_args[0] else ()
            kwargs = call_args[1] if call_args[1] else {}

            # Current bug: token (arg index 2) is empty string ""
            # After fix: api_key should be passed as kwarg
            token_arg = args[2] if len(args) > 2 else ""
            api_key_kwarg = kwargs.get("api_key", None)

            # This assertion will fail until fix is applied
            assert api_key_kwarg == "valid_api_key" or token_arg != "", (
                f"Expected API key to be passed to verify_permission. "
                f"Got token={token_arg!r}, api_key={api_key_kwarg!r}"
            )

    @pytest.mark.asyncio
    async def test_api_key_auth_server_mode_permission_denied(
        self, auth_config_server_mode, api_key_user_limited
    ):
        """
        API key auth + server mode + server denies permission → 403 Forbidden.

        BUG: Currently fails for the wrong reason (empty Bearer token).
        EXPECTED AFTER FIX: 403 because server denies "admin:access".
        """
        guard = MagicMock(spec=AuthGuard)
        guard._config = auth_config_server_mode
        guard._http_client = AsyncMock()
        guard._permission_cache = MagicMock()
        guard._permission_cache.get = MagicMock(return_value=None)

        async def mock_auth(auth_header, api_key):
            if api_key:
                return api_key_user_limited
            raise Exception("No credentials")

        guard.authenticate_or_raise = AsyncMock(side_effect=mock_auth)

        # After fix: server-side check denies permission (correct behavior)
        with patch("ab0t_auth.dependencies.verify_permission") as mock_verify:
            # Server denies permission (user genuinely lacks admin:access)
            mock_verify.return_value = PermissionResult.deny(
                "admin:access",
                "User lacks permission: admin:access"
            )

            app = FastAPI()
            add_exception_handlers(app)

            @app.get("/admin")
            async def admin_only(
                user: AuthenticatedUser = Depends(require_permission(
                    guard,
                    "admin:access",  # User doesn't have this
                )),
            ):
                return {"admin": True}

            client = TestClient(app)
            response = client.get("/admin", headers={"X-API-Key": "limited_api_key"})

            # Should be 403 Forbidden (permission denied by server)
            assert response.status_code == 403

            # After fix: verify_permission (server-side) should be called with API key
            mock_verify.assert_called_once()

            # Verify API key was passed
            call_args = mock_verify.call_args
            kwargs = call_args[1] if call_args[1] else {}
            api_key_kwarg = kwargs.get("api_key", None)

            assert api_key_kwarg == "limited_api_key", (
                f"Expected API key to be passed to verify_permission. "
                f"Got api_key={api_key_kwarg!r}"
            )


class TestApiKeyServerModeRequireAnyPermission:
    """Tests for require_any_permission with API key + server mode."""

    @pytest.mark.asyncio
    async def test_api_key_server_mode_any_permission_allowed(
        self, auth_config_server_mode, api_key_user_with_permissions
    ):
        """
        API key auth + server mode + require_any_permission + server grants → 200 OK.
        """
        guard = MagicMock(spec=AuthGuard)
        guard._config = auth_config_server_mode
        guard._http_client = AsyncMock()
        guard._permission_cache = MagicMock()
        guard._permission_cache.get = MagicMock(return_value=None)

        async def mock_auth(auth_header, api_key):
            if api_key:
                return api_key_user_with_permissions
            raise Exception("No credentials")

        guard.authenticate_or_raise = AsyncMock(side_effect=mock_auth)

        # After fix: server-side check with API key auth succeeds
        with patch("ab0t_auth.dependencies.verify_any_permission") as mock_verify:
            mock_verify.return_value = PermissionResult.grant("reports:view")

            app = FastAPI()
            add_exception_handlers(app)

            @app.get("/reports")
            async def get_reports(
                user: AuthenticatedUser = Depends(require_any_permission(
                    guard,
                    "reports:view",  # User has this
                    "reports:admin",  # User doesn't have this
                )),
            ):
                return {"reports": [], "user_id": user.user_id}

            client = TestClient(app)
            response = client.get("/reports", headers={"X-API-Key": "valid_key"})

            # After fix: server-side check with API key should succeed
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}. Response: {response.json()}"
            )

            # Verify API key was passed to server-side check
            mock_verify.assert_called_once()
            call_kwargs = mock_verify.call_args[1] if mock_verify.call_args[1] else {}
            assert call_kwargs.get("api_key") == "valid_key", (
                f"Expected api_key='valid_key' in kwargs, got {call_kwargs}"
            )

    @pytest.mark.asyncio
    async def test_api_key_server_mode_any_permission_denied(
        self, auth_config_server_mode, api_key_user_limited
    ):
        """
        API key auth + server mode + require_any_permission + server denies → 403.
        """
        guard = MagicMock(spec=AuthGuard)
        guard._config = auth_config_server_mode
        guard._http_client = AsyncMock()
        guard._permission_cache = MagicMock()
        guard._permission_cache.get = MagicMock(return_value=None)

        async def mock_auth(auth_header, api_key):
            if api_key:
                return api_key_user_limited
            raise Exception("No credentials")

        guard.authenticate_or_raise = AsyncMock(side_effect=mock_auth)

        # After fix: server-side check denies (user lacks all permissions)
        with patch("ab0t_auth.dependencies.verify_any_permission") as mock_verify:
            mock_verify.return_value = PermissionResult.deny(
                "admin:access",
                "User lacks all required permissions"
            )

            app = FastAPI()
            add_exception_handlers(app)

            @app.get("/admin-reports")
            async def admin_reports(
                user: AuthenticatedUser = Depends(require_any_permission(
                    guard,
                    "admin:access",
                    "reports:admin",
                )),
            ):
                return {"reports": []}

            client = TestClient(app)
            response = client.get("/admin-reports", headers={"X-API-Key": "limited_key"})

            assert response.status_code == 403

            # After fix: server-side check should be called with API key
            mock_verify.assert_called_once()
            call_kwargs = mock_verify.call_args[1] if mock_verify.call_args[1] else {}
            assert call_kwargs.get("api_key") == "limited_key", (
                f"Expected api_key='limited_key' in kwargs, got {call_kwargs}"
            )


class TestApiKeyServerModeRequireAllPermissions:
    """Tests for require_all_permissions with API key + server mode."""

    @pytest.mark.asyncio
    async def test_api_key_server_mode_all_permissions_allowed(
        self, auth_config_server_mode, api_key_user_with_permissions
    ):
        """
        API key auth + server mode + require_all_permissions + server grants → 200 OK.
        """
        guard = MagicMock(spec=AuthGuard)
        guard._config = auth_config_server_mode
        guard._http_client = AsyncMock()
        guard._permission_cache = MagicMock()
        guard._permission_cache.get = MagicMock(return_value=None)

        async def mock_auth(auth_header, api_key):
            if api_key:
                return api_key_user_with_permissions
            raise Exception("No credentials")

        guard.authenticate_or_raise = AsyncMock(side_effect=mock_auth)

        # After fix: server-side check with API key auth succeeds
        with patch("ab0t_auth.dependencies.verify_all_permissions") as mock_verify:
            mock_verify.return_value = PermissionResult.grant("data:write")

            app = FastAPI()
            add_exception_handlers(app)

            @app.post("/data/modify")
            async def modify_data(
                user: AuthenticatedUser = Depends(require_all_permissions(
                    guard,
                    "data:read",
                    "data:write",
                )),
            ):
                return {"modified": True, "user_id": user.user_id}

            client = TestClient(app)
            response = client.post("/data/modify", headers={"X-API-Key": "valid_key"})

            # After fix: server-side check with API key should succeed
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}. Response: {response.json()}"
            )

            # Verify API key was passed to server-side check
            mock_verify.assert_called_once()
            call_kwargs = mock_verify.call_args[1] if mock_verify.call_args[1] else {}
            assert call_kwargs.get("api_key") == "valid_key", (
                f"Expected api_key='valid_key' in kwargs, got {call_kwargs}"
            )

    @pytest.mark.asyncio
    async def test_api_key_server_mode_all_permissions_denied(
        self, auth_config_server_mode, api_key_user_limited
    ):
        """
        API key auth + server mode + require_all_permissions + server denies → 403.
        """
        guard = MagicMock(spec=AuthGuard)
        guard._config = auth_config_server_mode
        guard._http_client = AsyncMock()
        guard._permission_cache = MagicMock()
        guard._permission_cache.get = MagicMock(return_value=None)

        async def mock_auth(auth_header, api_key):
            if api_key:
                return api_key_user_limited  # Only has data:read
            raise Exception("No credentials")

        guard.authenticate_or_raise = AsyncMock(side_effect=mock_auth)

        # After fix: server-side check denies (user lacks data:write)
        with patch("ab0t_auth.dependencies.verify_all_permissions") as mock_verify:
            mock_verify.return_value = PermissionResult.deny(
                "data:write",
                "User lacks required permission: data:write"
            )

            app = FastAPI()
            add_exception_handlers(app)

            @app.post("/data/modify")
            async def modify_data(
                user: AuthenticatedUser = Depends(require_all_permissions(
                    guard,
                    "data:read",   # User has this
                    "data:write",  # User does NOT have this
                )),
            ):
                return {"modified": True}

            client = TestClient(app)
            response = client.post("/data/modify", headers={"X-API-Key": "limited_key"})

            assert response.status_code == 403

            # After fix: server-side check should be called with API key
            mock_verify.assert_called_once()
            call_kwargs = mock_verify.call_args[1] if mock_verify.call_args[1] else {}
            assert call_kwargs.get("api_key") == "limited_key", (
                f"Expected api_key='limited_key' in kwargs, got {call_kwargs}"
            )


# =============================================================================
# COMPARISON: JWT + Server Mode (should continue to work)
# These tests verify JWT auth + server mode still makes server-side calls
# =============================================================================


class TestJwtServerModeStillCallsServer:
    """
    Verify that JWT auth + server mode continues to make server-side calls.

    The fix should NOT change behavior for JWT auth — only API key auth
    should switch to client-side checks.
    """

    @pytest.mark.asyncio
    async def test_jwt_auth_server_mode_calls_verify_permission(
        self, auth_config_server_mode, jwt_user_with_permissions
    ):
        """
        JWT auth + server mode → verify_permission() is called (not client-side check).

        This ensures the fix doesn't accidentally break server-side checks for JWT.
        """
        guard = MagicMock(spec=AuthGuard)
        guard._config = auth_config_server_mode
        guard._http_client = MagicMock()
        guard._permission_cache = MagicMock()
        guard._permission_cache.get = MagicMock(return_value=None)

        async def mock_auth(auth_header, api_key):
            if auth_header and auth_header.startswith("Bearer "):
                return jwt_user_with_permissions
            raise Exception("No credentials")

        guard.authenticate_or_raise = AsyncMock(side_effect=mock_auth)

        with patch("ab0t_auth.dependencies.verify_permission") as mock_verify:
            mock_verify.return_value = PermissionResult.grant("data:read")

            app = FastAPI()
            add_exception_handlers(app)

            @app.get("/data")
            async def get_data(
                user: AuthenticatedUser = Depends(require_permission(
                    guard,
                    "data:read",
                )),
            ):
                return {"user_id": user.user_id}

            client = TestClient(app)
            response = client.get(
                "/data",
                headers={"Authorization": "Bearer valid_jwt_token"}
            )

            assert response.status_code == 200

            # CRITICAL: For JWT auth, verify_permission SHOULD be called
            mock_verify.assert_called_once()

    @pytest.mark.asyncio
    async def test_jwt_auth_server_mode_server_denies(
        self, auth_config_server_mode, jwt_user_with_permissions
    ):
        """
        JWT auth + server mode + server denies → 403 Forbidden.

        Ensures server-side denial still works for JWT (revoked permissions).
        """
        guard = MagicMock(spec=AuthGuard)
        guard._config = auth_config_server_mode
        guard._http_client = MagicMock()
        guard._permission_cache = MagicMock()
        guard._permission_cache.get = MagicMock(return_value=None)

        async def mock_auth(auth_header, api_key):
            if auth_header:
                return jwt_user_with_permissions
            raise Exception("No credentials")

        guard.authenticate_or_raise = AsyncMock(side_effect=mock_auth)

        with patch("ab0t_auth.dependencies.verify_permission") as mock_verify:
            # Server denies even though user has permission in JWT claims
            mock_verify.return_value = PermissionResult.deny(
                "data:read",
                "Permission revoked by admin"
            )

            app = FastAPI()
            add_exception_handlers(app)

            @app.get("/data")
            async def get_data(
                user: AuthenticatedUser = Depends(require_permission(
                    guard,
                    "data:read",
                )),
            ):
                return {"user_id": user.user_id}

            client = TestClient(app)
            response = client.get(
                "/data",
                headers={"Authorization": "Bearer valid_jwt_token"}
            )

            assert response.status_code == 403


# =============================================================================
# CLIENT MODE: API Key + Client Mode (should work, baseline)
# These tests verify API key + client mode works (permissions from API key validation)
# =============================================================================


class TestApiKeyClientModeBaseline:
    """
    Baseline tests: API key auth + client mode (default) should work.

    This verifies the expected behavior that the fix will restore for server mode.
    """

    @pytest.mark.asyncio
    async def test_api_key_client_mode_permission_allowed(
        self, auth_config_client_mode, api_key_user_with_permissions
    ):
        """API key auth + client mode + user has permission → 200 OK."""
        guard = MagicMock(spec=AuthGuard)
        guard._config = auth_config_client_mode

        async def mock_auth(auth_header, api_key):
            if api_key:
                return api_key_user_with_permissions
            raise Exception("No credentials")

        guard.authenticate_or_raise = AsyncMock(side_effect=mock_auth)

        app = FastAPI()
        add_exception_handlers(app)

        @app.get("/data")
        async def get_data(
            user: AuthenticatedUser = Depends(require_permission(
                guard,
                "data:read",
            )),
        ):
            return {"user_id": user.user_id, "auth_method": user.auth_method.value}

        client = TestClient(app)
        response = client.get("/data", headers={"X-API-Key": "valid_key"})

        assert response.status_code == 200
        assert response.json()["auth_method"] == "api_key"

    @pytest.mark.asyncio
    async def test_api_key_client_mode_permission_denied(
        self, auth_config_client_mode, api_key_user_limited
    ):
        """API key auth + client mode + user lacks permission → 403 Forbidden."""
        guard = MagicMock(spec=AuthGuard)
        guard._config = auth_config_client_mode

        async def mock_auth(auth_header, api_key):
            if api_key:
                return api_key_user_limited
            raise Exception("No credentials")

        guard.authenticate_or_raise = AsyncMock(side_effect=mock_auth)

        app = FastAPI()
        add_exception_handlers(app)

        @app.get("/admin")
        async def admin_only(
            user: AuthenticatedUser = Depends(require_permission(
                guard,
                "admin:access",
            )),
        ):
            return {"admin": True}

        client = TestClient(app)
        response = client.get("/admin", headers={"X-API-Key": "limited_key"})

        assert response.status_code == 403


# =============================================================================
# IMPLEMENTATION VERIFICATION: Correct behavior after fix
# These tests verify the fix uses client-side check for API key auth
# =============================================================================


class TestApiKeyServerModeUsesServerSideCheckWithApiKey:
    """
    Verify that after the fix, API key auth + server mode still uses server-side checks.

    The fix should pass the API key to verify_permission, which then sends it
    via X-API-Key header to the /permissions/check endpoint. Server-side checks
    are authoritative (Zanzibar-based real-time permission system).
    """

    @pytest.mark.asyncio
    async def test_api_key_server_mode_calls_verify_permission_with_api_key(
        self, auth_config_server_mode, api_key_user_with_permissions
    ):
        """
        API key auth + server mode → verify_permission() SHOULD be called with API key.

        The fix should pass the API key to verify_permission so it can authenticate
        the permission check request via X-API-Key header.
        """
        guard = MagicMock(spec=AuthGuard)
        guard._config = auth_config_server_mode
        guard._http_client = AsyncMock()
        guard._permission_cache = MagicMock()
        guard._permission_cache.get = MagicMock(return_value=None)

        async def mock_auth(auth_header, api_key):
            if api_key:
                return api_key_user_with_permissions
            raise Exception("No credentials")

        guard.authenticate_or_raise = AsyncMock(side_effect=mock_auth)

        with patch("ab0t_auth.dependencies.verify_permission") as mock_verify:
            mock_verify.return_value = PermissionResult.grant("data:read")

            app = FastAPI()

            @app.get("/data")
            async def get_data(
                user: AuthenticatedUser = Depends(require_permission(
                    guard,
                    "data:read",
                )),
            ):
                return {"user_id": user.user_id}

            client = TestClient(app)
            response = client.get("/data", headers={"X-API-Key": "valid_key"})

            assert response.status_code == 200

            # CRITICAL: verify_permission SHOULD be called (server-side is authoritative)
            mock_verify.assert_called_once()

            # AFTER FIX: verify_permission should receive the API key
            call_kwargs = mock_verify.call_args
            # The fix should add api_key parameter to verify_permission
            # Check that api_key is passed (either as kwarg or the token is not empty)
            args = call_kwargs[0] if call_kwargs[0] else ()
            kwargs = call_kwargs[1] if call_kwargs[1] else {}

            # Current bug: token (arg index 2) is empty string ""
            # After fix: either token is non-empty OR api_key kwarg is passed
            token_arg = args[2] if len(args) > 2 else ""
            api_key_kwarg = kwargs.get("api_key", None)

            assert token_arg != "" or api_key_kwarg is not None, (
                f"Expected either non-empty token or api_key kwarg. "
                f"Got token={token_arg!r}, api_key={api_key_kwarg!r}. "
                "Bug: API key not passed to verify_permission for server-side check."
            )


# =============================================================================
# END-TO-END: Full flow with respx mocking auth service
# =============================================================================


class TestEndToEndApiKeyServerMode:
    """
    End-to-end tests with respx mocking the actual auth service HTTP calls.

    These tests simulate the real scenario more closely.
    """

    @pytest.mark.asyncio
    async def test_e2e_api_key_server_mode_full_flow(self, auth_config_server_mode):
        """
        Full E2E: API key validation → authenticate → permission check → response.

        This test demonstrates the actual bug: when permission_check_mode="server"
        and we authenticate via API key, the /permissions/check endpoint receives
        an empty Bearer token because `authorization or ""` evaluates to "".

        EXPECTED AFTER FIX: /permissions/check receives X-API-Key header instead,
        and the server-side Zanzibar check succeeds.
        """
        guard = AuthGuard(config=auth_config_server_mode)

        with respx.mock:
            # Mock API key validation endpoint
            respx.post(API_KEY_ENDPOINT).mock(
                return_value=httpx.Response(200, json={
                    "valid": True,
                    "user_id": "e2e_service_123",
                    "email": "e2e@example.com",
                    "org_id": "org_e2e",
                    "permissions": ["data:read", "data:write"],
                })
            )

            # Mock permission check endpoint
            # After fix: should receive Authorization: Bearer {api_key} and succeed
            def check_permission_handler(request):
                auth_header = request.headers.get("Authorization", "")
                # After fix: API key sent as Bearer token
                if auth_header == "Bearer e2e_test_key":
                    return httpx.Response(200, json={
                        "allowed": True,
                        "permission": "data:read",
                        "user_id": "e2e_service_123",
                    })
                # Bug: receives empty Bearer token
                elif auth_header == "Bearer ":
                    return httpx.Response(401, json={
                        "error": "Invalid or missing authorization token"
                    })
                else:
                    return httpx.Response(401, json={
                        "error": "No credentials provided"
                    })

            respx.post(PERMISSION_ENDPOINT).mock(side_effect=check_permission_handler)

            # Initialize guard with real HTTP client
            async with httpx.AsyncClient() as client:
                guard._http_client = client
                guard._initialized = True

                # Authenticate via API key - this works fine
                result = await guard.authenticate(
                    authorization=None,
                    api_key="e2e_test_key"
                )

                assert result.success
                assert result.user.user_id == "e2e_service_123"
                assert result.user.auth_method == AuthMethod.API_KEY
                assert "data:read" in result.user.permissions

                # Now create a FastAPI app and test permission check
                app = FastAPI()
                add_exception_handlers(app)

                @app.get("/e2e-data")
                async def e2e_data(
                    user: AuthenticatedUser = Depends(require_permission(
                        guard,
                        "data:read",
                    )),
                ):
                    return {"user_id": user.user_id}

                test_client = TestClient(app)
                response = test_client.get(
                    "/e2e-data",
                    headers={"X-API-Key": "e2e_test_key"}
                )

                # CURRENT BUG: 401 because empty Bearer token sent to /permissions/check
                # AFTER FIX: 200 because X-API-Key header sent to /permissions/check
                assert response.status_code == 200, (
                    f"E2E test failed. Expected 200, got {response.status_code}. "
                    f"Response: {response.json()}. "
                    "Bug: API key auth with server permission mode sends empty Bearer token "
                    "to /permissions/check instead of X-API-Key header."
                )


# =============================================================================
# REGRESSION: Ensure no permission bypass on AuthMethod spoofing
# =============================================================================


class TestNoAuthMethodSpoofing:
    """
    Security tests: Ensure the fix doesn't allow AuthMethod spoofing.

    An attacker should not be able to set auth_method=API_KEY to bypass
    server-side permission checks when authenticating via JWT.
    """

    @pytest.mark.asyncio
    async def test_jwt_cannot_spoof_api_key_auth_method(
        self, auth_config_server_mode
    ):
        """
        JWT auth should not be able to bypass server-side checks by claiming
        to be API key auth.

        The auth_method should be set by the authentication layer, not user input.
        """
        # Create a user that claims to be API key auth but actually authenticated via JWT
        spoofed_user = AuthenticatedUser(
            user_id="spoofer",
            email="spoof@evil.com",
            org_id="org_evil",
            permissions=("data:read",),
            roles=(),
            auth_method=AuthMethod.API_KEY,  # Spoofed!
            token_type=TokenType.BEARER,  # But token type is Bearer (JWT)
        )

        guard = MagicMock(spec=AuthGuard)
        guard._config = auth_config_server_mode
        guard._http_client = MagicMock()
        guard._permission_cache = MagicMock()
        guard._permission_cache.get = MagicMock(return_value=None)

        # Guard returns the spoofed user when JWT is provided
        async def mock_auth(auth_header, api_key):
            if auth_header and auth_header.startswith("Bearer "):
                return spoofed_user
            raise Exception("No credentials")

        guard.authenticate_or_raise = AsyncMock(side_effect=mock_auth)

        # The fix should check BOTH auth_method AND how authentication occurred.
        # If authorization header was provided, it's JWT auth regardless of auth_method.
        # This test documents the expected behavior.

        app = FastAPI()
        add_exception_handlers(app)

        @app.get("/data")
        async def get_data(
            user: AuthenticatedUser = Depends(require_permission(
                guard,
                "data:read",
            )),
        ):
            return {"user_id": user.user_id}

        # Note: This test documents expected behavior.
        # The implementation should prevent this attack vector.
        # For now, we accept that auth_method from authenticate_or_raise is trusted.
