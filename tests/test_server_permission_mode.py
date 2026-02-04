"""
Tests for server-side permission checking mode.

Tests the `permission_check_mode` configuration that switches between
client-side (JWT claims) and server-side (/permissions/check API) verification.
"""

import pytest
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
from ab0t_auth.dependencies import require_permission


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
def test_user() -> AuthenticatedUser:
    """User with specific permissions for testing."""
    return AuthenticatedUser(
        user_id="user_123",
        email="test@example.com",
        org_id="org_abc",
        permissions=("users:read", "reports:view"),  # Has users:read, NOT admin:access
        roles=("user",),
        auth_method=AuthMethod.JWT,
        token_type=TokenType.BEARER,
    )


@pytest.fixture
def mock_guard_client_mode(test_user: AuthenticatedUser):
    """Mock AuthGuard in client mode (default)."""
    guard = MagicMock(spec=AuthGuard)
    guard.config = MagicMock()
    guard.config.api_key_header = "X-API-Key"
    guard.config.header_name = "Authorization"
    guard._config = MagicMock()
    guard._config.permission_check_mode = "client"

    async def mock_authenticate_or_raise(auth, api_key):
        return test_user

    guard.authenticate_or_raise = AsyncMock(side_effect=mock_authenticate_or_raise)
    return guard


@pytest.fixture
def mock_guard_server_mode(test_user: AuthenticatedUser):
    """Mock AuthGuard in server mode."""
    guard = MagicMock(spec=AuthGuard)
    guard.config = MagicMock()
    guard.config.api_key_header = "X-API-Key"
    guard.config.header_name = "Authorization"
    guard._config = MagicMock()
    guard._config.permission_check_mode = "server"
    guard._http_client = MagicMock()
    guard._permission_cache = MagicMock()
    guard._permission_cache.get = MagicMock(return_value=None)  # No cache hit

    async def mock_authenticate_or_raise(auth, api_key):
        return test_user

    guard.authenticate_or_raise = AsyncMock(side_effect=mock_authenticate_or_raise)
    return guard


# =============================================================================
# Test Client Mode (Default Behavior)
# =============================================================================


class TestClientModePermissionCheck:
    """Tests for client-side permission checking (JWT claims)."""

    def test_permission_granted_from_claims(self, mock_guard_client_mode: AuthGuard):
        """Permission check passes when user has permission in JWT claims."""
        app = FastAPI()

        @app.get("/users")
        async def get_users(
            user: AuthenticatedUser = Depends(require_permission(
                mock_guard_client_mode,
                "users:read",
            )),
        ):
            return {"user_id": user.user_id, "mode": "client"}

        client = TestClient(app)
        response = client.get("/users", headers={"Authorization": "Bearer token"})

        assert response.status_code == 200
        assert response.json()["user_id"] == "user_123"

    def test_permission_denied_from_claims(self, mock_guard_client_mode: AuthGuard):
        """Permission check fails when user lacks permission in JWT claims."""
        app = FastAPI()
        add_exception_handlers(app)

        @app.get("/admin")
        async def admin_only(
            user: AuthenticatedUser = Depends(require_permission(
                mock_guard_client_mode,
                "admin:access",  # User doesn't have this
            )),
        ):
            return {"admin": True}

        client = TestClient(app)
        response = client.get("/admin", headers={"Authorization": "Bearer token"})

        assert response.status_code == 403
        assert "admin:access" in response.json()["detail"]


# =============================================================================
# Test Server Mode (API Call to /permissions/check)
# =============================================================================


class TestServerModePermissionCheck:
    """Tests for server-side permission checking (API call)."""

    def test_permission_granted_from_server(self, mock_guard_server_mode: AuthGuard, test_user: AuthenticatedUser):
        """Permission check passes when server grants permission."""
        app = FastAPI()

        # Mock verify_permission to return allowed
        with patch("ab0t_auth.dependencies.verify_permission") as mock_verify:
            mock_verify.return_value = PermissionResult.grant("admin:access")

            @app.get("/admin")
            async def admin_only(
                user: AuthenticatedUser = Depends(require_permission(
                    mock_guard_server_mode,
                    "admin:access",  # User doesn't have in JWT, but server grants
                )),
            ):
                return {"admin": True, "user_id": user.user_id}

            client = TestClient(app)
            response = client.get("/admin", headers={"Authorization": "Bearer token"})

            assert response.status_code == 200
            assert response.json()["admin"] is True

            # Verify the server-side check was called
            mock_verify.assert_called_once()

    def test_permission_denied_from_server(self, mock_guard_server_mode: AuthGuard, test_user: AuthenticatedUser):
        """Permission check fails when server denies permission."""
        app = FastAPI()
        add_exception_handlers(app)

        # Mock verify_permission to return denied
        with patch("ab0t_auth.dependencies.verify_permission") as mock_verify:
            mock_verify.return_value = PermissionResult.deny(
                "admin:access",
                "User does not have this permission",
            )

            @app.get("/admin")
            async def admin_only(
                user: AuthenticatedUser = Depends(require_permission(
                    mock_guard_server_mode,
                    "admin:access",
                )),
            ):
                return {"admin": True}

            client = TestClient(app)
            response = client.get("/admin", headers={"Authorization": "Bearer token"})

            assert response.status_code == 403
            mock_verify.assert_called_once()

    def test_server_mode_overrides_jwt_claims(self, mock_guard_server_mode: AuthGuard, test_user: AuthenticatedUser):
        """
        Server mode is authoritative - can deny even if JWT has the permission.

        This is the key use case: permissions can be revoked instantly on the
        server without waiting for JWT expiration.
        """
        app = FastAPI()
        add_exception_handlers(app)

        # User has users:read in JWT claims, but server denies it
        with patch("ab0t_auth.dependencies.verify_permission") as mock_verify:
            mock_verify.return_value = PermissionResult.deny(
                "users:read",
                "Permission revoked by admin",
            )

            @app.get("/users")
            async def get_users(
                user: AuthenticatedUser = Depends(require_permission(
                    mock_guard_server_mode,
                    "users:read",  # User HAS this in JWT, but server denies
                )),
            ):
                return {"users": []}

            client = TestClient(app)
            response = client.get("/users", headers={"Authorization": "Bearer token"})

            # Should be denied despite having permission in JWT
            assert response.status_code == 403
            mock_verify.assert_called_once()


# =============================================================================
# Test Configuration
# =============================================================================


class TestPermissionCheckModeConfig:
    """Tests for permission_check_mode configuration."""

    def test_default_mode_is_client(self):
        """Default permission_check_mode should be 'client'."""
        config = AuthConfig(auth_url="https://auth.example.com")
        assert config.permission_check_mode == "client"

    def test_can_set_server_mode(self):
        """Can explicitly set permission_check_mode to 'server'."""
        config = AuthConfig(
            auth_url="https://auth.example.com",
            permission_check_mode="server",
        )
        assert config.permission_check_mode == "server"

    def test_guard_accepts_mode_parameter(self):
        """AuthGuard accepts permission_check_mode in constructor."""
        guard = AuthGuard(
            auth_url="https://auth.example.com",
            permission_check_mode="server",
        )
        assert guard._config.permission_check_mode == "server"

    def test_guard_defaults_to_client_mode(self):
        """AuthGuard defaults to client mode."""
        guard = AuthGuard(auth_url="https://auth.example.com")
        assert guard._config.permission_check_mode == "client"


# =============================================================================
# Test Environment Variable Configuration
# =============================================================================


class TestPermissionCheckModeEnvVar:
    """Tests for AB0T_AUTH_PERMISSION_CHECK_MODE environment variable."""

    def test_env_var_sets_server_mode(self, monkeypatch):
        """AB0T_AUTH_PERMISSION_CHECK_MODE=server enables server mode."""
        monkeypatch.setenv("AB0T_AUTH_PERMISSION_CHECK_MODE", "server")

        from ab0t_auth.config import AuthSettings
        settings = AuthSettings()

        assert settings.permission_check_mode == "server"

    def test_env_var_defaults_to_client(self):
        """Without env var, defaults to client mode."""
        from ab0t_auth.config import AuthSettings
        settings = AuthSettings()

        assert settings.permission_check_mode == "client"
