"""
Tests for ab0t_auth.flask module.
"""

import time
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask, g

from ab0t_auth.core import AuthConfig, AuthenticatedUser, AuthMethod, TokenType
from ab0t_auth.errors import PermissionDeniedError, TokenNotFoundError
from ab0t_auth.flask import (
    Ab0tAuth,
    get_current_user,
    login_required,
    permission_required,
    permissions_required,
    role_required,
    permission_pattern_required,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def flask_app():
    """Create test Flask application."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["AB0T_AUTH_URL"] = "https://auth.test.ab0t.com"
    return app


@pytest.fixture
def auth_config():
    """Create test auth config."""
    return AuthConfig(
        auth_url="https://auth.test.ab0t.com",
        org_id="test_org",
        algorithms=("RS256",),
    )


@pytest.fixture
def test_user():
    """Create test user."""
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
def admin_user():
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


# =============================================================================
# Ab0tAuth Extension Tests
# =============================================================================


class TestAb0tAuthExtension:
    """Tests for Ab0tAuth Flask extension."""

    def test_init_with_app(self, flask_app):
        """Test initializing with Flask app."""
        with patch("ab0t_auth.flask.create_jwk_client"):
            auth = Ab0tAuth(flask_app, auth_url="https://auth.test.ab0t.com")

            assert auth._config is not None
            assert auth._config.auth_url == "https://auth.test.ab0t.com"
            assert "ab0t_auth" in flask_app.extensions

    def test_init_app_factory_pattern(self, flask_app):
        """Test factory pattern initialization."""
        with patch("ab0t_auth.flask.create_jwk_client"):
            auth = Ab0tAuth()
            auth.init_app(flask_app, auth_url="https://auth.test.ab0t.com")

            assert auth._config is not None
            assert "ab0t_auth" in flask_app.extensions

    def test_init_with_config(self, flask_app, auth_config):
        """Test initializing with AuthConfig."""
        with patch("ab0t_auth.flask.create_jwk_client"):
            auth = Ab0tAuth(flask_app, config=auth_config)

            assert auth._config.auth_url == auth_config.auth_url
            assert auth._config.algorithms == auth_config.algorithms

    def test_init_from_app_config(self, flask_app):
        """Test reading config from Flask app config."""
        flask_app.config["AB0T_AUTH_URL"] = "https://auth.example.com"
        flask_app.config["AB0T_AUTH_ORG_ID"] = "my_org"

        with patch("ab0t_auth.flask.create_jwk_client"):
            auth = Ab0tAuth(flask_app)

            assert auth._config.auth_url == "https://auth.example.com"

    def test_init_requires_auth_url(self, flask_app):
        """Test that auth_url is required."""
        flask_app.config.pop("AB0T_AUTH_URL", None)

        with pytest.raises(ValueError, match="Must provide auth_url"):
            Ab0tAuth(flask_app)

    def test_config_property_raises_if_not_initialized(self):
        """Test config property raises if not initialized."""
        auth = Ab0tAuth()

        with pytest.raises(RuntimeError, match="not initialized"):
            _ = auth.config

    def test_metrics_property(self, flask_app):
        """Test metrics property."""
        with patch("ab0t_auth.flask.create_jwk_client"):
            auth = Ab0tAuth(flask_app, auth_url="https://auth.test.ab0t.com")

            metrics = auth.metrics
            assert metrics.auth_attempts == 0


class TestAb0tAuthAuthentication:
    """Tests for authentication methods."""

    def test_authenticate_no_credentials(self, flask_app):
        """Test authenticate with no credentials."""
        with patch("ab0t_auth.flask.create_jwk_client"):
            auth = Ab0tAuth(flask_app, auth_url="https://auth.test.ab0t.com")

            result = auth.authenticate(None, None)

            assert not result.success
            assert result.error_code == "NO_CREDENTIALS"

    def test_authenticate_jwt_invalid_header(self, flask_app):
        """Test authenticate with invalid Authorization header."""
        with patch("ab0t_auth.flask.create_jwk_client"):
            auth = Ab0tAuth(flask_app, auth_url="https://auth.test.ab0t.com")

            # "InvalidHeader" without proper format returns NO_CREDENTIALS
            # because parse_token_header returns None
            result = auth.authenticate("InvalidHeader", None)

            assert not result.success
            assert result.error_code == "NO_CREDENTIALS"

    def test_authenticate_jwt_wrong_prefix(self, flask_app):
        """Test authenticate with wrong Authorization prefix."""
        with patch("ab0t_auth.flask.create_jwk_client"):
            auth = Ab0tAuth(flask_app, auth_url="https://auth.test.ab0t.com")

            # Wrong prefix "Basic" instead of "Bearer"
            result = auth.authenticate("Basic sometoken", None)

            assert not result.success
            # Falls through to NO_CREDENTIALS because parse_token_header returns None
            assert result.error_code == "NO_CREDENTIALS"

    def test_check_permission(self, flask_app, test_user):
        """Test check_permission method."""
        with patch("ab0t_auth.flask.create_jwk_client"):
            auth = Ab0tAuth(flask_app, auth_url="https://auth.test.ab0t.com")

            with flask_app.test_request_context():
                g.auth_user = test_user

                assert auth.check_permission("users:read")
                assert not auth.check_permission("admin:access")

    def test_require_permission_raises(self, flask_app, test_user):
        """Test require_permission raises on missing permission."""
        with patch("ab0t_auth.flask.create_jwk_client"):
            auth = Ab0tAuth(flask_app, auth_url="https://auth.test.ab0t.com")

            with flask_app.test_request_context():
                g.auth_user = test_user

                with pytest.raises(PermissionDeniedError):
                    auth.require_permission("admin:access")


# =============================================================================
# Decorator Tests
# =============================================================================


class TestLoginRequired:
    """Tests for login_required decorator."""

    def test_allows_authenticated_user(self, flask_app, test_user):
        """Test decorator allows authenticated user."""
        with patch("ab0t_auth.flask.create_jwk_client"):
            auth = Ab0tAuth(flask_app, auth_url="https://auth.test.ab0t.com", auto_authenticate=False)

            @flask_app.route("/test")
            @login_required
            def test_route():
                return {"user": get_current_user().user_id}

            with flask_app.test_client() as client:
                with flask_app.test_request_context():
                    g.auth_user = test_user

                    # Manually test the decorated function
                    with patch("ab0t_auth.flask.get_current_user", return_value=test_user):
                        result = test_route()
                        assert result["user"] == "user_123"

    def test_raises_for_unauthenticated(self, flask_app):
        """Test decorator raises for unauthenticated user."""
        @login_required
        def test_route():
            return {"ok": True}

        with flask_app.test_request_context():
            g.auth_user = None

            with pytest.raises(TokenNotFoundError):
                test_route()


class TestPermissionRequired:
    """Tests for permission_required decorator."""

    def test_allows_with_permission(self, flask_app, test_user):
        """Test decorator allows user with permission."""
        @permission_required("users:read")
        def test_route():
            return {"ok": True}

        with flask_app.test_request_context():
            g.auth_user = test_user

            result = test_route()
            assert result["ok"]

    def test_denies_without_permission(self, flask_app, test_user):
        """Test decorator denies user without permission."""
        @permission_required("admin:access")
        def test_route():
            return {"ok": True}

        with flask_app.test_request_context():
            g.auth_user = test_user

            with pytest.raises(PermissionDeniedError) as exc_info:
                test_route()

            assert "admin:access" in str(exc_info.value)

    def test_raises_for_unauthenticated(self, flask_app):
        """Test decorator raises for unauthenticated user."""
        @permission_required("users:read")
        def test_route():
            return {"ok": True}

        with flask_app.test_request_context():
            g.auth_user = None

            with pytest.raises(TokenNotFoundError):
                test_route()


class TestPermissionsRequired:
    """Tests for permissions_required decorator."""

    def test_require_all_success(self, flask_app, test_user):
        """Test requiring all permissions - success."""
        @permissions_required("users:read", "users:write", require_all=True)
        def test_route():
            return {"ok": True}

        with flask_app.test_request_context():
            g.auth_user = test_user

            result = test_route()
            assert result["ok"]

    def test_require_all_failure(self, flask_app, test_user):
        """Test requiring all permissions - failure."""
        @permissions_required("users:read", "admin:access", require_all=True)
        def test_route():
            return {"ok": True}

        with flask_app.test_request_context():
            g.auth_user = test_user

            with pytest.raises(PermissionDeniedError):
                test_route()

    def test_require_any_success(self, flask_app, test_user):
        """Test requiring any permission - success."""
        @permissions_required("users:read", "admin:access", require_all=False)
        def test_route():
            return {"ok": True}

        with flask_app.test_request_context():
            g.auth_user = test_user

            result = test_route()
            assert result["ok"]

    def test_require_any_failure(self, flask_app, test_user):
        """Test requiring any permission - failure."""
        @permissions_required("admin:access", "super:admin", require_all=False)
        def test_route():
            return {"ok": True}

        with flask_app.test_request_context():
            g.auth_user = test_user

            with pytest.raises(PermissionDeniedError):
                test_route()


class TestRoleRequired:
    """Tests for role_required decorator."""

    def test_allows_with_role(self, flask_app, test_user):
        """Test decorator allows user with role."""
        @role_required("user")
        def test_route():
            return {"ok": True}

        with flask_app.test_request_context():
            g.auth_user = test_user

            result = test_route()
            assert result["ok"]

    def test_denies_without_role(self, flask_app, test_user):
        """Test decorator denies user without role."""
        @role_required("admin")
        def test_route():
            return {"ok": True}

        with flask_app.test_request_context():
            g.auth_user = test_user

            with pytest.raises(PermissionDeniedError) as exc_info:
                test_route()

            assert "admin" in str(exc_info.value)


class TestPermissionPatternRequired:
    """Tests for permission_pattern_required decorator."""

    def test_allows_matching_pattern(self, flask_app, test_user):
        """Test decorator allows matching pattern."""
        @permission_pattern_required("users:*")
        def test_route():
            return {"ok": True}

        with flask_app.test_request_context():
            g.auth_user = test_user

            result = test_route()
            assert result["ok"]

    def test_denies_non_matching_pattern(self, flask_app, test_user):
        """Test decorator denies non-matching pattern."""
        @permission_pattern_required("admin:*")
        def test_route():
            return {"ok": True}

        with flask_app.test_request_context():
            g.auth_user = test_user

            with pytest.raises(PermissionDeniedError):
                test_route()


# =============================================================================
# get_current_user Tests
# =============================================================================


class TestGetCurrentUser:
    """Tests for get_current_user function."""

    def test_returns_user_from_g(self, flask_app, test_user):
        """Test getting user from flask.g."""
        with flask_app.test_request_context():
            g.auth_user = test_user

            user = get_current_user()

            assert user == test_user
            assert user.user_id == "user_123"

    def test_returns_none_when_no_user(self, flask_app):
        """Test returning None when no user."""
        with flask_app.test_request_context():
            g.auth_user = None

            user = get_current_user()

            assert user is None


# =============================================================================
# Cache Management Tests
# =============================================================================


class TestCacheManagement:
    """Tests for cache management methods."""

    def test_invalidate_token(self, flask_app):
        """Test invalidating cached token."""
        with patch("ab0t_auth.flask.create_jwk_client"):
            auth = Ab0tAuth(flask_app, auth_url="https://auth.test.ab0t.com")

            # Should not raise even with empty cache
            result = auth.invalidate_token("some_token")
            assert result is False

    def test_clear_caches(self, flask_app):
        """Test clearing all caches."""
        with patch("ab0t_auth.flask.create_jwk_client"):
            auth = Ab0tAuth(flask_app, auth_url="https://auth.test.ab0t.com")

            # Should not raise
            auth.clear_caches()
