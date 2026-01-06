"""
Tests for ab0t_auth.core module.
"""

import time

import pytest

from ab0t_auth.core import (
    AuthConfig,
    AuthContext,
    AuthenticatedUser,
    AuthMethod,
    AuthResult,
    Permission,
    PermissionResult,
    TokenClaims,
    TokenType,
)


class TestTokenClaims:
    """Tests for TokenClaims dataclass."""

    def test_create_token_claims(self):
        """Test creating TokenClaims."""
        claims = TokenClaims(
            sub="user_123",
            email="test@example.com",
            org_id="org_456",
            permissions=("read", "write"),
        )

        assert claims.sub == "user_123"
        assert claims.email == "test@example.com"
        assert claims.org_id == "org_456"
        assert claims.permissions == ("read", "write")

    def test_token_claims_immutable(self):
        """Test that TokenClaims is frozen."""
        claims = TokenClaims(sub="user_123")

        with pytest.raises(AttributeError):
            claims.sub = "other_user"  # type: ignore

    def test_token_claims_defaults(self):
        """Test TokenClaims default values."""
        claims = TokenClaims()

        assert claims.sub is None
        assert claims.permissions == ()
        assert claims.roles == ()
        assert claims.raw == {}


class TestAuthenticatedUser:
    """Tests for AuthenticatedUser dataclass."""

    def test_create_user(self):
        """Test creating AuthenticatedUser."""
        user = AuthenticatedUser(
            user_id="user_123",
            email="test@example.com",
            permissions=("users:read", "users:write"),
            roles=("admin",),
        )

        assert user.user_id == "user_123"
        assert user.email == "test@example.com"
        assert "users:read" in user.permissions

    def test_has_permission(self, test_user: AuthenticatedUser):
        """Test has_permission method."""
        assert test_user.has_permission("users:read")
        assert test_user.has_permission("users:write")
        assert not test_user.has_permission("admin:access")

    def test_has_any_permission(self, test_user: AuthenticatedUser):
        """Test has_any_permission method."""
        assert test_user.has_any_permission("users:read", "admin:access")
        assert test_user.has_any_permission("admin:access", "users:write")
        assert not test_user.has_any_permission("admin:access", "billing:read")

    def test_has_all_permissions(self, test_user: AuthenticatedUser):
        """Test has_all_permissions method."""
        assert test_user.has_all_permissions("users:read", "users:write")
        assert not test_user.has_all_permissions("users:read", "admin:access")

    def test_has_role(self, test_user: AuthenticatedUser):
        """Test has_role method."""
        assert test_user.has_role("user")
        assert test_user.has_role("editor")
        assert not test_user.has_role("admin")

    def test_user_immutable(self, test_user: AuthenticatedUser):
        """Test that AuthenticatedUser is frozen."""
        with pytest.raises(AttributeError):
            test_user.user_id = "other"  # type: ignore


class TestAuthContext:
    """Tests for AuthContext dataclass."""

    def test_create_context_authenticated(self, test_user: AuthenticatedUser):
        """Test creating context with authenticated user."""
        ctx = AuthContext(
            user=test_user,
            is_authenticated=True,
            token="test_token",
            request_id="req_123",
        )

        assert ctx.user == test_user
        assert ctx.is_authenticated
        assert ctx.token == "test_token"
        assert ctx.request_id == "req_123"

    def test_create_context_unauthenticated(self):
        """Test creating context without user."""
        ctx = AuthContext(
            user=None,
            is_authenticated=False,
        )

        assert ctx.user is None
        assert not ctx.is_authenticated
        assert ctx.error is None


class TestAuthConfig:
    """Tests for AuthConfig dataclass."""

    def test_create_config(self):
        """Test creating AuthConfig."""
        config = AuthConfig(
            auth_url="https://auth.example.com",
            org_id="test_org",
            audience="my-api",
        )

        assert config.auth_url == "https://auth.example.com"
        assert config.org_id == "test_org"
        assert config.audience == "my-api"

    def test_config_defaults(self):
        """Test AuthConfig default values."""
        config = AuthConfig(auth_url="https://auth.example.com")

        assert config.algorithms == ("RS256", "RS384", "RS512")
        assert config.jwks_cache_ttl == 300
        assert config.token_cache_ttl == 60
        assert config.verify_exp is True
        assert config.header_name == "Authorization"
        assert config.header_prefix == "Bearer"


class TestAuthResult:
    """Tests for AuthResult dataclass."""

    def test_ok_result(self, test_user: AuthenticatedUser):
        """Test creating successful result."""
        result = AuthResult.ok(test_user)

        assert result.success
        assert result.user == test_user
        assert result.error_code is None
        assert result.error_message is None

    def test_fail_result(self):
        """Test creating failed result."""
        result = AuthResult.fail("INVALID_TOKEN", "Token is invalid")

        assert not result.success
        assert result.user is None
        assert result.error_code == "INVALID_TOKEN"
        assert result.error_message == "Token is invalid"


class TestPermissionResult:
    """Tests for PermissionResult dataclass."""

    def test_grant_result(self):
        """Test creating granted result."""
        result = PermissionResult.grant("users:read")

        assert result.allowed
        assert result.permission == "users:read"
        assert result.reason is None

    def test_deny_result(self):
        """Test creating denied result."""
        result = PermissionResult.deny("admin:access", "User is not admin")

        assert not result.allowed
        assert result.permission == "admin:access"
        assert result.reason == "User is not admin"


class TestPermission:
    """Tests for Permission dataclass."""

    def test_create_permission(self):
        """Test creating Permission."""
        perm = Permission(
            name="users:delete",
            description="Delete users",
            category="users",
            is_sensitive=True,
        )

        assert perm.name == "users:delete"
        assert perm.description == "Delete users"
        assert perm.category == "users"
        assert perm.is_sensitive
