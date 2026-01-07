"""
Tests for auth bypass functionality.

These tests verify the defense-in-depth bypass mechanism for testing/development.
"""

import os
import pytest
from unittest.mock import patch

from ab0t_auth.config import BypassConfig, load_bypass_config
from ab0t_auth.core import AuthMethod, TokenType
from ab0t_auth.guard import AuthGuard


# =============================================================================
# BypassConfig Tests
# =============================================================================


class TestBypassConfig:
    """Tests for BypassConfig dataclass."""

    def test_default_config_disabled(self) -> None:
        """Test default config has bypass disabled."""
        config = BypassConfig()
        assert config.enabled is False
        assert config.user_id == "bypass_user"
        assert config.email == "bypass@test.local"
        assert config.permissions == ()
        assert config.roles == ()
        assert config.org_id is None

    def test_config_with_values(self) -> None:
        """Test config with custom values."""
        config = BypassConfig(
            enabled=True,
            user_id="test_user",
            email="test@example.com",
            permissions=("users:read", "users:write"),
            roles=("admin",),
            org_id="test_org",
        )
        assert config.enabled is True
        assert config.user_id == "test_user"
        assert config.email == "test@example.com"
        assert config.permissions == ("users:read", "users:write")
        assert config.roles == ("admin",)
        assert config.org_id == "test_org"

    def test_config_immutable(self) -> None:
        """Test that config is immutable."""
        config = BypassConfig()
        with pytest.raises(AttributeError):
            config.enabled = True  # type: ignore


# =============================================================================
# load_bypass_config Tests
# =============================================================================


class TestLoadBypassConfig:
    """Tests for load_bypass_config function."""

    def test_disabled_by_default(self) -> None:
        """Test bypass is disabled when no env vars set."""
        with patch.dict(os.environ, {}, clear=True):
            config = load_bypass_config()
            assert config.enabled is False

    def test_disabled_with_only_bypass_flag(self) -> None:
        """Test bypass is disabled with only BYPASS=true (no DEBUG)."""
        with patch.dict(os.environ, {"AB0T_AUTH_BYPASS": "true"}, clear=True):
            config = load_bypass_config()
            assert config.enabled is False

    def test_disabled_with_only_debug_flag(self) -> None:
        """Test bypass is disabled with only DEBUG=true (no BYPASS)."""
        with patch.dict(os.environ, {"AB0T_AUTH_DEBUG": "true"}, clear=True):
            config = load_bypass_config()
            assert config.enabled is False

    def test_enabled_with_both_flags(self) -> None:
        """Test bypass is enabled when BOTH flags are set."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
        }, clear=True):
            config = load_bypass_config()
            assert config.enabled is True

    def test_case_insensitive_flags(self) -> None:
        """Test flags are case insensitive."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "TRUE",
            "AB0T_AUTH_DEBUG": "True",
        }, clear=True):
            config = load_bypass_config()
            assert config.enabled is True

    def test_custom_user_id(self) -> None:
        """Test custom user ID from env var."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_USER_ID": "custom_user",
        }, clear=True):
            config = load_bypass_config()
            assert config.user_id == "custom_user"

    def test_custom_email(self) -> None:
        """Test custom email from env var."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_EMAIL": "custom@test.com",
        }, clear=True):
            config = load_bypass_config()
            assert config.email == "custom@test.com"

    def test_permissions_from_env(self) -> None:
        """Test permissions parsed from comma-separated env var."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_PERMISSIONS": "users:read,users:write,admin:access",
        }, clear=True):
            config = load_bypass_config()
            assert config.permissions == ("users:read", "users:write", "admin:access")

    def test_permissions_with_spaces(self) -> None:
        """Test permissions with spaces around commas are trimmed."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_PERMISSIONS": "users:read , users:write , admin:access",
        }, clear=True):
            config = load_bypass_config()
            assert config.permissions == ("users:read", "users:write", "admin:access")

    def test_roles_from_env(self) -> None:
        """Test roles parsed from comma-separated env var."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_ROLES": "admin,user,editor",
        }, clear=True):
            config = load_bypass_config()
            assert config.roles == ("admin", "user", "editor")

    def test_org_id_from_env(self) -> None:
        """Test org_id from env var."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_ORG_ID": "test_org_123",
        }, clear=True):
            config = load_bypass_config()
            assert config.org_id == "test_org_123"

    def test_empty_permissions_string(self) -> None:
        """Test empty permissions string results in empty tuple."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_PERMISSIONS": "",
        }, clear=True):
            config = load_bypass_config()
            assert config.permissions == ()


# =============================================================================
# AuthGuard Bypass Integration Tests
# =============================================================================


class TestAuthGuardBypass:
    """Tests for AuthGuard bypass integration."""

    @pytest.fixture
    def guard_with_bypass(self) -> AuthGuard:
        """Create AuthGuard with bypass enabled."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_USER_ID": "test_bypass_user",
            "AB0T_AUTH_BYPASS_PERMISSIONS": "users:read,users:write",
            "AB0T_AUTH_BYPASS_ROLES": "admin",
        }, clear=True):
            # Need to reload bypass config
            from ab0t_auth.config import load_bypass_config
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()
            return guard

    @pytest.fixture
    def guard_without_bypass(self) -> AuthGuard:
        """Create AuthGuard with bypass disabled."""
        with patch.dict(os.environ, {}, clear=True):
            from ab0t_auth.config import load_bypass_config
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()
            return guard

    def test_check_auth_bypass_returns_result_when_enabled(
        self, guard_with_bypass: AuthGuard
    ) -> None:
        """Test _check_auth_bypass returns AuthResult when bypass enabled."""
        result = guard_with_bypass._check_auth_bypass()
        assert result is not None
        assert result.success is True
        assert result.user is not None

    def test_check_auth_bypass_returns_none_when_disabled(
        self, guard_without_bypass: AuthGuard
    ) -> None:
        """Test _check_auth_bypass returns None when bypass disabled."""
        result = guard_without_bypass._check_auth_bypass()
        assert result is None

    def test_bypass_user_has_correct_attributes(
        self, guard_with_bypass: AuthGuard
    ) -> None:
        """Test bypass user has correct attributes from config."""
        result = guard_with_bypass._check_auth_bypass()
        assert result is not None
        assert result.user is not None

        user = result.user
        assert user.user_id == "test_bypass_user"
        assert user.permissions == ("users:read", "users:write")
        assert user.roles == ("admin",)
        assert user.auth_method == AuthMethod.BYPASS
        assert user.token_type == TokenType.NONE

    @pytest.mark.asyncio
    async def test_authenticate_uses_bypass_when_enabled(
        self, guard_with_bypass: AuthGuard
    ) -> None:
        """Test authenticate returns bypass user when enabled."""
        result = await guard_with_bypass.authenticate()
        assert result.success is True
        assert result.user is not None
        assert result.user.auth_method == AuthMethod.BYPASS

    @pytest.mark.asyncio
    async def test_authenticate_bypass_ignores_credentials(
        self, guard_with_bypass: AuthGuard
    ) -> None:
        """Test bypass ignores provided credentials."""
        result = await guard_with_bypass.authenticate(
            authorization="Bearer invalid_token",
            api_key="invalid_key",
        )
        # Should still succeed because bypass is enabled
        assert result.success is True
        assert result.user is not None
        assert result.user.auth_method == AuthMethod.BYPASS

    @pytest.mark.asyncio
    async def test_authenticate_fails_without_bypass_and_no_credentials(
        self, guard_without_bypass: AuthGuard
    ) -> None:
        """Test authenticate fails when bypass disabled and no credentials."""
        result = await guard_without_bypass.authenticate()
        assert result.success is False
        assert result.error_code == "NO_CREDENTIALS"


# =============================================================================
# Enum Tests
# =============================================================================


class TestBypassEnums:
    """Tests for bypass-related enum values."""

    def test_auth_method_bypass_exists(self) -> None:
        """Test AuthMethod.BYPASS enum value exists."""
        assert AuthMethod.BYPASS == "bypass"
        assert AuthMethod.BYPASS.value == "bypass"

    def test_token_type_none_exists(self) -> None:
        """Test TokenType.NONE enum value exists."""
        assert TokenType.NONE == "None"
        assert TokenType.NONE.value == "None"
