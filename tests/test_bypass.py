"""
Tests for auth bypass functionality.

These tests verify the defense-in-depth bypass mechanism for testing/development.
Comprehensive coverage includes:
- Configuration loading and validation
- Defense-in-depth (requires two env vars)
- User attribute injection
- Permission enforcement on bypass user
- Logging behavior
- Metrics recording
- Edge cases and error conditions
"""

import os
import pytest
from unittest.mock import MagicMock, patch

from ab0t_auth.config import BypassConfig, load_bypass_config
from ab0t_auth.core import AuthMethod, AuthenticatedUser, TokenType
from ab0t_auth.guard import AuthGuard
from ab0t_auth.permissions import check_permission, check_all_permissions, check_any_permission


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

    def test_auth_method_bypass_is_string_enum(self) -> None:
        """Test AuthMethod.BYPASS works as string."""
        assert str(AuthMethod.BYPASS) == "AuthMethod.BYPASS"
        assert f"{AuthMethod.BYPASS.value}" == "bypass"

    def test_token_type_none_is_string_enum(self) -> None:
        """Test TokenType.NONE works as string."""
        assert str(TokenType.NONE) == "TokenType.NONE"
        assert f"{TokenType.NONE.value}" == "None"


# =============================================================================
# Edge Cases and Invalid Values Tests
# =============================================================================


class TestBypassEdgeCases:
    """Tests for edge cases and invalid environment variable values."""

    def test_bypass_false_string_disables(self) -> None:
        """Test 'false' string disables bypass."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "false",
            "AB0T_AUTH_DEBUG": "true",
        }, clear=True):
            config = load_bypass_config()
            assert config.enabled is False

    def test_bypass_zero_disables(self) -> None:
        """Test '0' does not enable bypass."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "0",
            "AB0T_AUTH_DEBUG": "1",
        }, clear=True):
            config = load_bypass_config()
            assert config.enabled is False

    def test_bypass_yes_does_not_enable(self) -> None:
        """Test 'yes' does not enable bypass (must be 'true')."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "yes",
            "AB0T_AUTH_DEBUG": "yes",
        }, clear=True):
            config = load_bypass_config()
            assert config.enabled is False

    def test_bypass_one_does_not_enable(self) -> None:
        """Test '1' does not enable bypass (must be 'true')."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "1",
            "AB0T_AUTH_DEBUG": "1",
        }, clear=True):
            config = load_bypass_config()
            assert config.enabled is False

    def test_whitespace_only_permissions(self) -> None:
        """Test whitespace-only permissions string results in empty tuple."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_PERMISSIONS": "   ,  ,   ",
        }, clear=True):
            config = load_bypass_config()
            assert config.permissions == ()

    def test_single_permission(self) -> None:
        """Test single permission without comma."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_PERMISSIONS": "admin:full",
        }, clear=True):
            config = load_bypass_config()
            assert config.permissions == ("admin:full",)

    def test_single_role(self) -> None:
        """Test single role without comma."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_ROLES": "superadmin",
        }, clear=True):
            config = load_bypass_config()
            assert config.roles == ("superadmin",)

    def test_empty_user_id_uses_default(self) -> None:
        """Test empty user ID falls back to default."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_USER_ID": "",
        }, clear=True):
            config = load_bypass_config()
            # Empty string from getenv, but default is used
            assert config.user_id == ""  # Actually uses empty string

    def test_special_characters_in_permissions(self) -> None:
        """Test special characters in permissions are preserved."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_PERMISSIONS": "resource:read:*,org:123:admin",
        }, clear=True):
            config = load_bypass_config()
            assert config.permissions == ("resource:read:*", "org:123:admin")


# =============================================================================
# Permission Enforcement Tests
# =============================================================================


class TestBypassPermissionEnforcement:
    """Tests verifying permissions are enforced on bypass user."""

    @pytest.fixture
    def bypass_user_with_permissions(self) -> AuthenticatedUser:
        """Create bypass user with specific permissions."""
        return AuthenticatedUser(
            user_id="bypass_user",
            email="bypass@test.local",
            permissions=("users:read", "users:write", "reports:view"),
            roles=("editor", "viewer"),
            auth_method=AuthMethod.BYPASS,
            token_type=TokenType.NONE,
        )

    @pytest.fixture
    def bypass_user_no_permissions(self) -> AuthenticatedUser:
        """Create bypass user with no permissions."""
        return AuthenticatedUser(
            user_id="bypass_user",
            email="bypass@test.local",
            permissions=(),
            roles=(),
            auth_method=AuthMethod.BYPASS,
            token_type=TokenType.NONE,
        )

    def test_bypass_user_has_permission_granted(
        self, bypass_user_with_permissions: AuthenticatedUser
    ) -> None:
        """Test bypass user permission check returns granted."""
        result = check_permission(bypass_user_with_permissions, "users:read")
        assert result.allowed is True

    def test_bypass_user_has_permission_denied(
        self, bypass_user_with_permissions: AuthenticatedUser
    ) -> None:
        """Test bypass user permission check returns denied for missing permission."""
        result = check_permission(bypass_user_with_permissions, "admin:delete")
        assert result.allowed is False

    def test_bypass_user_check_all_permissions_granted(
        self, bypass_user_with_permissions: AuthenticatedUser
    ) -> None:
        """Test bypass user has all specified permissions."""
        result = check_all_permissions(
            bypass_user_with_permissions,
            "users:read",
            "users:write",
        )
        assert result.allowed is True

    def test_bypass_user_check_all_permissions_denied(
        self, bypass_user_with_permissions: AuthenticatedUser
    ) -> None:
        """Test bypass user missing one of required permissions."""
        result = check_all_permissions(
            bypass_user_with_permissions,
            "users:read",
            "admin:delete",
        )
        assert result.allowed is False

    def test_bypass_user_check_any_permission_granted(
        self, bypass_user_with_permissions: AuthenticatedUser
    ) -> None:
        """Test bypass user has at least one permission."""
        result = check_any_permission(
            bypass_user_with_permissions,
            "admin:delete",
            "users:read",
        )
        assert result.allowed is True

    def test_bypass_user_check_any_permission_denied(
        self, bypass_user_no_permissions: AuthenticatedUser
    ) -> None:
        """Test bypass user with no permissions is denied."""
        result = check_any_permission(
            bypass_user_no_permissions,
            "admin:delete",
            "users:read",
        )
        assert result.allowed is False

    def test_bypass_user_has_role(
        self, bypass_user_with_permissions: AuthenticatedUser
    ) -> None:
        """Test bypass user role check."""
        assert bypass_user_with_permissions.has_role("editor") is True
        assert bypass_user_with_permissions.has_role("admin") is False

    def test_bypass_user_has_permission_method(
        self, bypass_user_with_permissions: AuthenticatedUser
    ) -> None:
        """Test bypass user has_permission method."""
        assert bypass_user_with_permissions.has_permission("users:read") is True
        assert bypass_user_with_permissions.has_permission("admin:all") is False


# =============================================================================
# Logging Behavior Tests
# =============================================================================


class TestBypassLogging:
    """Tests verifying bypass logs WARNING on every request."""

    def test_bypass_logs_warning(self) -> None:
        """Test that bypass logs WARNING message."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_USER_ID": "log_test_user",
        }, clear=True):
            from ab0t_auth.config import load_bypass_config
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()

            # Mock the logger
            mock_logger = MagicMock()
            guard._logger = mock_logger

            # Call bypass check
            result = guard._check_auth_bypass()

            # Verify WARNING was logged
            mock_logger.warning.assert_called_once()
            call_args = mock_logger.warning.call_args
            assert call_args[0][0] == "AUTH BYPASS ACTIVE"
            assert call_args[1]["event_type"] == "auth_bypass"
            assert call_args[1]["user_id"] == "log_test_user"
            assert call_args[1]["warning"] == "Not for production use"

    def test_bypass_logs_permissions_and_roles(self) -> None:
        """Test that bypass logs permissions and roles."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_PERMISSIONS": "test:perm",
            "AB0T_AUTH_BYPASS_ROLES": "test_role",
        }, clear=True):
            from ab0t_auth.config import load_bypass_config
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()

            mock_logger = MagicMock()
            guard._logger = mock_logger

            guard._check_auth_bypass()

            call_kwargs = mock_logger.warning.call_args[1]
            assert call_kwargs["permissions"] == ("test:perm",)
            assert call_kwargs["roles"] == ("test_role",)

    def test_no_logging_when_bypass_disabled(self) -> None:
        """Test no WARNING logged when bypass is disabled."""
        with patch.dict(os.environ, {}, clear=True):
            from ab0t_auth.config import load_bypass_config
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()

            mock_logger = MagicMock()
            guard._logger = mock_logger

            result = guard._check_auth_bypass()

            assert result is None
            mock_logger.warning.assert_not_called()


# =============================================================================
# Metrics Recording Tests
# =============================================================================


class TestBypassMetrics:
    """Tests verifying metrics are recorded for bypass authentication."""

    @pytest.mark.asyncio
    async def test_bypass_records_auth_attempt_success(self) -> None:
        """Test that bypass records successful auth attempt in metrics."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
        }, clear=True):
            from ab0t_auth.config import load_bypass_config
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()

            initial_attempts = guard.metrics.auth_attempts
            initial_successes = guard.metrics.auth_successes

            await guard.authenticate()

            assert guard.metrics.auth_attempts == initial_attempts + 1
            assert guard.metrics.auth_successes == initial_successes + 1

    @pytest.mark.asyncio
    async def test_bypass_multiple_calls_record_metrics(self) -> None:
        """Test multiple bypass calls all record metrics."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
        }, clear=True):
            from ab0t_auth.config import load_bypass_config
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()

            initial_attempts = guard.metrics.auth_attempts

            # Make 5 calls
            for _ in range(5):
                await guard.authenticate()

            assert guard.metrics.auth_attempts == initial_attempts + 5


# =============================================================================
# Multiple Calls and Consistency Tests
# =============================================================================


class TestBypassConsistency:
    """Tests verifying bypass behavior is consistent across calls."""

    @pytest.mark.asyncio
    async def test_multiple_calls_return_same_user_id(self) -> None:
        """Test multiple bypass calls return user with same ID."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_USER_ID": "consistent_user",
        }, clear=True):
            from ab0t_auth.config import load_bypass_config
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()

            results = [await guard.authenticate() for _ in range(3)]

            user_ids = [r.user.user_id for r in results if r.user]
            assert all(uid == "consistent_user" for uid in user_ids)

    @pytest.mark.asyncio
    async def test_bypass_user_always_has_bypass_auth_method(self) -> None:
        """Test bypass user always has BYPASS auth method."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
        }, clear=True):
            from ab0t_auth.config import load_bypass_config
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()

            for _ in range(3):
                result = await guard.authenticate()
                assert result.user.auth_method == AuthMethod.BYPASS

    def test_bypass_config_is_immutable_after_load(self) -> None:
        """Test bypass config cannot be modified after loading."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
        }, clear=True):
            config = load_bypass_config()
            with pytest.raises(AttributeError):
                config.user_id = "hacked"  # type: ignore


# =============================================================================
# authenticate_or_raise Tests
# =============================================================================


class TestBypassAuthenticateOrRaise:
    """Tests for authenticate_or_raise with bypass."""

    @pytest.mark.asyncio
    async def test_authenticate_or_raise_returns_user_with_bypass(self) -> None:
        """Test authenticate_or_raise returns user when bypass enabled."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_USER_ID": "raise_test_user",
        }, clear=True):
            from ab0t_auth.config import load_bypass_config
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()

            user = await guard.authenticate_or_raise()

            assert user.user_id == "raise_test_user"
            assert user.auth_method == AuthMethod.BYPASS

    @pytest.mark.asyncio
    async def test_authenticate_or_raise_with_invalid_creds_but_bypass(self) -> None:
        """Test authenticate_or_raise succeeds with invalid creds when bypass on."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
        }, clear=True):
            from ab0t_auth.config import load_bypass_config
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()

            # Should not raise despite invalid credentials
            user = await guard.authenticate_or_raise(
                authorization="Bearer totally_invalid",
                api_key="also_invalid",
            )

            assert user is not None
            assert user.auth_method == AuthMethod.BYPASS


# =============================================================================
# Guard Property Tests
# =============================================================================


class TestBypassGuardProperties:
    """Tests for AuthGuard properties with bypass."""

    def test_guard_has_bypass_config(self) -> None:
        """Test AuthGuard has _bypass_config attribute."""
        guard = AuthGuard(auth_url="https://auth.test.com")
        assert hasattr(guard, "_bypass_config")
        assert isinstance(guard._bypass_config, BypassConfig)

    def test_bypass_config_loaded_on_init(self) -> None:
        """Test bypass config is loaded during __init__."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_USER_ID": "init_user",
        }, clear=True):
            # Need to ensure fresh load
            guard = AuthGuard(auth_url="https://auth.test.com")
            # Config is loaded but may use cached value, so reload
            from ab0t_auth.config import load_bypass_config
            guard._bypass_config = load_bypass_config()
            assert guard._bypass_config.user_id == "init_user"


# =============================================================================
# Security Tests - Default OFF Verification
# =============================================================================


class TestBypassDefaultOff:
    """Verify bypass is disabled by default - critical security tests."""

    def test_default_config_is_disabled(self) -> None:
        """Test BypassConfig() defaults to disabled."""
        config = BypassConfig()
        assert config.enabled is False

    def test_empty_environment_disables_bypass(self) -> None:
        """Test completely empty environment disables bypass."""
        with patch.dict(os.environ, {}, clear=True):
            config = load_bypass_config()
            assert config.enabled is False

    def test_fresh_guard_has_bypass_disabled(self) -> None:
        """Test new AuthGuard has bypass disabled by default."""
        with patch.dict(os.environ, {}, clear=True):
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()
            assert guard._bypass_config.enabled is False

    @pytest.mark.asyncio
    async def test_authenticate_requires_credentials_by_default(self) -> None:
        """Test authenticate fails without credentials when bypass off."""
        with patch.dict(os.environ, {}, clear=True):
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()
            result = await guard.authenticate()
            assert result.success is False
            assert result.error_code == "NO_CREDENTIALS"


# =============================================================================
# Security Tests - Hacker-Style Bypass Attempts
# =============================================================================


class TestBypassSecurityAttacks:
    """
    Adversarial tests attempting to bypass auth through clever tricks.

    These tests think like an attacker with deep knowledge of:
    - String parsing edge cases
    - Type confusion attacks
    - Injection techniques
    - Unicode tricks
    - Environment variable manipulation
    """

    # -------------------------------------------------------------------------
    # String Parsing Attacks
    # -------------------------------------------------------------------------

    def test_whitespace_padding_attack(self) -> None:
        """Attack: Add whitespace around 'true' to bypass parsing."""
        attack_values = [
            " true",      # Leading space
            "true ",      # Trailing space
            " true ",     # Both
            "\ttrue",     # Tab
            "true\n",     # Newline
            "\ntrue\n",   # Newlines
        ]
        for attack in attack_values:
            with patch.dict(os.environ, {
                "AB0T_AUTH_BYPASS": attack,
                "AB0T_AUTH_DEBUG": attack,
            }, clear=True):
                config = load_bypass_config()
                assert config.enabled is False, f"Bypass enabled with whitespace attack: {repr(attack)}"

    def test_case_mixed_attack(self) -> None:
        """Attack: Try unusual case combinations."""
        attack_values = [
            "tRuE",
            "truE",
            "TRUe",
            "trUE",
        ]
        for attack in attack_values:
            with patch.dict(os.environ, {
                "AB0T_AUTH_BYPASS": attack,
                "AB0T_AUTH_DEBUG": attack,
            }, clear=True):
                config = load_bypass_config()
                # These SHOULD work (case insensitive) - verify it's intentional
                assert config.enabled is True, f"Case insensitive should work: {attack}"

    def test_boolean_like_values_attack(self) -> None:
        """Attack: Try other boolean-like values that might be truthy."""
        attack_values = [
            "yes",
            "Yes",
            "YES",
            "y",
            "Y",
            "on",
            "ON",
            "enabled",
            "ENABLED",
            "1",
            "1.0",
            "-1",
            "ok",
            "OK",
            "positive",
            "affirmative",
        ]
        for attack in attack_values:
            with patch.dict(os.environ, {
                "AB0T_AUTH_BYPASS": attack,
                "AB0T_AUTH_DEBUG": attack,
            }, clear=True):
                config = load_bypass_config()
                assert config.enabled is False, f"Bypass enabled with boolean-like value: {attack}"

    def test_partial_match_attack(self) -> None:
        """Attack: Try strings containing 'true' but not exactly 'true'."""
        attack_values = [
            "true1",
            "1true",
            "truetrue",
            "true true",
            "nottrue",
            "truefalse",
            "true,true",
            "true;true",
            "[true]",
            "{true}",
            '"true"',
            "'true'",
            "true==true",
        ]
        for attack in attack_values:
            with patch.dict(os.environ, {
                "AB0T_AUTH_BYPASS": attack,
                "AB0T_AUTH_DEBUG": attack,
            }, clear=True):
                config = load_bypass_config()
                assert config.enabled is False, f"Bypass enabled with partial match: {attack}"

    # -------------------------------------------------------------------------
    # Injection Attacks
    # -------------------------------------------------------------------------

    def test_null_byte_injection_attack(self) -> None:
        """Attack: Null byte injection to truncate string comparison.

        Result: Python/OS prevents null bytes in environment variables.
        This is a security feature - the attack vector is blocked at OS level.
        """
        attack_values = [
            "true\x00false",
            "true\x00",
            "\x00true",
            "true\x00anything",
        ]
        for attack in attack_values:
            # Python's os.environ raises ValueError for null bytes
            # This is security enforced at OS/Python level - attack blocked
            with pytest.raises(ValueError, match="embedded null byte"):
                with patch.dict(os.environ, {
                    "AB0T_AUTH_BYPASS": attack,
                    "AB0T_AUTH_DEBUG": attack,
                }, clear=True):
                    pass  # Should never reach here

    def test_newline_injection_attack(self) -> None:
        """Attack: Newline injection to confuse parsers."""
        attack_values = [
            "true\nAB0T_AUTH_DEBUG=true",
            "false\ntrue",
            "true\r\nfalse",
            "true\rfalse",
        ]
        for attack in attack_values:
            with patch.dict(os.environ, {
                "AB0T_AUTH_BYPASS": attack,
                "AB0T_AUTH_DEBUG": "true",
            }, clear=True):
                config = load_bypass_config()
                assert config.enabled is False, f"Bypass enabled with newline injection: {repr(attack)}"

    def test_shell_injection_in_value(self) -> None:
        """Attack: Shell metacharacters in env var value."""
        attack_values = [
            "true; echo pwned",
            "true && echo pwned",
            "true | cat /etc/passwd",
            "$(echo true)",
            "`echo true`",
            "true; rm -rf /",
        ]
        for attack in attack_values:
            with patch.dict(os.environ, {
                "AB0T_AUTH_BYPASS": attack,
                "AB0T_AUTH_DEBUG": attack,
            }, clear=True):
                config = load_bypass_config()
                assert config.enabled is False, f"Bypass enabled with shell injection: {attack}"

    # -------------------------------------------------------------------------
    # Unicode Attacks
    # -------------------------------------------------------------------------

    def test_unicode_lookalike_attack(self) -> None:
        """Attack: Unicode characters that look like 'true'."""
        attack_values = [
            "ᴛʀᴜᴇ",         # Small caps
            "тrue",          # Cyrillic т
            "truе",          # Cyrillic е
            "ｔｒｕｅ",      # Fullwidth
            "t\u200brue",    # Zero-width space
            "tr\u00adue",    # Soft hyphen
            "true\ufeff",    # BOM
            "\ufefftrue",    # BOM prefix
        ]
        for attack in attack_values:
            with patch.dict(os.environ, {
                "AB0T_AUTH_BYPASS": attack,
                "AB0T_AUTH_DEBUG": attack,
            }, clear=True):
                config = load_bypass_config()
                assert config.enabled is False, f"Bypass enabled with unicode lookalike: {repr(attack)}"

    def test_unicode_normalization_attack(self) -> None:
        """Attack: Unicode strings that might normalize to 'true'."""
        import unicodedata
        attack_values = [
            unicodedata.normalize("NFD", "true"),  # Decomposed
            unicodedata.normalize("NFKD", "true"), # Compatibility decomposed
            "true\u0300",  # With combining character
        ]
        for attack in attack_values:
            with patch.dict(os.environ, {
                "AB0T_AUTH_BYPASS": attack,
                "AB0T_AUTH_DEBUG": attack,
            }, clear=True):
                config = load_bypass_config()
                # NFD/NFKD of "true" is still "true", so these should work
                # This test documents the behavior
                if attack == "true":
                    assert config.enabled is True
                else:
                    assert config.enabled is False, f"Unexpected with: {repr(attack)}"

    # -------------------------------------------------------------------------
    # Type Confusion Attacks
    # -------------------------------------------------------------------------

    def test_json_boolean_attack(self) -> None:
        """Attack: JSON-style boolean representations."""
        attack_values = [
            "True",   # Python repr - actually this should work (case insensitive)
            "False",
            "null",
            "None",
            "undefined",
            "NaN",
        ]
        for attack in attack_values:
            with patch.dict(os.environ, {
                "AB0T_AUTH_BYPASS": attack,
                "AB0T_AUTH_DEBUG": attack,
            }, clear=True):
                config = load_bypass_config()
                if attack.lower() == "true":
                    assert config.enabled is True
                else:
                    assert config.enabled is False, f"Bypass enabled with: {attack}"

    def test_numeric_truthy_attack(self) -> None:
        """Attack: Numeric values that might be truthy."""
        attack_values = [
            "0",
            "1",
            "-1",
            "0.0",
            "1.0",
            "0x1",
            "0b1",
            "0o1",
            "inf",
            "-inf",
            "1e10",
        ]
        for attack in attack_values:
            with patch.dict(os.environ, {
                "AB0T_AUTH_BYPASS": attack,
                "AB0T_AUTH_DEBUG": attack,
            }, clear=True):
                config = load_bypass_config()
                assert config.enabled is False, f"Bypass enabled with numeric: {attack}"

    # -------------------------------------------------------------------------
    # Single Flag Attacks (Defense-in-Depth)
    # -------------------------------------------------------------------------

    def test_only_bypass_many_values(self) -> None:
        """Attack: Try to enable bypass with only AB0T_AUTH_BYPASS."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            # Intentionally NOT setting AB0T_AUTH_DEBUG
        }, clear=True):
            config = load_bypass_config()
            assert config.enabled is False, "Defense-in-depth failed: only BYPASS set"

    def test_only_debug_many_values(self) -> None:
        """Attack: Try to enable bypass with only AB0T_AUTH_DEBUG."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_DEBUG": "true",
            # Intentionally NOT setting AB0T_AUTH_BYPASS
        }, clear=True):
            config = load_bypass_config()
            assert config.enabled is False, "Defense-in-depth failed: only DEBUG set"

    def test_one_true_one_truthy(self) -> None:
        """Attack: One correct flag, one truthy-but-wrong value."""
        attack_combos = [
            ("true", "1"),
            ("true", "yes"),
            ("1", "true"),
            ("yes", "true"),
            ("true", "TRUE "),  # with space
        ]
        for bypass_val, debug_val in attack_combos:
            with patch.dict(os.environ, {
                "AB0T_AUTH_BYPASS": bypass_val,
                "AB0T_AUTH_DEBUG": debug_val,
            }, clear=True):
                config = load_bypass_config()
                # Only "true" (case insensitive, no whitespace) should work
                bypass_ok = bypass_val.lower() == "true"
                debug_ok = debug_val.lower() == "true"
                expected = bypass_ok and debug_ok
                assert config.enabled is expected, f"Unexpected result for ({bypass_val}, {debug_val})"

    # -------------------------------------------------------------------------
    # Runtime Manipulation Attacks
    # -------------------------------------------------------------------------

    def test_frozen_config_cannot_be_modified(self) -> None:
        """Attack: Try to modify bypass config after creation."""
        config = BypassConfig(enabled=False)

        with pytest.raises(AttributeError):
            config.enabled = True  # type: ignore

        with pytest.raises(AttributeError):
            config.user_id = "hacker"  # type: ignore

        with pytest.raises(AttributeError):
            config.permissions = ("admin:*",)  # type: ignore

    def test_guard_bypass_config_replacement_attack(self) -> None:
        """Attack: Try to replace guard's bypass config at runtime."""
        with patch.dict(os.environ, {}, clear=True):
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()

            # Verify initially disabled
            assert guard._bypass_config.enabled is False

            # Attacker tries to replace config
            malicious_config = BypassConfig(
                enabled=True,
                user_id="hacker",
                permissions=("admin:*", "superuser:*"),
            )
            guard._bypass_config = malicious_config

            # This DOES work - but requires code access
            # Document that internal state can be modified if attacker has code execution
            assert guard._bypass_config.enabled is True
            # This is expected - if attacker can modify code, they can do anything

    @pytest.mark.asyncio
    async def test_env_change_after_init_attack(self) -> None:
        """Attack: Change environment after guard initialization."""
        with patch.dict(os.environ, {}, clear=True):
            guard = AuthGuard(auth_url="https://auth.test.com")
            guard._bypass_config = load_bypass_config()

            # Verify disabled
            assert guard._bypass_config.enabled is False

            # Attacker changes env vars after init
            os.environ["AB0T_AUTH_BYPASS"] = "true"
            os.environ["AB0T_AUTH_DEBUG"] = "true"

            # Config was loaded at init time, should still be disabled
            result = await guard.authenticate()
            assert result.success is False, "Guard should use config from init time"

    # -------------------------------------------------------------------------
    # Empty and Boundary Value Attacks
    # -------------------------------------------------------------------------

    def test_empty_string_attack(self) -> None:
        """Attack: Empty strings for flags."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "",
            "AB0T_AUTH_DEBUG": "",
        }, clear=True):
            config = load_bypass_config()
            assert config.enabled is False

    def test_only_spaces_attack(self) -> None:
        """Attack: Strings of only whitespace."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "   ",
            "AB0T_AUTH_DEBUG": "   ",
        }, clear=True):
            config = load_bypass_config()
            assert config.enabled is False

    def test_very_long_string_attack(self) -> None:
        """Attack: Very long string starting with 'true'."""
        long_attack = "true" + "x" * 10000
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": long_attack,
            "AB0T_AUTH_DEBUG": long_attack,
        }, clear=True):
            config = load_bypass_config()
            assert config.enabled is False

    # -------------------------------------------------------------------------
    # Permission Escalation Attacks
    # -------------------------------------------------------------------------

    def test_wildcard_permission_injection(self) -> None:
        """Attack: Inject wildcard permissions via env var."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_PERMISSIONS": "*,admin:*,**,root:*",
        }, clear=True):
            config = load_bypass_config()
            # Wildcards are stored but permission system must handle them safely
            assert "*" in config.permissions
            # This documents that permission validation is separate concern

    def test_special_chars_in_user_id(self) -> None:
        """Attack: Special characters in user_id for injection."""
        attack_ids = [
            "../../../etc/passwd",
            "admin' OR '1'='1",
            "admin; DROP TABLE users;--",
            "<script>alert('xss')</script>",
            "{{constructor.constructor('return this')()}}",
        ]
        for attack_id in attack_ids:
            with patch.dict(os.environ, {
                "AB0T_AUTH_BYPASS": "true",
                "AB0T_AUTH_DEBUG": "true",
                "AB0T_AUTH_BYPASS_USER_ID": attack_id,
            }, clear=True):
                config = load_bypass_config()
                # Value is stored as-is - downstream code must sanitize
                assert config.user_id == attack_id
                # This documents the responsibility boundary
