"""
Tests for ab0t_auth.permissions module.
"""

import pytest

from ab0t_auth.core import AuthenticatedUser, AuthMethod, TokenType
from ab0t_auth.errors import PermissionDeniedError
from ab0t_auth.permissions import (
    check_all_permissions,
    check_any_permission,
    check_any_pattern,
    check_permission,
    check_permission_pattern,
    check_role,
    filter_permissions,
    get_permission_categories,
    has_all_permissions,
    has_any_permission,
    has_permission,
    has_permission_pattern,
    has_role,
    require_all_permissions_or_raise,
    require_any_permission_or_raise,
    require_permission_or_raise,
)


class TestCheckPermission:
    """Tests for check_permission function."""

    def test_has_permission(self, test_user: AuthenticatedUser):
        """Test checking existing permission."""
        result = check_permission(test_user, "users:read")

        assert result.allowed
        assert result.permission == "users:read"

    def test_lacks_permission(self, test_user: AuthenticatedUser):
        """Test checking missing permission."""
        result = check_permission(test_user, "admin:access")

        assert not result.allowed
        assert result.permission == "admin:access"
        assert "lacks permission" in result.reason.lower()


class TestCheckAnyPermission:
    """Tests for check_any_permission function."""

    def test_has_one_permission(self, test_user: AuthenticatedUser):
        """Test when user has one of the permissions."""
        result = check_any_permission(test_user, "users:read", "admin:access")

        assert result.allowed

    def test_has_none_permissions(self, test_user: AuthenticatedUser):
        """Test when user has none of the permissions."""
        result = check_any_permission(test_user, "admin:access", "billing:read")

        assert not result.allowed


class TestCheckAllPermissions:
    """Tests for check_all_permissions function."""

    def test_has_all_permissions(self, test_user: AuthenticatedUser):
        """Test when user has all permissions."""
        result = check_all_permissions(test_user, "users:read", "users:write")

        assert result.allowed

    def test_missing_one_permission(self, test_user: AuthenticatedUser):
        """Test when user missing one permission."""
        result = check_all_permissions(test_user, "users:read", "admin:access")

        assert not result.allowed


class TestCheckPermissionPattern:
    """Tests for check_permission_pattern function."""

    def test_matches_pattern(self, test_user: AuthenticatedUser):
        """Test pattern matching existing permission."""
        result = check_permission_pattern(test_user, "users:*")

        assert result.allowed
        # Should match users:read or users:write
        assert result.permission.startswith("users:")

    def test_no_match(self, test_user: AuthenticatedUser):
        """Test pattern with no match."""
        result = check_permission_pattern(test_user, "admin:*")

        assert not result.allowed


class TestCheckAnyPattern:
    """Tests for check_any_pattern function."""

    def test_matches_one_pattern(self, test_user: AuthenticatedUser):
        """Test when one pattern matches."""
        result = check_any_pattern(test_user, "admin:*", "users:*")

        assert result.allowed

    def test_no_patterns_match(self, test_user: AuthenticatedUser):
        """Test when no patterns match."""
        result = check_any_pattern(test_user, "admin:*", "billing:*")

        assert not result.allowed


class TestCheckRole:
    """Tests for check_role function."""

    def test_has_role(self, test_user: AuthenticatedUser):
        """Test checking existing role."""
        result = check_role(test_user, "user")

        assert result.allowed

    def test_lacks_role(self, test_user: AuthenticatedUser):
        """Test checking missing role."""
        result = check_role(test_user, "admin")

        assert not result.allowed


class TestFilterPermissions:
    """Tests for filter_permissions function."""

    def test_filter_by_pattern(self, test_user: AuthenticatedUser):
        """Test filtering permissions by pattern."""
        result = filter_permissions(test_user, "users:*")

        assert "users:read" in result
        assert "users:write" in result
        assert "reports:read" not in result

    def test_filter_no_match(self, test_user: AuthenticatedUser):
        """Test filtering with no matches."""
        result = filter_permissions(test_user, "admin:*")

        assert len(result) == 0


class TestGetPermissionCategories:
    """Tests for get_permission_categories function."""

    def test_extract_categories(self, test_user: AuthenticatedUser):
        """Test extracting permission categories."""
        result = get_permission_categories(test_user)

        assert "users" in result
        assert "reports" in result

    def test_sorted_categories(self):
        """Test categories are sorted."""
        user = AuthenticatedUser(
            user_id="test",
            permissions=("z:read", "a:write", "m:delete"),
        )
        result = get_permission_categories(user)

        assert result == ("a", "m", "z")


class TestRequirePermissionOrRaise:
    """Tests for require_permission_or_raise function."""

    def test_has_permission_no_raise(self, test_user: AuthenticatedUser):
        """Test no exception when has permission."""
        require_permission_or_raise(test_user, "users:read")  # Should not raise

    def test_lacks_permission_raises(self, test_user: AuthenticatedUser):
        """Test raises when lacks permission."""
        with pytest.raises(PermissionDeniedError) as exc_info:
            require_permission_or_raise(test_user, "admin:access")

        assert exc_info.value.details["required"] == "admin:access"


class TestRequireAnyPermissionOrRaise:
    """Tests for require_any_permission_or_raise function."""

    def test_has_one_no_raise(self, test_user: AuthenticatedUser):
        """Test no exception when has one permission."""
        require_any_permission_or_raise(test_user, "users:read", "admin:access")

    def test_has_none_raises(self, test_user: AuthenticatedUser):
        """Test raises when has no permissions."""
        with pytest.raises(PermissionDeniedError):
            require_any_permission_or_raise(test_user, "admin:access", "billing:read")


class TestRequireAllPermissionsOrRaise:
    """Tests for require_all_permissions_or_raise function."""

    def test_has_all_no_raise(self, test_user: AuthenticatedUser):
        """Test no exception when has all permissions."""
        require_all_permissions_or_raise(test_user, "users:read", "users:write")

    def test_missing_one_raises(self, test_user: AuthenticatedUser):
        """Test raises when missing one permission."""
        with pytest.raises(PermissionDeniedError):
            require_all_permissions_or_raise(test_user, "users:read", "admin:access")


class TestPredicateBuilders:
    """Tests for predicate builder functions."""

    def test_has_permission_predicate(self, test_user: AuthenticatedUser):
        """Test has_permission predicate."""
        predicate = has_permission("users:read")

        assert predicate(test_user)
        assert not has_permission("admin:access")(test_user)

    def test_has_any_permission_predicate(self, test_user: AuthenticatedUser):
        """Test has_any_permission predicate."""
        predicate = has_any_permission("users:read", "admin:access")

        assert predicate(test_user)

    def test_has_all_permissions_predicate(self, test_user: AuthenticatedUser):
        """Test has_all_permissions predicate."""
        assert has_all_permissions("users:read", "users:write")(test_user)
        assert not has_all_permissions("users:read", "admin:access")(test_user)

    def test_has_permission_pattern_predicate(self, test_user: AuthenticatedUser):
        """Test has_permission_pattern predicate."""
        assert has_permission_pattern("users:*")(test_user)
        assert not has_permission_pattern("admin:*")(test_user)

    def test_has_role_predicate(self, test_user: AuthenticatedUser):
        """Test has_role predicate."""
        assert has_role("user")(test_user)
        assert not has_role("admin")(test_user)
