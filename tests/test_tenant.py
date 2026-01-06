"""
Tests for ab0t_auth.tenant module.
"""

import pytest

from ab0t_auth.core import AuthenticatedUser, AuthMethod, TokenType, TokenClaims
from ab0t_auth.tenant import (
    TenantContext,
    TenantConfig,
    TenantExtractionStrategy,
    Organization,
    OrgRelationship,
    TenantError,
    TenantRequiredError,
    TenantAccessDeniedError,
    OrgAccessDeniedError,
    OrgNotFoundError,
    extract_tenant_from_user,
    extract_org_path_from_claims,
    validate_tenant_access,
    validate_org_access,
    build_tenant_context,
    validate_tenant_context,
    check_tenant_permission,
    check_org_permission,
    build_tenant_scoped_permission,
    build_org_scoped_permission,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def test_user():
    """Create test user with tenant info."""
    claims = TokenClaims(
        sub="user_123",
        exp=9999999999,
        raw={
            "tenant_id": "tenant_789",
            "org_id": "org_456",
            "org_path": ["root", "child", "grandchild"],
        },
    )
    return AuthenticatedUser(
        user_id="user_123",
        email="test@example.com",
        org_id="org_456",
        permissions=("users:read", "users:write", "reports:read"),
        roles=("user", "editor"),
        auth_method=AuthMethod.JWT,
        token_type=TokenType.BEARER,
        claims=claims,
    )


@pytest.fixture
def admin_user():
    """Create admin user with cross-tenant access."""
    claims = TokenClaims(
        sub="admin_001",
        exp=9999999999,
        raw={
            "tenant_id": "tenant_admin",
            "org_id": "org_admin",
        },
    )
    return AuthenticatedUser(
        user_id="admin_001",
        email="admin@example.com",
        org_id="org_admin",
        permissions=("admin:cross_tenant", "admin:access", "users:read"),
        roles=("admin",),
        auth_method=AuthMethod.JWT,
        token_type=TokenType.BEARER,
        claims=claims,
    )


@pytest.fixture
def simple_user():
    """Create simple user without claims."""
    return AuthenticatedUser(
        user_id="user_simple",
        email="simple@example.com",
        org_id="org_simple",
        permissions=("users:read",),
        roles=("user",),
        auth_method=AuthMethod.JWT,
        token_type=TokenType.BEARER,
    )


@pytest.fixture
def default_config():
    """Create default tenant config."""
    return TenantConfig()


@pytest.fixture
def strict_config():
    """Create strict tenant isolation config."""
    return TenantConfig(
        enforce_tenant_isolation=True,
        enforce_org_isolation=True,
        allow_cross_tenant_admin=False,
    )


@pytest.fixture
def relaxed_config():
    """Create relaxed config with no isolation."""
    return TenantConfig(
        enforce_tenant_isolation=False,
        enforce_org_isolation=False,
    )


# =============================================================================
# TenantContext Tests
# =============================================================================


class TestTenantContext:
    """Tests for TenantContext dataclass."""

    def test_create_basic_context(self):
        """Test creating basic tenant context."""
        ctx = TenantContext(tenant_id="tenant_123")

        assert ctx.tenant_id == "tenant_123"
        assert ctx.org_id is None
        assert ctx.org_path == ()
        assert ctx.user is None
        assert ctx.extraction_strategy == TenantExtractionStrategy.TOKEN
        assert ctx.is_validated is False
        assert ctx.is_cross_tenant is False

    def test_create_full_context(self, test_user):
        """Test creating full tenant context."""
        ctx = TenantContext(
            tenant_id="tenant_789",
            org_id="org_456",
            org_path=("root", "child"),
            user=test_user,
            extraction_strategy=TenantExtractionStrategy.HEADER,
            is_validated=True,
            is_cross_tenant=False,
        )

        assert ctx.tenant_id == "tenant_789"
        assert ctx.org_id == "org_456"
        assert ctx.org_path == ("root", "child")
        assert ctx.user == test_user
        assert ctx.is_validated is True

    def test_context_is_immutable(self):
        """Test that tenant context is immutable."""
        ctx = TenantContext(tenant_id="tenant_123")

        with pytest.raises(AttributeError):
            ctx.tenant_id = "other"

    def test_is_same_tenant(self):
        """Test is_same_tenant method."""
        ctx = TenantContext(tenant_id="tenant_123")

        assert ctx.is_same_tenant("tenant_123") is True
        assert ctx.is_same_tenant("other") is False

    def test_is_same_org(self):
        """Test is_same_org method."""
        ctx = TenantContext(tenant_id="t", org_id="org_123")

        assert ctx.is_same_org("org_123") is True
        assert ctx.is_same_org("other") is False

    def test_is_in_org_hierarchy(self):
        """Test is_in_org_hierarchy method."""
        ctx = TenantContext(
            tenant_id="t",
            org_id="current",
            org_path=("root", "parent"),
        )

        assert ctx.is_in_org_hierarchy("current") is True
        assert ctx.is_in_org_hierarchy("root") is True
        assert ctx.is_in_org_hierarchy("parent") is True
        assert ctx.is_in_org_hierarchy("other") is False


# =============================================================================
# TenantConfig Tests
# =============================================================================


class TestTenantConfig:
    """Tests for TenantConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = TenantConfig()

        assert config.enforce_tenant_isolation is True
        assert config.enforce_org_isolation is False
        assert config.allow_cross_tenant_admin is True
        assert config.cross_tenant_permission == "admin:cross_tenant"
        assert config.enable_org_hierarchy is True

    def test_custom_config(self):
        """Test custom configuration."""
        config = TenantConfig(
            enforce_tenant_isolation=False,
            enforce_org_isolation=True,
            allow_cross_tenant_admin=False,
            cross_tenant_permission="super:admin",
            enable_org_hierarchy=False,
        )

        assert config.enforce_tenant_isolation is False
        assert config.enforce_org_isolation is True
        assert config.allow_cross_tenant_admin is False
        assert config.cross_tenant_permission == "super:admin"
        assert config.enable_org_hierarchy is False


# =============================================================================
# Organization Tests
# =============================================================================


class TestOrganization:
    """Tests for Organization dataclass."""

    def test_create_organization(self):
        """Test creating organization."""
        org = Organization(
            org_id="org_123",
            name="Test Org",
            tenant_id="tenant_456",
        )

        assert org.org_id == "org_123"
        assert org.name == "Test Org"
        assert org.tenant_id == "tenant_456"
        assert org.parent_id is None
        assert org.path == ()

    def test_create_nested_organization(self):
        """Test creating nested organization."""
        org = Organization(
            org_id="org_child",
            name="Child Org",
            tenant_id="tenant_456",
            parent_id="org_parent",
            path=("root", "parent"),
        )

        assert org.parent_id == "org_parent"
        assert org.path == ("root", "parent")

    def test_is_root(self):
        """Test is_root method."""
        root_org = Organization(org_id="root")
        child_org = Organization(org_id="child", parent_id="root")

        assert root_org.is_root() is True
        assert child_org.is_root() is False


# =============================================================================
# Extraction Function Tests
# =============================================================================


class TestExtractTenantFromUser:
    """Tests for extract_tenant_from_user function."""

    def test_extract_from_claims(self, test_user):
        """Test extracting tenant from user claims."""
        tenant_id, org_id = extract_tenant_from_user(test_user)

        assert tenant_id == "tenant_789"
        assert org_id == "org_456"

    def test_extract_fallback_to_org_id(self, simple_user):
        """Test fallback to org_id when no tenant_id in claims."""
        tenant_id, org_id = extract_tenant_from_user(simple_user)

        # Falls back to org_id as tenant_id
        assert tenant_id == "org_simple"
        assert org_id == "org_simple"


class TestExtractOrgPathFromClaims:
    """Tests for extract_org_path_from_claims function."""

    def test_extract_path_from_list(self, test_user):
        """Test extracting org path from list in claims."""
        path = extract_org_path_from_claims(test_user)
        assert path == ("root", "child", "grandchild")

    def test_extract_empty_path_when_no_claims(self, simple_user):
        """Test returning empty tuple when no claims."""
        path = extract_org_path_from_claims(simple_user)
        assert path == ()

    def test_extract_path_from_string(self):
        """Test extracting org path from slash-separated string."""
        claims = TokenClaims(
            sub="user",
            exp=9999999999,
            raw={"org_path": "root/child/grandchild"},
        )
        user = AuthenticatedUser(
            user_id="user",
            email="test@example.com",
            permissions=(),
            roles=(),
            auth_method=AuthMethod.JWT,
            token_type=TokenType.BEARER,
            claims=claims,
        )

        path = extract_org_path_from_claims(user)
        assert path == ("root", "child", "grandchild")


# =============================================================================
# Validation Function Tests
# =============================================================================


class TestValidateTenantAccess:
    """Tests for validate_tenant_access function."""

    def test_access_own_tenant(self, test_user, default_config):
        """Test accessing own tenant."""
        allowed, reason = validate_tenant_access(
            user=test_user,
            requested_tenant_id="tenant_789",
            config=default_config,
        )
        assert allowed is True
        assert reason is None

    def test_deny_other_tenant_without_cross_tenant(self, test_user, default_config):
        """Test denying access to other tenant."""
        allowed, reason = validate_tenant_access(
            user=test_user,
            requested_tenant_id="other_tenant",
            config=default_config,
        )
        assert allowed is False
        assert "other_tenant" in reason

    def test_allow_cross_tenant_admin(self, admin_user, default_config):
        """Test allowing cross-tenant admin access."""
        allowed, reason = validate_tenant_access(
            user=admin_user,
            requested_tenant_id="other_tenant",
            config=default_config,
        )
        assert allowed is True

    def test_deny_cross_tenant_when_disabled(self, admin_user, strict_config):
        """Test denying cross-tenant even for admin when disabled."""
        allowed, reason = validate_tenant_access(
            user=admin_user,
            requested_tenant_id="other_tenant",
            config=strict_config,
        )
        assert allowed is False

    def test_allow_when_isolation_disabled(self, test_user, relaxed_config):
        """Test allowing any access when isolation disabled."""
        allowed, reason = validate_tenant_access(
            user=test_user,
            requested_tenant_id="any_tenant",
            config=relaxed_config,
        )
        assert allowed is True


class TestValidateOrgAccess:
    """Tests for validate_org_access function."""

    def test_access_own_org(self, test_user, default_config):
        """Test accessing own org."""
        allowed, reason = validate_org_access(
            user=test_user,
            requested_org_id="org_456",
            config=default_config,
        )
        assert allowed is True

    def test_allow_any_org_when_isolation_disabled(self, test_user, default_config):
        """Test allowing any org when isolation disabled."""
        # default_config has enforce_org_isolation=False
        allowed, reason = validate_org_access(
            user=test_user,
            requested_org_id="any_org",
            config=default_config,
        )
        assert allowed is True

    def test_deny_other_org_when_strict(self, test_user, strict_config):
        """Test denying access to other org with strict config."""
        allowed, reason = validate_org_access(
            user=test_user,
            requested_org_id="other_org",
            config=strict_config,
        )
        assert allowed is False

    def test_allow_ancestor_org_in_hierarchy(self, test_user, strict_config):
        """Test allowing access to ancestor org in hierarchy."""
        # test_user has org_path ["root", "child", "grandchild"]
        allowed, reason = validate_org_access(
            user=test_user,
            requested_org_id="root",
            config=strict_config,
        )
        assert allowed is True


# =============================================================================
# Build and Validate Context Tests
# =============================================================================


class TestBuildTenantContext:
    """Tests for build_tenant_context function."""

    def test_build_from_user(self, test_user, default_config):
        """Test building context from user."""
        ctx = build_tenant_context(
            user=test_user,
            config=default_config,
        )

        assert ctx.tenant_id == "tenant_789"
        assert ctx.org_id == "org_456"
        assert ctx.user == test_user
        assert ctx.is_validated is False

    def test_build_with_requested_tenant(self, test_user, default_config):
        """Test building context with explicit tenant."""
        ctx = build_tenant_context(
            user=test_user,
            requested_tenant_id="tenant_789",
            config=default_config,
        )

        assert ctx.tenant_id == "tenant_789"
        assert ctx.requested_tenant_id == "tenant_789"
        assert ctx.is_cross_tenant is False

    def test_build_cross_tenant_context(self, admin_user, default_config):
        """Test building cross-tenant context."""
        ctx = build_tenant_context(
            user=admin_user,
            requested_tenant_id="other_tenant",
            config=default_config,
        )

        assert ctx.tenant_id == "other_tenant"
        assert ctx.is_cross_tenant is True


class TestValidateTenantContext:
    """Tests for validate_tenant_context function."""

    def test_validate_own_tenant(self, test_user, default_config):
        """Test validating access to own tenant."""
        ctx = build_tenant_context(
            user=test_user,
            requested_tenant_id="tenant_789",
            config=default_config,
        )

        validated = validate_tenant_context(ctx, default_config)

        assert validated.is_validated is True
        assert validated.tenant_id == "tenant_789"

    def test_validate_raises_on_invalid_tenant(self, test_user, default_config):
        """Test raising error on invalid tenant access."""
        ctx = build_tenant_context(
            user=test_user,
            requested_tenant_id="other_tenant",
            config=default_config,
        )

        with pytest.raises(TenantAccessDeniedError):
            validate_tenant_context(ctx, default_config)

    def test_validate_allows_cross_tenant_admin(self, admin_user, default_config):
        """Test validating cross-tenant admin access."""
        ctx = build_tenant_context(
            user=admin_user,
            requested_tenant_id="other_tenant",
            config=default_config,
        )

        validated = validate_tenant_context(ctx, default_config)

        assert validated.is_validated is True
        assert validated.is_cross_tenant is True


# =============================================================================
# Permission Function Tests
# =============================================================================


class TestCheckTenantPermission:
    """Tests for check_tenant_permission function."""

    def test_has_tenant_permission(self, test_user, default_config):
        """Test checking permission within tenant."""
        result = check_tenant_permission(
            user=test_user,
            permission="users:read",
            tenant_id="tenant_789",
            config=default_config,
        )
        assert result is True

    def test_lacks_permission(self, test_user, default_config):
        """Test lacking permission."""
        result = check_tenant_permission(
            user=test_user,
            permission="admin:delete",
            tenant_id="tenant_789",
            config=default_config,
        )
        assert result is False

    def test_deny_permission_for_other_tenant(self, test_user, default_config):
        """Test denying permission for other tenant."""
        result = check_tenant_permission(
            user=test_user,
            permission="users:read",
            tenant_id="other_tenant",
            config=default_config,
        )
        assert result is False


class TestCheckOrgPermission:
    """Tests for check_org_permission function."""

    def test_has_org_permission(self, test_user, default_config):
        """Test checking permission within org."""
        result = check_org_permission(
            user=test_user,
            permission="users:read",
            org_id="org_456",
            config=default_config,
        )
        assert result is True

    def test_lacks_permission(self, test_user, default_config):
        """Test lacking permission."""
        result = check_org_permission(
            user=test_user,
            permission="admin:delete",
            org_id="org_456",
            config=default_config,
        )
        assert result is False


class TestBuildScopedPermissions:
    """Tests for permission string builders."""

    def test_build_tenant_scoped_permission(self):
        """Test building tenant-scoped permission."""
        perm = build_tenant_scoped_permission("users:read", "acme")
        assert perm == "tenant:acme:users:read"

    def test_build_org_scoped_permission(self):
        """Test building org-scoped permission."""
        perm = build_org_scoped_permission("users:read", "engineering")
        assert perm == "org:engineering:users:read"


# =============================================================================
# Error Tests
# =============================================================================


class TestTenantErrors:
    """Tests for tenant error types."""

    def test_tenant_error_base(self):
        """Test TenantError base class."""
        error = TenantError("Test error")
        assert str(error) == "Test error"
        assert error.status_code == 403

    def test_tenant_required_error(self):
        """Test TenantRequiredError."""
        error = TenantRequiredError("Tenant required")
        assert "Tenant required" in str(error)
        assert error.status_code == 400

    def test_tenant_access_denied_error(self):
        """Test TenantAccessDeniedError."""
        error = TenantAccessDeniedError("Access denied to tenant_123")
        assert "tenant_123" in str(error)
        assert error.status_code == 403

    def test_org_access_denied_error(self):
        """Test OrgAccessDeniedError."""
        error = OrgAccessDeniedError("Access denied to org_456")
        assert "org_456" in str(error)
        assert error.status_code == 403

    def test_org_not_found_error(self):
        """Test OrgNotFoundError."""
        error = OrgNotFoundError("Org org_missing not found")
        assert "org_missing" in str(error)
        assert error.status_code == 404
