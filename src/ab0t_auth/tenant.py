"""
Multi-tenancy support for Ab0t Auth.

Ab0t is multi-tenant by design:
- Each user belongs to a tenant (company)
- Tenants can have organizations
- Organizations can be nested (hierarchical)

This module provides:
- Tenant context extraction and validation
- Organization hierarchy support
- Tenant-scoped permission checking
- Tenant isolation enforcement

Usage:
    from ab0t_auth.tenant import (
        TenantContext,
        require_tenant,
        require_org,
        TenantMiddleware,
    )

    # Require specific tenant
    @app.get("/tenant/{tenant_id}/data")
    async def get_data(
        tenant_id: str,
        ctx: TenantContext = Depends(require_tenant(auth))
    ):
        # ctx.tenant_id is validated against user's token
        return {"tenant": ctx.tenant_id}
"""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Sequence

from ab0t_auth.core import AuthenticatedUser, AuthConfig
from ab0t_auth.errors import AuthError, PermissionDeniedError


# =============================================================================
# Tenant Types
# =============================================================================


class TenantExtractionStrategy(str, Enum):
    """How to extract tenant ID from request."""

    TOKEN = "token"           # From JWT claims (org_id or tenant_id)
    HEADER = "header"         # From X-Tenant-ID header
    PATH = "path"             # From URL path parameter
    SUBDOMAIN = "subdomain"   # From request host subdomain
    QUERY = "query"           # From query parameter


class OrgRelationship(str, Enum):
    """Relationship between organizations."""

    SELF = "self"             # Same organization
    PARENT = "parent"         # Parent organization
    CHILD = "child"           # Child organization
    SIBLING = "sibling"       # Same parent
    ANCESTOR = "ancestor"     # Any ancestor
    DESCENDANT = "descendant" # Any descendant
    NONE = "none"             # No relationship


@dataclass(frozen=True, slots=True)
class Organization:
    """
    Organization within a tenant.

    Supports hierarchical organization structures.
    """

    org_id: str
    name: str | None = None
    parent_id: str | None = None
    tenant_id: str | None = None
    path: tuple[str, ...] = field(default_factory=tuple)  # Ancestry path
    depth: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_root(self) -> bool:
        """Check if this is a root organization."""
        return self.parent_id is None

    def is_ancestor_of(self, org_id: str) -> bool:
        """Check if this org is an ancestor of another."""
        return self.org_id in self.path

    def is_descendant_of(self, org_id: str) -> bool:
        """Check if this org is a descendant of another."""
        return org_id in self.path


@dataclass(frozen=True, slots=True)
class TenantContext:
    """
    Multi-tenant context for a request.

    Carries tenant and organization information through the request lifecycle.
    Immutable to prevent accidental mutations.
    """

    tenant_id: str
    org_id: str | None = None
    org_path: tuple[str, ...] = field(default_factory=tuple)  # Full org hierarchy
    user: AuthenticatedUser | None = None

    # Extraction metadata
    extraction_strategy: TenantExtractionStrategy = TenantExtractionStrategy.TOKEN
    requested_tenant_id: str | None = None  # What was requested (may differ from resolved)
    requested_org_id: str | None = None

    # Validation state
    is_validated: bool = False
    is_cross_tenant: bool = False  # User accessing different tenant (admin)

    def is_same_tenant(self, other_tenant_id: str) -> bool:
        """Check if context matches a tenant ID."""
        return self.tenant_id == other_tenant_id

    def is_same_org(self, other_org_id: str) -> bool:
        """Check if context matches an organization ID."""
        return self.org_id == other_org_id

    def is_in_org_hierarchy(self, org_id: str) -> bool:
        """Check if org_id is in the current org hierarchy."""
        return org_id in self.org_path or org_id == self.org_id

    def can_access_org(self, target_org_id: str, *, allow_ancestors: bool = True, allow_descendants: bool = True) -> bool:
        """
        Check if user can access target organization.

        By default allows access to ancestors and descendants in hierarchy.
        """
        if self.org_id == target_org_id:
            return True

        if allow_ancestors and target_org_id in self.org_path:
            return True

        # For descendants, we'd need the target's path - this is a simplified check
        # In practice, you'd query the org hierarchy
        if allow_descendants and self.org_id and self.org_path:
            # If our org is in target's ancestry, target is our descendant
            # This requires knowing target's path
            pass

        return False


@dataclass(frozen=True, slots=True)
class TenantConfig:
    """
    Configuration for multi-tenant behavior.
    """

    # Extraction
    extraction_strategies: tuple[TenantExtractionStrategy, ...] = (
        TenantExtractionStrategy.TOKEN,
        TenantExtractionStrategy.HEADER,
        TenantExtractionStrategy.PATH,
    )
    tenant_header: str = "X-Tenant-ID"
    org_header: str = "X-Org-ID"
    tenant_path_param: str = "tenant_id"
    org_path_param: str = "org_id"
    tenant_query_param: str = "tenant_id"

    # Validation
    enforce_tenant_isolation: bool = True  # Require tenant_id match
    enforce_org_isolation: bool = False     # Require org_id match
    allow_cross_tenant_admin: bool = True   # Allow admins to access other tenants
    cross_tenant_permission: str = "admin:cross_tenant"

    # Organization hierarchy
    enable_org_hierarchy: bool = True
    allow_ancestor_access: bool = True      # Can access parent orgs
    allow_descendant_access: bool = True    # Can access child orgs


# =============================================================================
# Tenant Extraction Functions (Pure)
# =============================================================================


def extract_tenant_from_user(user: AuthenticatedUser) -> tuple[str | None, str | None]:
    """
    Extract tenant and org ID from authenticated user.

    Pure function - looks in user claims for tenant info.
    """
    tenant_id = None
    org_id = user.org_id

    # Check claims for tenant_id (might be separate from org_id)
    if user.claims and user.claims.raw:
        tenant_id = user.claims.raw.get("tenant_id")
        if not org_id:
            org_id = user.claims.raw.get("org_id")

    # Fall back to org_id as tenant_id if not separate
    if not tenant_id:
        tenant_id = org_id

    return tenant_id, org_id


def extract_org_path_from_claims(user: AuthenticatedUser) -> tuple[str, ...]:
    """
    Extract organization hierarchy path from user claims.

    Pure function.
    """
    if not user.claims or not user.claims.raw:
        return ()

    # Look for org_path or organization_path in claims
    path = user.claims.raw.get("org_path") or user.claims.raw.get("organization_path")

    if isinstance(path, list):
        return tuple(path)
    if isinstance(path, str):
        return tuple(path.split("/")) if "/" in path else (path,)

    return ()


def validate_tenant_access(
    user: AuthenticatedUser,
    requested_tenant_id: str,
    config: TenantConfig,
) -> tuple[bool, str | None]:
    """
    Validate user can access requested tenant.

    Pure function - returns (allowed, reason).
    """
    user_tenant_id, _ = extract_tenant_from_user(user)

    # Same tenant - always allowed
    if user_tenant_id == requested_tenant_id:
        return True, None

    # Cross-tenant access
    if not config.enforce_tenant_isolation:
        return True, None

    # Check for cross-tenant admin permission
    if config.allow_cross_tenant_admin:
        if user.has_permission(config.cross_tenant_permission):
            return True, None

    return False, f"Access denied to tenant {requested_tenant_id}"


def validate_org_access(
    user: AuthenticatedUser,
    requested_org_id: str,
    config: TenantConfig,
) -> tuple[bool, str | None]:
    """
    Validate user can access requested organization.

    Pure function - returns (allowed, reason).
    """
    _, user_org_id = extract_tenant_from_user(user)

    # Same org - always allowed
    if user_org_id == requested_org_id:
        return True, None

    # No org isolation enforced
    if not config.enforce_org_isolation:
        return True, None

    # Check hierarchy access
    if config.enable_org_hierarchy:
        org_path = extract_org_path_from_claims(user)

        # Ancestor access
        if config.allow_ancestor_access and requested_org_id in org_path:
            return True, None

        # Descendant access would require knowing the target's path
        # This is typically handled by the backend API

    return False, f"Access denied to organization {requested_org_id}"


# =============================================================================
# Tenant Context Builder (Pure)
# =============================================================================


def build_tenant_context(
    user: AuthenticatedUser,
    *,
    requested_tenant_id: str | None = None,
    requested_org_id: str | None = None,
    extraction_strategy: TenantExtractionStrategy = TenantExtractionStrategy.TOKEN,
    config: TenantConfig | None = None,
) -> TenantContext:
    """
    Build tenant context from user and request info.

    Pure function - constructs immutable context.
    """
    cfg = config or TenantConfig()

    # Extract from user
    user_tenant_id, user_org_id = extract_tenant_from_user(user)
    org_path = extract_org_path_from_claims(user)

    # Resolve tenant ID
    tenant_id = requested_tenant_id or user_tenant_id
    if not tenant_id:
        raise TenantRequiredError("No tenant ID available")

    # Resolve org ID
    org_id = requested_org_id or user_org_id

    # Check if cross-tenant
    is_cross_tenant = (
        requested_tenant_id is not None
        and user_tenant_id is not None
        and requested_tenant_id != user_tenant_id
    )

    return TenantContext(
        tenant_id=tenant_id,
        org_id=org_id,
        org_path=org_path,
        user=user,
        extraction_strategy=extraction_strategy,
        requested_tenant_id=requested_tenant_id,
        requested_org_id=requested_org_id,
        is_validated=False,
        is_cross_tenant=is_cross_tenant,
    )


def validate_tenant_context(
    ctx: TenantContext,
    config: TenantConfig,
) -> TenantContext:
    """
    Validate tenant context and return validated version.

    Pure function - returns new context with is_validated=True or raises.
    """
    if not ctx.user:
        raise TenantRequiredError("User required for tenant validation")

    # Validate tenant access
    if ctx.requested_tenant_id:
        allowed, reason = validate_tenant_access(
            ctx.user, ctx.requested_tenant_id, config
        )
        if not allowed:
            raise TenantAccessDeniedError(reason or "Tenant access denied")

    # Validate org access
    if ctx.requested_org_id:
        allowed, reason = validate_org_access(
            ctx.user, ctx.requested_org_id, config
        )
        if not allowed:
            raise OrgAccessDeniedError(reason or "Organization access denied")

    # Return validated context
    return TenantContext(
        tenant_id=ctx.tenant_id,
        org_id=ctx.org_id,
        org_path=ctx.org_path,
        user=ctx.user,
        extraction_strategy=ctx.extraction_strategy,
        requested_tenant_id=ctx.requested_tenant_id,
        requested_org_id=ctx.requested_org_id,
        is_validated=True,
        is_cross_tenant=ctx.is_cross_tenant,
    )


# =============================================================================
# Tenant Errors
# =============================================================================


class TenantError(AuthError):
    """Base tenant error."""

    error_code = "TENANT_ERROR"
    status_code = 403


class TenantRequiredError(TenantError):
    """Tenant ID required but not provided."""

    error_code = "TENANT_REQUIRED"
    status_code = 400


class TenantAccessDeniedError(TenantError):
    """Access to tenant denied."""

    error_code = "TENANT_ACCESS_DENIED"
    status_code = 403


class OrgAccessDeniedError(TenantError):
    """Access to organization denied."""

    error_code = "ORG_ACCESS_DENIED"
    status_code = 403


class OrgNotFoundError(TenantError):
    """Organization not found."""

    error_code = "ORG_NOT_FOUND"
    status_code = 404


# =============================================================================
# Tenant-Scoped Permission Checking
# =============================================================================


def check_tenant_permission(
    user: AuthenticatedUser,
    permission: str,
    tenant_id: str,
    *,
    config: TenantConfig | None = None,
) -> bool:
    """
    Check permission scoped to a tenant.

    First validates tenant access, then checks permission.
    """
    cfg = config or TenantConfig()

    # Validate tenant access
    allowed, _ = validate_tenant_access(user, tenant_id, cfg)
    if not allowed:
        return False

    # Check permission
    return user.has_permission(permission)


def check_org_permission(
    user: AuthenticatedUser,
    permission: str,
    org_id: str,
    *,
    config: TenantConfig | None = None,
) -> bool:
    """
    Check permission scoped to an organization.

    First validates org access, then checks permission.
    """
    cfg = config or TenantConfig()

    # Validate org access
    allowed, _ = validate_org_access(user, org_id, cfg)
    if not allowed:
        return False

    # Check permission
    return user.has_permission(permission)


def build_tenant_scoped_permission(
    base_permission: str,
    tenant_id: str,
) -> str:
    """
    Build a tenant-scoped permission string.

    Example: build_tenant_scoped_permission("users:read", "acme") -> "tenant:acme:users:read"
    """
    return f"tenant:{tenant_id}:{base_permission}"


def build_org_scoped_permission(
    base_permission: str,
    org_id: str,
) -> str:
    """
    Build an org-scoped permission string.

    Example: build_org_scoped_permission("users:read", "eng") -> "org:eng:users:read"
    """
    return f"org:{org_id}:{base_permission}"


# =============================================================================
# FastAPI Dependencies
# =============================================================================

# Import guard to avoid circular imports
_guard_type = None

def _get_guard_type():
    global _guard_type
    if _guard_type is None:
        from ab0t_auth.guard import AuthGuard
        _guard_type = AuthGuard
    return _guard_type


def require_tenant(
    guard: Any,  # AuthGuard
    *,
    config: TenantConfig | None = None,
    tenant_path_param: str | None = None,
    tenant_header: str | None = None,
):
    """
    FastAPI dependency that requires and validates tenant context.

    Extracts tenant from path param, header, or token (in that order).

    Example:
        @app.get("/tenants/{tenant_id}/users")
        async def get_users(
            tenant_id: str,
            ctx: TenantContext = Depends(require_tenant(auth))
        ):
            # ctx.tenant_id is validated
            return {"tenant": ctx.tenant_id}
    """
    cfg = config or TenantConfig()
    path_param = tenant_path_param or cfg.tenant_path_param
    header = tenant_header or cfg.tenant_header

    async def dependency(
        request: Any,  # Request
        **path_params,
    ) -> TenantContext:
        from fastapi import Request, Header

        # Get authenticated user first
        user = await guard.authenticate_or_raise(
            request.headers.get("Authorization"),
            request.headers.get(guard.config.api_key_header),
        )

        # Extract tenant ID from various sources
        requested_tenant_id = None
        strategy = TenantExtractionStrategy.TOKEN

        # 1. Try path parameter
        if path_param in request.path_params:
            requested_tenant_id = request.path_params[path_param]
            strategy = TenantExtractionStrategy.PATH

        # 2. Try header
        if not requested_tenant_id:
            requested_tenant_id = request.headers.get(header)
            if requested_tenant_id:
                strategy = TenantExtractionStrategy.HEADER

        # 3. Fall back to token
        if not requested_tenant_id:
            requested_tenant_id, _ = extract_tenant_from_user(user)
            strategy = TenantExtractionStrategy.TOKEN

        # Build and validate context
        ctx = build_tenant_context(
            user,
            requested_tenant_id=requested_tenant_id,
            extraction_strategy=strategy,
            config=cfg,
        )

        return validate_tenant_context(ctx, cfg)

    return dependency


def require_org(
    guard: Any,  # AuthGuard
    *,
    config: TenantConfig | None = None,
    org_path_param: str | None = None,
    org_header: str | None = None,
):
    """
    FastAPI dependency that requires and validates organization context.

    Example:
        @app.get("/orgs/{org_id}/members")
        async def get_members(
            org_id: str,
            ctx: TenantContext = Depends(require_org(auth))
        ):
            return {"org": ctx.org_id}
    """
    cfg = config or TenantConfig()
    path_param = org_path_param or cfg.org_path_param
    header = org_header or cfg.org_header

    async def dependency(
        request: Any,
    ) -> TenantContext:
        # Get authenticated user
        user = await guard.authenticate_or_raise(
            request.headers.get("Authorization"),
            request.headers.get(guard.config.api_key_header),
        )

        # Extract org ID
        requested_org_id = None

        if path_param in request.path_params:
            requested_org_id = request.path_params[path_param]

        if not requested_org_id:
            requested_org_id = request.headers.get(header)

        if not requested_org_id:
            _, requested_org_id = extract_tenant_from_user(user)

        # Build and validate
        ctx = build_tenant_context(
            user,
            requested_org_id=requested_org_id,
            config=cfg,
        )

        return validate_tenant_context(ctx, cfg)

    return dependency


def require_tenant_permission(
    guard: Any,
    permission: str,
    *,
    config: TenantConfig | None = None,
):
    """
    FastAPI dependency requiring both tenant context and permission.

    Example:
        @app.delete("/tenants/{tenant_id}/users/{user_id}")
        async def delete_user(
            tenant_id: str,
            user_id: str,
            ctx: TenantContext = Depends(require_tenant_permission(auth, "users:delete"))
        ):
            return {"deleted": user_id}
    """
    cfg = config or TenantConfig()

    async def dependency(
        request: Any,
    ) -> TenantContext:
        # Get tenant context first
        tenant_dep = require_tenant(guard, config=cfg)
        ctx = await tenant_dep(request)

        # Check permission
        if not ctx.user or not ctx.user.has_permission(permission):
            raise PermissionDeniedError(
                f"Permission '{permission}' required",
                required_permission=permission,
            )

        return ctx

    return dependency


# =============================================================================
# Flask Support
# =============================================================================


def get_tenant_context_flask() -> TenantContext | None:
    """
    Get tenant context from Flask request.

    Must be used within a request context.
    """
    try:
        from flask import g
        return getattr(g, "tenant_context", None)
    except ImportError:
        return None


def tenant_required(
    config: TenantConfig | None = None,
):
    """
    Flask decorator requiring tenant context.

    Example:
        @app.route("/tenants/<tenant_id>/data")
        @tenant_required()
        def get_data(tenant_id):
            ctx = get_tenant_context_flask()
            return {"tenant": ctx.tenant_id}
    """
    cfg = config or TenantConfig()

    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            from flask import request, g
            from ab0t_auth.flask import get_current_user

            user = get_current_user()
            if not user:
                raise TenantRequiredError("Authentication required")

            # Extract tenant from path or header
            tenant_id = kwargs.get(cfg.tenant_path_param)
            if not tenant_id:
                tenant_id = request.headers.get(cfg.tenant_header)

            # Build context
            ctx = build_tenant_context(
                user,
                requested_tenant_id=tenant_id,
                config=cfg,
            )

            # Validate and store
            g.tenant_context = validate_tenant_context(ctx, cfg)

            return f(*args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Types
    "TenantContext",
    "TenantConfig",
    "Organization",
    "TenantExtractionStrategy",
    "OrgRelationship",
    # Errors
    "TenantError",
    "TenantRequiredError",
    "TenantAccessDeniedError",
    "OrgAccessDeniedError",
    "OrgNotFoundError",
    # Functions
    "extract_tenant_from_user",
    "extract_org_path_from_claims",
    "validate_tenant_access",
    "validate_org_access",
    "build_tenant_context",
    "validate_tenant_context",
    "check_tenant_permission",
    "check_org_permission",
    "build_tenant_scoped_permission",
    "build_org_scoped_permission",
    # FastAPI
    "require_tenant",
    "require_org",
    "require_tenant_permission",
    # Flask
    "get_tenant_context_flask",
    "tenant_required",
]
