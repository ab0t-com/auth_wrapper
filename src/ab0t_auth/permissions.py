"""
Permission checking functions for Ab0t Auth.

Pure functions for client-side and server-side permission evaluation.
Supports pattern matching for flexible permission schemes.
"""

from __future__ import annotations

import fnmatch
from typing import Callable

import httpx

from ab0t_auth.cache import PermissionCache
from ab0t_auth.client import check_permission as check_permission_remote
from ab0t_auth.core import (
    AuthConfig,
    AuthenticatedUser,
    PermissionCheckRequest,
    PermissionResult,
)
from ab0t_auth.errors import PermissionDeniedError


# =============================================================================
# Client-Side Permission Checks (Pure Functions)
# =============================================================================


def check_permission(user: AuthenticatedUser, permission: str) -> PermissionResult:
    """
    Check if user has a specific permission (client-side).

    Pure function - uses permissions from token claims.
    Fast, offline check.
    """
    if permission in user.permissions:
        return PermissionResult.grant(permission)

    return PermissionResult.deny(
        permission,
        f"User lacks permission: {permission}",
    )


def check_any_permission(user: AuthenticatedUser, *permissions: str) -> PermissionResult:
    """
    Check if user has any of the specified permissions.

    Pure function - returns first matching permission.
    """
    for perm in permissions:
        if perm in user.permissions:
            return PermissionResult.grant(perm)

    return PermissionResult.deny(
        permissions[0] if permissions else "",
        f"User lacks all required permissions: {', '.join(permissions)}",
    )


def check_all_permissions(user: AuthenticatedUser, *permissions: str) -> PermissionResult:
    """
    Check if user has all specified permissions.

    Pure function - fails on first missing permission.
    """
    for perm in permissions:
        if perm not in user.permissions:
            return PermissionResult.deny(
                perm,
                f"User lacks required permission: {perm}",
            )

    return PermissionResult.grant(",".join(permissions))


def check_permission_pattern(user: AuthenticatedUser, pattern: str) -> PermissionResult:
    """
    Check if user has any permission matching pattern.

    Supports glob patterns like "admin:*", "users:*:read".
    Pure function.
    """
    for perm in user.permissions:
        if fnmatch.fnmatch(perm, pattern):
            return PermissionResult.grant(perm)

    return PermissionResult.deny(
        pattern,
        f"No permission matches pattern: {pattern}",
    )


def check_any_pattern(user: AuthenticatedUser, *patterns: str) -> PermissionResult:
    """
    Check if user has any permission matching any pattern.

    Pure function.
    """
    for pattern in patterns:
        for perm in user.permissions:
            if fnmatch.fnmatch(perm, pattern):
                return PermissionResult.grant(perm)

    return PermissionResult.deny(
        patterns[0] if patterns else "",
        f"No permission matches patterns: {', '.join(patterns)}",
    )


def check_role(user: AuthenticatedUser, role: str) -> PermissionResult:
    """
    Check if user has a specific role.

    Pure function.
    """
    if role in user.roles:
        return PermissionResult.grant(f"role:{role}")

    return PermissionResult.deny(
        f"role:{role}",
        f"User lacks required role: {role}",
    )


def check_any_role(user: AuthenticatedUser, *roles: str) -> PermissionResult:
    """
    Check if user has any of the specified roles.

    Pure function.
    """
    for role in roles:
        if role in user.roles:
            return PermissionResult.grant(f"role:{role}")

    return PermissionResult.deny(
        f"role:{roles[0] if roles else ''}",
        f"User lacks all required roles: {', '.join(roles)}",
    )


# =============================================================================
# Permission Filtering Functions (Pure)
# =============================================================================


def filter_permissions(
    user: AuthenticatedUser,
    pattern: str,
) -> tuple[str, ...]:
    """
    Get all user permissions matching pattern.

    Pure function - returns immutable tuple.
    """
    return tuple(
        perm for perm in user.permissions
        if fnmatch.fnmatch(perm, pattern)
    )


def get_permission_categories(user: AuthenticatedUser) -> tuple[str, ...]:
    """
    Extract unique permission categories from user permissions.

    Assumes permissions are in format "category:action".
    Pure function.
    """
    categories = set()
    for perm in user.permissions:
        if ":" in perm:
            category = perm.split(":")[0]
            categories.add(category)
    return tuple(sorted(categories))


# =============================================================================
# Server-Side Permission Verification (Async)
# =============================================================================


async def verify_permission(
    client: httpx.AsyncClient,
    config: AuthConfig,
    token: str,
    user: AuthenticatedUser,
    permission: str,
    *,
    resource_id: str | None = None,
    resource_type: str | None = None,
    cache: PermissionCache | None = None,
) -> PermissionResult:
    """
    Verify permission with server (authoritative check).

    Async function for server-side verification.
    Falls back to client-side if server unavailable.
    """
    # Check cache first
    if cache:
        cached = cache.get(user.user_id, permission, resource_id)
        if cached is not None:
            if cached:
                return PermissionResult.grant(permission)
            return PermissionResult.deny(permission, "Permission denied (cached)")

    request = PermissionCheckRequest(
        user_id=user.user_id,
        permission=permission,
        org_id=user.org_id or config.org_id,
        resource_id=resource_id,
        resource_type=resource_type,
    )

    try:
        response = await check_permission_remote(client, config, token, request)

        # Update cache
        if cache:
            cache.set(user.user_id, permission, response.allowed, resource_id)

        if response.allowed:
            return PermissionResult.grant(permission)
        return PermissionResult.deny(permission, response.reason or "Permission denied")

    except Exception:
        # Fall back to client-side check on error
        return check_permission(user, permission)


async def verify_any_permission(
    client: httpx.AsyncClient,
    config: AuthConfig,
    token: str,
    user: AuthenticatedUser,
    *permissions: str,
    resource_id: str | None = None,
    cache: PermissionCache | None = None,
) -> PermissionResult:
    """
    Verify if user has any of the specified permissions (server-side).

    Async function.
    """
    for perm in permissions:
        result = await verify_permission(
            client, config, token, user, perm,
            resource_id=resource_id,
            cache=cache,
        )
        if result.allowed:
            return result

    return PermissionResult.deny(
        permissions[0] if permissions else "",
        f"User lacks all required permissions",
    )


async def verify_all_permissions(
    client: httpx.AsyncClient,
    config: AuthConfig,
    token: str,
    user: AuthenticatedUser,
    *permissions: str,
    resource_id: str | None = None,
    cache: PermissionCache | None = None,
) -> PermissionResult:
    """
    Verify if user has all specified permissions (server-side).

    Async function.
    """
    for perm in permissions:
        result = await verify_permission(
            client, config, token, user, perm,
            resource_id=resource_id,
            cache=cache,
        )
        if not result.allowed:
            return result

    return PermissionResult.grant(",".join(permissions))


# =============================================================================
# Permission Guard Functions
# =============================================================================


def require_permission_or_raise(user: AuthenticatedUser, permission: str) -> None:
    """
    Require permission or raise PermissionDeniedError.

    Side effect: raises exception if permission missing.
    """
    result = check_permission(user, permission)
    if not result.allowed:
        raise PermissionDeniedError(
            result.reason or "Permission denied",
            required_permission=permission,
            user_permissions=list(user.permissions),
        )


def require_any_permission_or_raise(user: AuthenticatedUser, *permissions: str) -> None:
    """
    Require any permission or raise PermissionDeniedError.

    Side effect: raises exception if all permissions missing.
    """
    result = check_any_permission(user, *permissions)
    if not result.allowed:
        raise PermissionDeniedError(
            result.reason or "Permission denied",
            required_permission=",".join(permissions),
            user_permissions=list(user.permissions),
        )


def require_all_permissions_or_raise(user: AuthenticatedUser, *permissions: str) -> None:
    """
    Require all permissions or raise PermissionDeniedError.

    Side effect: raises exception if any permission missing.
    """
    result = check_all_permissions(user, *permissions)
    if not result.allowed:
        raise PermissionDeniedError(
            result.reason or "Permission denied",
            required_permission=",".join(permissions),
            user_permissions=list(user.permissions),
        )


# =============================================================================
# Permission Predicate Builders (Higher-Order Functions)
# =============================================================================


def has_permission(permission: str) -> Callable[[AuthenticatedUser], bool]:
    """
    Create predicate function for permission check.

    Higher-order function - returns reusable predicate.
    """
    def predicate(user: AuthenticatedUser) -> bool:
        return permission in user.permissions
    return predicate


def has_any_permission(*permissions: str) -> Callable[[AuthenticatedUser], bool]:
    """
    Create predicate function for any-permission check.

    Higher-order function.
    """
    def predicate(user: AuthenticatedUser) -> bool:
        return any(p in user.permissions for p in permissions)
    return predicate


def has_all_permissions(*permissions: str) -> Callable[[AuthenticatedUser], bool]:
    """
    Create predicate function for all-permissions check.

    Higher-order function.
    """
    def predicate(user: AuthenticatedUser) -> bool:
        return all(p in user.permissions for p in permissions)
    return predicate


def has_permission_pattern(pattern: str) -> Callable[[AuthenticatedUser], bool]:
    """
    Create predicate function for pattern-based check.

    Higher-order function.
    """
    def predicate(user: AuthenticatedUser) -> bool:
        return any(fnmatch.fnmatch(p, pattern) for p in user.permissions)
    return predicate


def has_role(role: str) -> Callable[[AuthenticatedUser], bool]:
    """
    Create predicate function for role check.

    Higher-order function.
    """
    def predicate(user: AuthenticatedUser) -> bool:
        return role in user.roles
    return predicate
