"""
Permission checking functions for Ab0t Auth.

Pure functions for client-side and server-side permission evaluation.
Supports pattern matching for flexible permission schemes.
"""

from __future__ import annotations

import fnmatch
from typing import Any, Callable

import httpx

from ab0t_auth.cache import PermissionCache, permission_credential_fingerprint
from ab0t_auth.client import check_permission as check_permission_remote
from ab0t_auth.core import (
    AuthConfig,
    AuthenticatedUser,
    AuthMethod,
    PermissionCheckRequest,
    PermissionResult,
)
from ab0t_auth.errors import AuthServiceError, PermissionDeniedError

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
    return tuple(perm for perm in user.permissions if fnmatch.fnmatch(perm, pattern))


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
    api_key: str | None = None,
    fresh: bool = False,
) -> PermissionResult:
    """
    Verify permission with server (authoritative check).

    Async function for server-side verification.
    On an auth-service failure the answer follows config.permission_fallback ("deny" by default - fail closed).

    Supports both Bearer token and API key authentication:
    - If token is provided, uses Authorization: Bearer header with token
    - If api_key is provided (and no token), sends API key as Bearer token

    Caching: with a `cache`, an allowed answer is reused for the cache's ttl (default 15 s) and a denied answer for
    its negative ttl (default 5 s). Errors are never cached. `fresh=True` skips the cache READ for this call (always
    asks the auth service) and stores the new answer - use it for sensitive operations (admin, money movement,
    ownership changes).
    """
    # Security hardening: ask with the credential that AUTHENTICATED this user. The guard tries the
    # bearer first and falls through to X-API-Key when the bearer is rejected locally (wrong audience, other service);
    # sending that rejected bearer would let auth answer for a different caller than the one authenticated here (a
    # narrow key + any login token the service rejects = the key owner's full authority).
    if user.auth_method == AuthMethod.API_KEY:
        token = ""
    elif user.auth_method == AuthMethod.JWT:
        api_key = None

    # Permission cache keying: the cached answer belongs to the CREDENTIAL that asked, in the ORG it asked in — never to
    # the user id alone (an owner's / wide key's allow must not authorise the owner's narrow key; a narrow key's deny
    # must not lock the owner out). No credential → never read or write the cache.
    credential = permission_credential_fingerprint(token, api_key)
    org_id = user.org_id or config.org_id
    use_cache = cache is not None and credential is not None

    # Check cache first (unless the caller asked for a fresh answer)
    if use_cache and not fresh:
        cached = cache.get(
            user.user_id, permission, resource_id, credential=credential, org_id=org_id
        )
        if cached is not None:
            if cached:
                return PermissionResult.grant(permission)
            return PermissionResult.deny(permission, "Permission denied (cached)")

    request = PermissionCheckRequest(
        user_id=user.user_id,
        permission=permission,
        org_id=org_id,
        resource_id=resource_id,
        resource_type=resource_type,
    )

    try:
        response = await check_permission_remote(client, config, token, request, api_key=api_key)

        # Update cache
        if use_cache:
            cache.set(
                user.user_id,
                permission,
                response.allowed,
                resource_id,
                credential=credential,
                org_id=org_id,
            )

        if response.allowed:
            return PermissionResult.grant(permission)
        return PermissionResult.deny(permission, response.reason or "Permission denied")

    except AuthServiceError as e:
        # Auth service unreachable or erroring.
        # Behavior depends on config.permission_fallback:
        #   "deny"   — reject the request (fail-closed, default)
        #   "client" — fall back to JWT claims (fail-open, maintains availability)
        import structlog

        logger = structlog.get_logger("ab0t_auth")
        logger.warning(
            "Server-side permission check failed, using fallback",
            fallback=config.permission_fallback,
            permission=permission,
            user_id=user.user_id,
            error=str(e),
        )
        if config.permission_fallback == "client":
            return check_permission(user, permission)
        return PermissionResult.deny(
            permission, "Permission check failed: auth service unavailable"
        )


async def verify_any_permission(
    client: httpx.AsyncClient,
    config: AuthConfig,
    token: str,
    user: AuthenticatedUser,
    *permissions: str,
    resource_id: str | None = None,
    cache: PermissionCache | None = None,
    api_key: str | None = None,
    fresh: bool = False,
) -> PermissionResult:
    """
    Verify if user has any of the specified permissions (server-side).

    Async function. `fresh=True` bypasses the permission cache for these checks (see verify_permission).
    """
    extra: dict[str, Any] = {"fresh": True} if fresh else {}
    for perm in permissions:
        result = await verify_permission(
            client,
            config,
            token,
            user,
            perm,
            resource_id=resource_id,
            cache=cache,
            api_key=api_key,
            **extra,
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
    api_key: str | None = None,
    fresh: bool = False,
) -> PermissionResult:
    """
    Verify if user has all specified permissions (server-side).

    Async function. `fresh=True` bypasses the permission cache for these checks (see verify_permission).
    """
    extra: dict[str, Any] = {"fresh": True} if fresh else {}
    for perm in permissions:
        result = await verify_permission(
            client,
            config,
            token,
            user,
            perm,
            resource_id=resource_id,
            cache=cache,
            api_key=api_key,
            **extra,
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
