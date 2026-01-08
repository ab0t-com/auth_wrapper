"""
FastAPI dependencies for Ab0t Auth.

Dependency injection functions for authentication and authorization.
Follow FastAPI patterns - return callables that work with Depends().
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any, Callable, Literal, Sequence

from fastapi import Depends, Header, Request

from ab0t_auth.core import (
    AuthCheckCallable,
    AuthenticatedUser,
)
from ab0t_auth.errors import (
    InsufficientScopeError,
    PermissionDeniedError,
    TokenExpiredError,
    TokenInvalidError,
    TokenNotFoundError,
)
from ab0t_auth.guard import AuthGuard
from ab0t_auth.permissions import (
    check_all_permissions,
    check_any_permission,
    check_permission,
    check_permission_pattern,
)


# =============================================================================
# Type Aliases for FastAPI
# =============================================================================

# Header extraction types
AuthorizationHeader = Annotated[str | None, Header(alias="Authorization")]
ApiKeyHeader = Annotated[str | None, Header(alias="X-API-Key")]


# =============================================================================
# Auth Check Helper
# =============================================================================

import logging

_logger = logging.getLogger("ab0t_auth.dependencies")


def _validate_check_result(result: Any, callback_name: str) -> bool:
    """
    Validate and normalize check callback result to bool.

    Logs warning for non-bool returns and treats them as failure (safe default).
    """
    if isinstance(result, bool):
        return result

    _logger.warning(
        "Check callback '%s' returned non-bool type '%s', treating as False. "
        "Check callbacks must return bool for security.",
        callback_name,
        type(result).__name__,
    )
    return False


async def _run_auth_checks(
    user: AuthenticatedUser,
    request: Request,
    check: AuthCheckCallable | None,
    checks: Sequence[AuthCheckCallable] | None,
    check_mode: Literal["all", "any"],
    check_error: str,
) -> None:
    """
    Run authorization checks and raise PermissionDeniedError on failure.

    Supports both sync and async check functions.

    Security features:
    - Validates callback returns bool (non-bool treated as False)
    - Catches exceptions from callbacks (treated as failure)
    - Logs warnings for debugging
    """
    all_checks: list[AuthCheckCallable] = []

    if check is not None:
        all_checks.append(check)
    if checks is not None:
        all_checks.extend(checks)

    if not all_checks:
        return  # No checks to run

    for check_fn in all_checks:
        callback_name = getattr(check_fn, "__name__", repr(check_fn))

        # Execute callback with exception handling
        try:
            if asyncio.iscoroutinefunction(check_fn):
                raw_result = await check_fn(user, request)
            else:
                raw_result = check_fn(user, request)
        except Exception as e:
            _logger.warning(
                "Check callback '%s' raised exception: %s. Treating as False.",
                callback_name,
                str(e),
            )
            raw_result = False

        # Validate return type (non-bool is treated as False)
        result = _validate_check_result(raw_result, callback_name)

        # Short-circuit for "any" mode on success
        if check_mode == "any" and result:
            return

        # Short-circuit for "all" mode on failure
        if check_mode == "all" and not result:
            raise PermissionDeniedError(check_error)

    # Final check for "any" mode - none passed
    if check_mode == "any":
        raise PermissionDeniedError(check_error)


# =============================================================================
# Dependency Factory Functions
# =============================================================================


def require_auth(
    guard: AuthGuard,
    *,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[..., Any]:
    """
    Create dependency that requires authentication.

    Factory function returning FastAPI dependency.
    Raises TokenNotFoundError if not authenticated.

    Args:
        guard: AuthGuard instance
        allow_api_key: Whether to accept API key authentication
        check: Single authorization check callback (optional)
        checks: List of authorization check callbacks (optional)
        check_mode: "all" requires all checks pass, "any" requires one
        check_error: Error message when check fails

    The check callback signature:
        def my_check(user: AuthenticatedUser, request: Request) -> bool:
            # Return True to allow, False to deny

    Examples:
        # Simple auth only
        require_auth(auth)

        # With single check
        def can_access_domain(user, request):
            domain = request.path_params.get("domain")
            return user.has_permission(f"domain:{domain}:access")

        require_auth(auth, check=can_access_domain)

        # With multiple checks (all must pass)
        require_auth(auth, checks=[is_active, has_subscription])

        # With multiple checks (any can pass)
        require_auth(auth, checks=[is_admin, is_owner], check_mode="any")
    """

    async def dependency(
        request: Request,
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> AuthenticatedUser:
        api_key = x_api_key if allow_api_key else None
        user = await guard.authenticate_or_raise(authorization, api_key)

        # Run authorization checks if provided
        await _run_auth_checks(user, request, check, checks, check_mode, check_error)

        return user

    return dependency


def require_permission(
    guard: AuthGuard,
    permission: str,
    *,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[..., Any]:
    """
    Create dependency that requires specific permission.

    Factory function returning FastAPI dependency.
    Raises PermissionDeniedError if permission not granted.
    Additional checks run AFTER permission check.

    Example:
        @app.delete("/users/{id}")
        async def delete_user(
            id: int,
            user: AuthenticatedUser = Depends(require_permission(auth, "users:delete"))
        ):
            ...
    """

    async def dependency(
        request: Request,
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> AuthenticatedUser:
        api_key = x_api_key if allow_api_key else None
        user = await guard.authenticate_or_raise(authorization, api_key)

        result = check_permission(user, permission)
        if not result.allowed:
            raise PermissionDeniedError(
                result.reason or f"Permission '{permission}' required",
                required_permission=permission,
                user_permissions=list(user.permissions),
            )

        # Run additional authorization checks if provided
        await _run_auth_checks(user, request, check, checks, check_mode, check_error)

        return user

    return dependency


def require_any_permission(
    guard: AuthGuard,
    *permissions: str,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[..., Any]:
    """
    Create dependency that requires any of the specified permissions.

    Factory function returning FastAPI dependency.
    Additional checks run AFTER permission check.

    Example:
        @app.get("/reports")
        async def get_reports(
            user: AuthenticatedUser = Depends(
                require_any_permission(auth, "reports:read", "admin:access")
            )
        ):
            ...
    """

    async def dependency(
        request: Request,
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> AuthenticatedUser:
        api_key = x_api_key if allow_api_key else None
        user = await guard.authenticate_or_raise(authorization, api_key)

        result = check_any_permission(user, *permissions)
        if not result.allowed:
            raise PermissionDeniedError(
                result.reason or f"One of permissions required: {', '.join(permissions)}",
                required_permission=",".join(permissions),
                user_permissions=list(user.permissions),
            )

        # Run additional authorization checks if provided
        await _run_auth_checks(user, request, check, checks, check_mode, check_error)

        return user

    return dependency


def require_all_permissions(
    guard: AuthGuard,
    *permissions: str,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[..., Any]:
    """
    Create dependency that requires all specified permissions.

    Factory function returning FastAPI dependency.
    Additional checks run AFTER permission check.

    Example:
        @app.post("/sensitive-operation")
        async def sensitive_op(
            user: AuthenticatedUser = Depends(
                require_all_permissions(auth, "data:write", "audit:create")
            )
        ):
            ...
    """

    async def dependency(
        request: Request,
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> AuthenticatedUser:
        api_key = x_api_key if allow_api_key else None
        user = await guard.authenticate_or_raise(authorization, api_key)

        result = check_all_permissions(user, *permissions)
        if not result.allowed:
            raise PermissionDeniedError(
                result.reason or f"All permissions required: {', '.join(permissions)}",
                required_permission=",".join(permissions),
                user_permissions=list(user.permissions),
            )

        # Run additional authorization checks if provided
        await _run_auth_checks(user, request, check, checks, check_mode, check_error)

        return user

    return dependency


def require_permission_pattern(
    guard: AuthGuard,
    pattern: str,
    *,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[..., Any]:
    """
    Create dependency that requires permission matching pattern.

    Supports glob patterns like "admin:*", "users:*:read".
    Additional checks run AFTER permission check.

    Example:
        @app.get("/admin/dashboard")
        async def admin_dashboard(
            user: AuthenticatedUser = Depends(
                require_permission_pattern(auth, "admin:*")
            )
        ):
            ...
    """

    async def dependency(
        request: Request,
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> AuthenticatedUser:
        api_key = x_api_key if allow_api_key else None
        user = await guard.authenticate_or_raise(authorization, api_key)

        result = check_permission_pattern(user, pattern)
        if not result.allowed:
            raise PermissionDeniedError(
                result.reason or f"Permission matching '{pattern}' required",
                required_permission=pattern,
                user_permissions=list(user.permissions),
            )

        # Run additional authorization checks if provided
        await _run_auth_checks(user, request, check, checks, check_mode, check_error)

        return user

    return dependency


def optional_auth(
    guard: AuthGuard,
    *,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
) -> Callable[..., Any]:
    """
    Create dependency that optionally authenticates.

    Returns None if:
    - No credentials provided
    - Token is invalid/expired (expected auth failures)
    - Authorization checks fail

    Raises (does NOT return None) for:
    - Auth service unavailable (503)
    - JWKS fetch errors (503)
    - Configuration errors (500)
    - Unexpected exceptions

    This ensures service problems are visible rather than silently
    treated as "unauthenticated".

    Example:
        @app.get("/content")
        async def get_content(
            user: AuthenticatedUser | None = Depends(optional_auth(auth))
        ):
            if user:
                return {"content": "premium", "user": user.user_id}
            return {"content": "basic"}
    """

    async def dependency(
        request: Request,
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> AuthenticatedUser | None:
        if not authorization and not x_api_key:
            return None

        api_key = x_api_key if allow_api_key else None

        try:
            user = await guard.authenticate_or_raise(authorization, api_key)
        except (TokenInvalidError, TokenExpiredError, TokenNotFoundError, InsufficientScopeError):
            # Expected auth failures - treat as unauthenticated
            return None
        # Let other exceptions propagate (AuthServiceError, JWKSFetchError, etc.)

        # Run checks if provided; return None on failure (don't raise)
        try:
            await _run_auth_checks(
                user, request, check, checks, check_mode, "Check failed"
            )
        except PermissionDeniedError:
            return None

        return user

    return dependency


def get_current_user(
    guard: AuthGuard,
    *,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[..., Any]:
    """
    Alias for require_auth - semantic naming.

    Example:
        CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user(auth))]

        @app.get("/me")
        async def get_me(user: CurrentUser):
            return {"user_id": user.user_id}
    """
    return require_auth(
        guard,
        allow_api_key=allow_api_key,
        check=check,
        checks=checks,
        check_mode=check_mode,
        check_error=check_error,
    )


# =============================================================================
# Request-Scoped Dependencies
# =============================================================================


def get_auth_context(
    guard: AuthGuard,
    *,
    allow_api_key: bool = True,
) -> Callable[..., Any]:
    """
    Create dependency that returns full AuthContext.

    Includes request metadata alongside user info.

    Example:
        @app.get("/audit")
        async def audit(
            ctx: AuthContext = Depends(get_auth_context(auth))
        ):
            return {
                "user_id": ctx.user.user_id if ctx.user else None,
                "request_id": ctx.request_id,
                "timestamp": ctx.timestamp.isoformat(),
            }
    """
    from ab0t_auth.core import AuthContext
    import uuid

    async def dependency(
        request: Request,
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> AuthContext:
        api_key = x_api_key if allow_api_key else None
        result = await guard.authenticate(authorization, api_key)

        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        return guard.get_context(
            user=result.user,
            token=authorization,
            request_id=request_id,
        )

    return dependency


# =============================================================================
# Role-Based Dependencies
# =============================================================================


def require_role(
    guard: AuthGuard,
    role: str,
    *,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[..., Any]:
    """
    Create dependency that requires specific role.
    Additional checks run AFTER role check.

    Example:
        @app.get("/admin")
        async def admin_only(
            user: AuthenticatedUser = Depends(require_role(auth, "admin"))
        ):
            ...
    """

    async def dependency(
        request: Request,
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> AuthenticatedUser:
        api_key = x_api_key if allow_api_key else None
        user = await guard.authenticate_or_raise(authorization, api_key)

        if role not in user.roles:
            raise PermissionDeniedError(
                f"Role '{role}' required",
                required_permission=f"role:{role}",
            )

        # Run additional authorization checks if provided
        await _run_auth_checks(user, request, check, checks, check_mode, check_error)

        return user

    return dependency


def require_any_role(
    guard: AuthGuard,
    *roles: str,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[..., Any]:
    """
    Create dependency that requires any of the specified roles.
    Additional checks run AFTER role check.

    Example:
        @app.get("/staff")
        async def staff_only(
            user: AuthenticatedUser = Depends(
                require_any_role(auth, "admin", "manager", "support")
            )
        ):
            ...
    """

    async def dependency(
        request: Request,
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> AuthenticatedUser:
        api_key = x_api_key if allow_api_key else None
        user = await guard.authenticate_or_raise(authorization, api_key)

        if not any(role in user.roles for role in roles):
            raise PermissionDeniedError(
                f"One of roles required: {', '.join(roles)}",
                required_permission=f"roles:{','.join(roles)}",
            )

        # Run additional authorization checks if provided
        await _run_auth_checks(user, request, check, checks, check_mode, check_error)

        return user

    return dependency


# =============================================================================
# Organization-Scoped Dependencies
# =============================================================================


def require_org_membership(
    guard: AuthGuard,
    *,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[..., Any]:
    """
    Create dependency that requires organization membership.

    Validates that user belongs to an organization.
    Additional checks run AFTER org check.

    Example:
        @app.get("/org/settings")
        async def org_settings(
            user: AuthenticatedUser = Depends(require_org_membership(auth))
        ):
            return {"org_id": user.org_id}
    """

    async def dependency(
        request: Request,
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> AuthenticatedUser:
        api_key = x_api_key if allow_api_key else None
        user = await guard.authenticate_or_raise(authorization, api_key)

        if not user.org_id:
            raise PermissionDeniedError(
                "Organization membership required",
                required_permission="org:member",
            )

        # Run additional authorization checks if provided
        await _run_auth_checks(user, request, check, checks, check_mode, check_error)

        return user

    return dependency


def require_org(
    guard: AuthGuard,
    org_id: str,
    *,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[..., Any]:
    """
    Create dependency that requires specific organization.
    Additional checks run AFTER org check.

    Example:
        @app.get("/org/acme/data")
        async def acme_data(
            user: AuthenticatedUser = Depends(require_org(auth, "acme"))
        ):
            ...
    """

    async def dependency(
        request: Request,
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> AuthenticatedUser:
        api_key = x_api_key if allow_api_key else None
        user = await guard.authenticate_or_raise(authorization, api_key)

        if user.org_id != org_id:
            raise PermissionDeniedError(
                f"Organization '{org_id}' membership required",
                required_permission=f"org:{org_id}",
            )

        # Run additional authorization checks if provided
        await _run_auth_checks(user, request, check, checks, check_mode, check_error)

        return user

    return dependency


# =============================================================================
# Composite Dependencies
# =============================================================================


def require_auth_and_permission(
    guard: AuthGuard,
    permission: str,
    *,
    require_org: bool = False,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[..., Any]:
    """
    Create composite dependency with multiple requirements.

    Combines authentication, permission, and optional org check.
    Additional checks run AFTER all other checks.

    Example:
        @app.post("/org/billing")
        async def update_billing(
            user: AuthenticatedUser = Depends(
                require_auth_and_permission(
                    auth, "billing:write", require_org=True
                )
            )
        ):
            ...
    """

    async def dependency(
        request: Request,
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> AuthenticatedUser:
        api_key = x_api_key if allow_api_key else None
        user = await guard.authenticate_or_raise(authorization, api_key)

        # Check org membership if required
        if require_org and not user.org_id:
            raise PermissionDeniedError(
                "Organization membership required",
                required_permission="org:member",
            )

        # Check permission
        result = check_permission(user, permission)
        if not result.allowed:
            raise PermissionDeniedError(
                result.reason or f"Permission '{permission}' required",
                required_permission=permission,
                user_permissions=list(user.permissions),
            )

        # Run additional authorization checks if provided
        await _run_auth_checks(user, request, check, checks, check_mode, check_error)

        return user

    return dependency
