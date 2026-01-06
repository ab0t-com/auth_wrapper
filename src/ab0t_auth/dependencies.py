"""
FastAPI dependencies for Ab0t Auth.

Dependency injection functions for authentication and authorization.
Follow FastAPI patterns - return callables that work with Depends().
"""

from __future__ import annotations

from typing import Annotated, Any, Callable

from fastapi import Depends, Header, Request

from ab0t_auth.core import AuthenticatedUser
from ab0t_auth.errors import PermissionDeniedError, TokenNotFoundError
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
# Dependency Factory Functions
# =============================================================================


def require_auth(
    guard: AuthGuard,
    *,
    allow_api_key: bool = True,
) -> Callable[..., Any]:
    """
    Create dependency that requires authentication.

    Factory function returning FastAPI dependency.
    Raises TokenNotFoundError if not authenticated.

    Example:
        auth = AuthGuard(...)

        @app.get("/protected")
        async def protected(
            user: AuthenticatedUser = Depends(require_auth(auth))
        ):
            return {"user_id": user.user_id}
    """

    async def dependency(
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> AuthenticatedUser:
        api_key = x_api_key if allow_api_key else None
        return await guard.authenticate_or_raise(authorization, api_key)

    return dependency


def require_permission(
    guard: AuthGuard,
    permission: str,
    *,
    allow_api_key: bool = True,
) -> Callable[..., Any]:
    """
    Create dependency that requires specific permission.

    Factory function returning FastAPI dependency.
    Raises PermissionDeniedError if permission not granted.

    Example:
        @app.delete("/users/{id}")
        async def delete_user(
            id: int,
            user: AuthenticatedUser = Depends(require_permission(auth, "users:delete"))
        ):
            ...
    """

    async def dependency(
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

        return user

    return dependency


def require_any_permission(
    guard: AuthGuard,
    *permissions: str,
    allow_api_key: bool = True,
) -> Callable[..., Any]:
    """
    Create dependency that requires any of the specified permissions.

    Factory function returning FastAPI dependency.

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

        return user

    return dependency


def require_all_permissions(
    guard: AuthGuard,
    *permissions: str,
    allow_api_key: bool = True,
) -> Callable[..., Any]:
    """
    Create dependency that requires all specified permissions.

    Factory function returning FastAPI dependency.

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

        return user

    return dependency


def require_permission_pattern(
    guard: AuthGuard,
    pattern: str,
    *,
    allow_api_key: bool = True,
) -> Callable[..., Any]:
    """
    Create dependency that requires permission matching pattern.

    Supports glob patterns like "admin:*", "users:*:read".

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

        return user

    return dependency


def optional_auth(
    guard: AuthGuard,
    *,
    allow_api_key: bool = True,
) -> Callable[..., Any]:
    """
    Create dependency that optionally authenticates.

    Returns None if not authenticated (no error raised).

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
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> AuthenticatedUser | None:
        if not authorization and not x_api_key:
            return None

        api_key = x_api_key if allow_api_key else None
        result = await guard.authenticate(authorization, api_key)

        return result.user if result.success else None

    return dependency


def get_current_user(
    guard: AuthGuard,
    *,
    allow_api_key: bool = True,
) -> Callable[..., Any]:
    """
    Alias for require_auth - semantic naming.

    Example:
        CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user(auth))]

        @app.get("/me")
        async def get_me(user: CurrentUser):
            return {"user_id": user.user_id}
    """
    return require_auth(guard, allow_api_key=allow_api_key)


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
) -> Callable[..., Any]:
    """
    Create dependency that requires specific role.

    Example:
        @app.get("/admin")
        async def admin_only(
            user: AuthenticatedUser = Depends(require_role(auth, "admin"))
        ):
            ...
    """

    async def dependency(
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

        return user

    return dependency


def require_any_role(
    guard: AuthGuard,
    *roles: str,
    allow_api_key: bool = True,
) -> Callable[..., Any]:
    """
    Create dependency that requires any of the specified roles.

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

        return user

    return dependency


# =============================================================================
# Organization-Scoped Dependencies
# =============================================================================


def require_org_membership(
    guard: AuthGuard,
    *,
    allow_api_key: bool = True,
) -> Callable[..., Any]:
    """
    Create dependency that requires organization membership.

    Validates that user belongs to an organization.

    Example:
        @app.get("/org/settings")
        async def org_settings(
            user: AuthenticatedUser = Depends(require_org_membership(auth))
        ):
            return {"org_id": user.org_id}
    """

    async def dependency(
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

        return user

    return dependency


def require_org(
    guard: AuthGuard,
    org_id: str,
    *,
    allow_api_key: bool = True,
) -> Callable[..., Any]:
    """
    Create dependency that requires specific organization.

    Example:
        @app.get("/org/acme/data")
        async def acme_data(
            user: AuthenticatedUser = Depends(require_org(auth, "acme"))
        ):
            ...
    """

    async def dependency(
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
) -> Callable[..., Any]:
    """
    Create composite dependency with multiple requirements.

    Combines authentication, permission, and optional org check.

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

        return user

    return dependency
