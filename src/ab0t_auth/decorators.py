"""
Route decorators for Ab0t Auth.

Decorator-based approach similar to slowapi's @limiter.limit().
Provides an alternative to dependency injection for route protection.
"""

from __future__ import annotations

import asyncio
import functools
from typing import Any, Callable, Literal, ParamSpec, Sequence, TypeVar

from fastapi import Request

from ab0t_auth.core import AuthCheckCallable, AuthenticatedUser
from ab0t_auth.errors import PermissionDeniedError, TokenNotFoundError
from ab0t_auth.guard import AuthGuard
from ab0t_auth.middleware import get_user_from_request
from ab0t_auth.permissions import (
    check_all_permissions,
    check_any_permission,
    check_permission,
    check_permission_pattern,
)


P = ParamSpec("P")
T = TypeVar("T")


# =============================================================================
# Auth Check Helper
# =============================================================================


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

    Supports both sync and async check callbacks.
    """
    all_checks: list[AuthCheckCallable] = []

    if check is not None:
        all_checks.append(check)
    if checks is not None:
        all_checks.extend(checks)

    if not all_checks:
        return  # No checks to run

    for check_fn in all_checks:
        # Support both sync and async checks
        if asyncio.iscoroutinefunction(check_fn):
            result = await check_fn(user, request)
        else:
            result = check_fn(user, request)

        # Short-circuit for "any" mode on success
        if check_mode == "any" and result:
            return

        # Short-circuit for "all" mode on failure
        if check_mode == "all" and not result:
            raise PermissionDeniedError(check_error)

    # If we get here in "any" mode, no check passed
    if check_mode == "any":
        raise PermissionDeniedError(check_error)


# =============================================================================
# Decorator Factories
# =============================================================================


def protected(
    guard: AuthGuard,
    *,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator to protect a route with authentication.

    Requires AuthMiddleware to be installed on the app.
    Injects authenticated user into function kwargs as 'auth_user'.

    Note: The auth_user parameter MUST have a default value (e.g., auth_user=None)
    to prevent FastAPI from interpreting it as a request body. The decorator
    injects the actual AuthenticatedUser at runtime.

    Args:
        guard: AuthGuard instance
        allow_api_key: Whether to accept API key authentication
        check: Single authorization check callback (optional)
        checks: List of authorization check callbacks (optional)
        check_mode: "all" requires all checks pass, "any" requires one
        check_error: Error message when check fails

    Example:
        auth = AuthGuard(...)

        @app.get("/protected")
        @protected(auth)
        async def my_route(request: Request, auth_user=None):
            return {"user_id": auth_user.user_id}

        # With authorization check
        def can_access_resource(user: AuthenticatedUser, request: Request) -> bool:
            resource_id = request.path_params.get("id")
            return user.has_permission(f"resource:{resource_id}:read")

        @app.get("/resources/{id}")
        @protected(auth, check=can_access_resource)
        async def get_resource(request: Request, id: str, auth_user=None):
            ...
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            # Find request in args or kwargs
            request = _extract_request(args, kwargs)
            if request is None:
                raise RuntimeError(
                    "Request not found. Ensure your route accepts a Request parameter."
                )

            # Get user from middleware
            user = get_user_from_request(request)

            if user is None:
                # Try to authenticate directly
                authorization = request.headers.get("Authorization")
                api_key = request.headers.get(guard.config.api_key_header) if allow_api_key else None

                result = await guard.authenticate(authorization, api_key)

                if not result.success or result.user is None:
                    raise TokenNotFoundError(
                        "Authentication required",
                        expected_header=guard.config.header_name,
                    )

                user = result.user

            # Run authorization checks if provided
            await _run_auth_checks(user, request, check, checks, check_mode, check_error)

            # Inject user into kwargs
            kwargs["auth_user"] = user

            return await func(*args, **kwargs)

        return wrapper  # type: ignore

    return decorator


def permission_required(
    guard: AuthGuard,
    permission: str,
    *,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator to require specific permission.

    Similar to @protected but also checks permission.
    Authorization checks run AFTER permission check.

    Args:
        guard: AuthGuard instance
        permission: Permission string to require
        allow_api_key: Whether to accept API key authentication
        check: Single authorization check callback (optional)
        checks: List of authorization check callbacks (optional)
        check_mode: "all" requires all checks pass, "any" requires one
        check_error: Error message when check fails

    Example:
        @app.delete("/users/{id}")
        @permission_required(auth, "users:delete")
        async def delete_user(request: Request, id: int, auth_user: AuthenticatedUser):
            ...
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            request = _extract_request(args, kwargs)
            if request is None:
                raise RuntimeError("Request not found")

            user = get_user_from_request(request)

            if user is None:
                authorization = request.headers.get("Authorization")
                api_key = request.headers.get(guard.config.api_key_header) if allow_api_key else None
                result = await guard.authenticate(authorization, api_key)

                if not result.success or result.user is None:
                    raise TokenNotFoundError("Authentication required")

                user = result.user

            # Check permission
            result = check_permission(user, permission)
            if not result.allowed:
                raise PermissionDeniedError(
                    result.reason or f"Permission '{permission}' required",
                    required_permission=permission,
                    user_permissions=list(user.permissions),
                )

            # Run authorization checks if provided
            await _run_auth_checks(user, request, check, checks, check_mode, check_error)

            kwargs["auth_user"] = user

            return await func(*args, **kwargs)

        return wrapper  # type: ignore

    return decorator


def permissions_required(
    guard: AuthGuard,
    *permissions: str,
    require_all: bool = True,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator to require multiple permissions.

    Authorization checks run AFTER permission checks.

    Args:
        guard: AuthGuard instance
        *permissions: Permission strings to check
        require_all: If True, require all permissions. If False, any permission suffices.
        allow_api_key: Whether to allow API key authentication
        check: Single authorization check callback (optional)
        checks: List of authorization check callbacks (optional)
        check_mode: "all" requires all checks pass, "any" requires one
        check_error: Error message when check fails

    Example:
        # Require all permissions
        @app.post("/admin/users")
        @permissions_required(auth, "users:write", "admin:access")
        async def admin_create_user(...): ...

        # Require any permission
        @app.get("/reports")
        @permissions_required(auth, "reports:read", "admin:access", require_all=False)
        async def get_reports(...): ...
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            request = _extract_request(args, kwargs)
            if request is None:
                raise RuntimeError("Request not found")

            user = get_user_from_request(request)

            if user is None:
                authorization = request.headers.get("Authorization")
                api_key = request.headers.get(guard.config.api_key_header) if allow_api_key else None
                result = await guard.authenticate(authorization, api_key)

                if not result.success or result.user is None:
                    raise TokenNotFoundError("Authentication required")

                user = result.user

            # Check permissions
            if require_all:
                result = check_all_permissions(user, *permissions)
            else:
                result = check_any_permission(user, *permissions)

            if not result.allowed:
                raise PermissionDeniedError(
                    result.reason or f"Required permissions: {', '.join(permissions)}",
                    required_permission=",".join(permissions),
                    user_permissions=list(user.permissions),
                )

            # Run authorization checks if provided
            await _run_auth_checks(user, request, check, checks, check_mode, check_error)

            kwargs["auth_user"] = user

            return await func(*args, **kwargs)

        return wrapper  # type: ignore

    return decorator


def role_required(
    guard: AuthGuard,
    role: str,
    *,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator to require specific role.

    Authorization checks run AFTER role check.

    Args:
        guard: AuthGuard instance
        role: Role string to require
        allow_api_key: Whether to accept API key authentication
        check: Single authorization check callback (optional)
        checks: List of authorization check callbacks (optional)
        check_mode: "all" requires all checks pass, "any" requires one
        check_error: Error message when check fails

    Example:
        @app.get("/admin")
        @role_required(auth, "admin")
        async def admin_only(request: Request, auth_user: AuthenticatedUser):
            ...
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            request = _extract_request(args, kwargs)
            if request is None:
                raise RuntimeError("Request not found")

            user = get_user_from_request(request)

            if user is None:
                authorization = request.headers.get("Authorization")
                api_key = request.headers.get(guard.config.api_key_header) if allow_api_key else None
                result = await guard.authenticate(authorization, api_key)

                if not result.success or result.user is None:
                    raise TokenNotFoundError("Authentication required")

                user = result.user

            # Check role
            if role not in user.roles:
                raise PermissionDeniedError(
                    f"Role '{role}' required",
                    required_permission=f"role:{role}",
                )

            # Run authorization checks if provided
            await _run_auth_checks(user, request, check, checks, check_mode, check_error)

            kwargs["auth_user"] = user

            return await func(*args, **kwargs)

        return wrapper  # type: ignore

    return decorator


def permission_pattern_required(
    guard: AuthGuard,
    pattern: str,
    *,
    allow_api_key: bool = True,
    check: AuthCheckCallable | None = None,
    checks: Sequence[AuthCheckCallable] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator to require permission matching pattern.

    Supports glob patterns like "admin:*", "users:*:read".
    Authorization checks run AFTER pattern check.

    Args:
        guard: AuthGuard instance
        pattern: Glob pattern to match against permissions
        allow_api_key: Whether to accept API key authentication
        check: Single authorization check callback (optional)
        checks: List of authorization check callbacks (optional)
        check_mode: "all" requires all checks pass, "any" requires one
        check_error: Error message when check fails

    Example:
        @app.get("/admin/dashboard")
        @permission_pattern_required(auth, "admin:*")
        async def admin_dashboard(request: Request, auth_user: AuthenticatedUser):
            ...
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            request = _extract_request(args, kwargs)
            if request is None:
                raise RuntimeError("Request not found")

            user = get_user_from_request(request)

            if user is None:
                authorization = request.headers.get("Authorization")
                api_key = request.headers.get(guard.config.api_key_header) if allow_api_key else None
                result = await guard.authenticate(authorization, api_key)

                if not result.success or result.user is None:
                    raise TokenNotFoundError("Authentication required")

                user = result.user

            # Check permission pattern
            result = check_permission_pattern(user, pattern)
            if not result.allowed:
                raise PermissionDeniedError(
                    result.reason or f"Permission matching '{pattern}' required",
                    required_permission=pattern,
                    user_permissions=list(user.permissions),
                )

            # Run authorization checks if provided
            await _run_auth_checks(user, request, check, checks, check_mode, check_error)

            kwargs["auth_user"] = user

            return await func(*args, **kwargs)

        return wrapper  # type: ignore

    return decorator


# =============================================================================
# Class-Based Decorator (Alternative Pattern)
# =============================================================================


class Auth:
    """
    Class-based auth decorator factory.

    Alternative pattern similar to slowapi's Limiter class.

    Example:
        auth = Auth(AuthGuard(...))

        @app.get("/protected")
        @auth.protected()
        async def my_route(request: Request, auth_user: AuthenticatedUser):
            ...

        @app.delete("/users/{id}")
        @auth.permission("users:delete")
        async def delete_user(...): ...

        # With authorization check
        def can_access(user: AuthenticatedUser, request: Request) -> bool:
            return user.org_id == request.path_params.get("org_id")

        @app.get("/orgs/{org_id}/data")
        @auth.protected(check=can_access)
        async def get_org_data(...): ...
    """

    def __init__(self, guard: AuthGuard) -> None:
        self.guard = guard

    def protected(
        self,
        *,
        allow_api_key: bool = True,
        check: AuthCheckCallable | None = None,
        checks: Sequence[AuthCheckCallable] | None = None,
        check_mode: Literal["all", "any"] = "all",
        check_error: str = "Authorization check failed",
    ) -> Callable[[Callable[P, T]], Callable[P, T]]:
        """Decorator requiring authentication."""
        return protected(
            self.guard,
            allow_api_key=allow_api_key,
            check=check,
            checks=checks,
            check_mode=check_mode,
            check_error=check_error,
        )

    def permission(
        self,
        permission: str,
        *,
        allow_api_key: bool = True,
        check: AuthCheckCallable | None = None,
        checks: Sequence[AuthCheckCallable] | None = None,
        check_mode: Literal["all", "any"] = "all",
        check_error: str = "Authorization check failed",
    ) -> Callable[[Callable[P, T]], Callable[P, T]]:
        """Decorator requiring specific permission."""
        return permission_required(
            self.guard,
            permission,
            allow_api_key=allow_api_key,
            check=check,
            checks=checks,
            check_mode=check_mode,
            check_error=check_error,
        )

    def permissions(
        self,
        *permissions: str,
        require_all: bool = True,
        allow_api_key: bool = True,
        check: AuthCheckCallable | None = None,
        checks: Sequence[AuthCheckCallable] | None = None,
        check_mode: Literal["all", "any"] = "all",
        check_error: str = "Authorization check failed",
    ) -> Callable[[Callable[P, T]], Callable[P, T]]:
        """Decorator requiring multiple permissions."""
        return permissions_required(
            self.guard, *permissions,
            require_all=require_all,
            allow_api_key=allow_api_key,
            check=check,
            checks=checks,
            check_mode=check_mode,
            check_error=check_error,
        )

    def role(
        self,
        role: str,
        *,
        allow_api_key: bool = True,
        check: AuthCheckCallable | None = None,
        checks: Sequence[AuthCheckCallable] | None = None,
        check_mode: Literal["all", "any"] = "all",
        check_error: str = "Authorization check failed",
    ) -> Callable[[Callable[P, T]], Callable[P, T]]:
        """Decorator requiring specific role."""
        return role_required(
            self.guard,
            role,
            allow_api_key=allow_api_key,
            check=check,
            checks=checks,
            check_mode=check_mode,
            check_error=check_error,
        )

    def pattern(
        self,
        pattern: str,
        *,
        allow_api_key: bool = True,
        check: AuthCheckCallable | None = None,
        checks: Sequence[AuthCheckCallable] | None = None,
        check_mode: Literal["all", "any"] = "all",
        check_error: str = "Authorization check failed",
    ) -> Callable[[Callable[P, T]], Callable[P, T]]:
        """Decorator requiring permission matching pattern."""
        return permission_pattern_required(
            self.guard,
            pattern,
            allow_api_key=allow_api_key,
            check=check,
            checks=checks,
            check_mode=check_mode,
            check_error=check_error,
        )


# =============================================================================
# Helper Functions
# =============================================================================


def _extract_request(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> Request | None:
    """
    Extract Request from function arguments.

    Looks in both args and kwargs for a Request instance.
    """
    # Check kwargs first
    if "request" in kwargs:
        return kwargs["request"]

    # Check args
    for arg in args:
        if isinstance(arg, Request):
            return arg

    return None
