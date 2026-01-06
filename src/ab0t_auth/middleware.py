"""
FastAPI middleware for Ab0t Auth.

ASGI middleware for automatic authentication on all requests.
Similar to authentication middleware in other frameworks.
"""

from __future__ import annotations

import uuid
from typing import Any, Callable, Sequence

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

from ab0t_auth.core import AuthContext, AuthenticatedUser
from ab0t_auth.errors import AuthError
from ab0t_auth.guard import AuthGuard
from ab0t_auth.logging import get_logger, log_auth_attempt, Timer


# =============================================================================
# Request State Keys
# =============================================================================

AUTH_USER_KEY = "auth_user"
AUTH_CONTEXT_KEY = "auth_context"
REQUEST_ID_KEY = "request_id"


# =============================================================================
# Auth Middleware
# =============================================================================


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Authentication middleware for FastAPI.

    Automatically authenticates requests and attaches user to request.state.
    Similar to other auth middleware patterns.

    Example:
        auth = AuthGuard(...)
        app = FastAPI()
        app.add_middleware(AuthMiddleware, guard=auth)

        @app.get("/me")
        async def get_me(request: Request):
            user = request.state.auth_user
            return {"user_id": user.user_id if user else None}
    """

    def __init__(
        self,
        app: ASGIApp,
        guard: AuthGuard,
        *,
        exclude_paths: Sequence[str] | None = None,
        require_auth_paths: Sequence[str] | None = None,
        on_error: Callable[[AuthError], Response] | None = None,
    ) -> None:
        """
        Initialize middleware.

        Args:
            app: ASGI application
            guard: AuthGuard instance
            exclude_paths: Paths to skip authentication (e.g., ["/health", "/docs"])
            require_auth_paths: Paths that require authentication (None = optional auth)
            on_error: Custom error handler for auth failures
        """
        super().__init__(app)
        self.guard = guard
        self.exclude_paths = set(exclude_paths or [])
        self.require_auth_paths = set(require_auth_paths or [])
        self.on_error = on_error or self._default_error_handler
        self._logger = get_logger("ab0t_auth.middleware")

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Process request through authentication."""
        # Generate request ID
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        # Check if path should be excluded
        if self._should_exclude(request.url.path):
            request.state.auth_user = None
            request.state.auth_context = None
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response

        # Attempt authentication
        timer = Timer().start()

        authorization = request.headers.get("Authorization")
        api_key = request.headers.get(self.guard.config.api_key_header)

        result = await self.guard.authenticate(authorization, api_key)

        timer.stop()

        # Log auth attempt
        log_auth_attempt(
            self._logger,
            method="middleware",
            success=result.success,
            user_id=result.user.user_id if result.user else None,
            duration_ms=timer.elapsed_ms,
            error=result.error_message if not result.success else None,
            path=request.url.path,
        )

        # Check if auth is required for this path
        requires_auth = self._requires_auth(request.url.path)

        if requires_auth and not result.success:
            error = AuthError(
                result.error_message or "Authentication required",
                code=result.error_code or "AUTH_REQUIRED",
            )
            return self.on_error(error)

        # Attach to request state
        request.state.auth_user = result.user
        request.state.auth_context = self.guard.get_context(
            user=result.user,
            token=authorization,
            request_id=request_id,
        )

        # Process request
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id

        return response

    def _should_exclude(self, path: str) -> bool:
        """Check if path should be excluded from auth."""
        # Exact match
        if path in self.exclude_paths:
            return True

        # Prefix match (for paths ending with *)
        for exclude in self.exclude_paths:
            if exclude.endswith("*") and path.startswith(exclude[:-1]):
                return True

        return False

    def _requires_auth(self, path: str) -> bool:
        """Check if path requires authentication."""
        if not self.require_auth_paths:
            return False

        # Exact match
        if path in self.require_auth_paths:
            return True

        # Prefix match
        for require_path in self.require_auth_paths:
            if require_path.endswith("*") and path.startswith(require_path[:-1]):
                return True

        return False

    @staticmethod
    def _default_error_handler(error: AuthError) -> Response:
        """Default error handler returning JSON response."""
        return JSONResponse(
            status_code=error.status_code,
            content=error.to_dict(),
        )


# =============================================================================
# Request State Helpers
# =============================================================================


def get_user_from_request(request: Request) -> AuthenticatedUser | None:
    """
    Get authenticated user from request state.

    Utility function for accessing user in routes.
    """
    return getattr(request.state, AUTH_USER_KEY, None)


def get_context_from_request(request: Request) -> AuthContext | None:
    """
    Get auth context from request state.

    Utility function for accessing full context.
    """
    return getattr(request.state, AUTH_CONTEXT_KEY, None)


def get_request_id(request: Request) -> str | None:
    """
    Get request ID from request state.

    Utility function for tracing.
    """
    return getattr(request.state, REQUEST_ID_KEY, None)


# =============================================================================
# Middleware Setup Helpers
# =============================================================================


def setup_auth_middleware(
    app: FastAPI,
    guard: AuthGuard,
    *,
    exclude_paths: Sequence[str] | None = None,
    require_auth_paths: Sequence[str] | None = None,
) -> None:
    """
    Setup auth middleware on FastAPI app.

    Convenience function for common configuration.

    Example:
        app = FastAPI()
        auth = AuthGuard(...)

        setup_auth_middleware(
            app, auth,
            exclude_paths=["/health", "/docs", "/openapi.json"],
            require_auth_paths=["/api/*"],
        )
    """
    # Default exclusions for common endpoints
    default_excludes = [
        "/health",
        "/healthz",
        "/ready",
        "/readyz",
        "/docs",
        "/redoc",
        "/openapi.json",
    ]

    all_excludes = list(exclude_paths or []) + default_excludes

    app.add_middleware(
        AuthMiddleware,
        guard=guard,
        exclude_paths=all_excludes,
        require_auth_paths=require_auth_paths,
    )


# =============================================================================
# CORS + Auth Middleware
# =============================================================================


def add_cors_headers(response: Response, origins: str = "*") -> Response:
    """
    Add CORS headers to response.

    Utility for handling CORS with auth.
    """
    response.headers["Access-Control-Allow-Origin"] = origins
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-API-Key"
    return response


# =============================================================================
# Exception Handlers
# =============================================================================


def create_auth_exception_handler() -> Callable[[Request, AuthError], Response]:
    """
    Create exception handler for AuthError.

    Register with FastAPI for consistent error responses.

    Example:
        app.add_exception_handler(AuthError, create_auth_exception_handler())
    """

    async def handler(request: Request, exc: AuthError) -> Response:
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_dict(),
            headers={"X-Request-ID": getattr(request.state, "request_id", "unknown")},
        )

    return handler


def register_auth_exception_handlers(app: FastAPI) -> None:
    """
    Register all auth exception handlers.

    Convenience function to register handlers for all auth errors.

    Example:
        app = FastAPI()
        register_auth_exception_handlers(app)
    """
    from ab0t_auth.errors import (
        AuthError,
        TokenExpiredError,
        TokenInvalidError,
        TokenNotFoundError,
        PermissionDeniedError,
        AuthServiceError,
    )

    handler = create_auth_exception_handler()

    app.add_exception_handler(AuthError, handler)
    app.add_exception_handler(TokenExpiredError, handler)
    app.add_exception_handler(TokenInvalidError, handler)
    app.add_exception_handler(TokenNotFoundError, handler)
    app.add_exception_handler(PermissionDeniedError, handler)
    app.add_exception_handler(AuthServiceError, handler)
