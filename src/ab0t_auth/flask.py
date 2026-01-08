"""
Flask integration for Ab0t Auth.

Provides Flask extension, decorators, and middleware for authentication.
Follows Flask extension patterns (like Flask-Login).

Example:
    from flask import Flask
    from ab0t_auth.flask import Ab0tAuth, login_required, permission_required

    app = Flask(__name__)
    auth = Ab0tAuth(app, auth_url="https://auth.service.ab0t.com")

    @app.route("/protected")
    @login_required
    def protected():
        return {"user_id": current_user.user_id}

    @app.route("/admin")
    @permission_required("admin:access")
    def admin():
        return {"admin": True}
"""

from __future__ import annotations

import asyncio
import functools
from contextvars import ContextVar
from typing import Any, Callable, Literal, ParamSpec, Sequence, TypeVar

from flask import Flask, Request, Response, g, request, jsonify

from ab0t_auth.core import (
    AuthCheckSync,
    AuthChecksSync,
    AuthConfig,
    AuthContext,
    AuthenticatedUser,
    AuthMethod,
    AuthResult,
    TokenType,
)
from ab0t_auth.config import create_config
from ab0t_auth.errors import (
    AuthError,
    PermissionDeniedError,
    TokenInvalidError,
    TokenNotFoundError,
)
from ab0t_auth.jwt import (
    create_jwk_client,
    parse_token_header,
    validate_token_pipeline,
)
from ab0t_auth.permissions import (
    check_all_permissions,
    check_any_permission,
    check_permission,
    check_permission_pattern,
)
from ab0t_auth.cache import TokenCache, PermissionCache, JWKSCache, create_caches
from ab0t_auth.client import create_http_client, validate_api_key
from ab0t_auth.logging import get_logger, AuthMetrics


P = ParamSpec("P")
T = TypeVar("T")


# =============================================================================
# Context Variables
# =============================================================================

_current_user: ContextVar[AuthenticatedUser | None] = ContextVar("current_user", default=None)


def get_current_user() -> AuthenticatedUser | None:
    """
    Get current authenticated user.

    Returns None if not authenticated.
    """
    # Try context var first, then flask.g
    user = _current_user.get()
    if user is not None:
        return user
    return getattr(g, "auth_user", None)


# Alias for Flask-Login compatibility
current_user = property(lambda self: get_current_user())


# =============================================================================
# Flask Extension
# =============================================================================


class Ab0tAuth:
    """
    Flask extension for Ab0t authentication.

    Follows Flask extension pattern - can be initialized with app
    or using init_app for factory pattern.

    Example:
        # Direct initialization
        app = Flask(__name__)
        auth = Ab0tAuth(app, auth_url="https://auth.service.ab0t.com")

        # Factory pattern
        auth = Ab0tAuth()

        def create_app():
            app = Flask(__name__)
            auth.init_app(app, auth_url="https://auth.service.ab0t.com")
            return app
    """

    def __init__(
        self,
        app: Flask | None = None,
        auth_url: str | None = None,
        *,
        config: AuthConfig | None = None,
        org_id: str | None = None,
        audience: str | tuple[str, ...] | None = None,
        auto_authenticate: bool = True,
    ) -> None:
        """
        Initialize Flask extension.

        Args:
            app: Flask application (optional for factory pattern)
            auth_url: Ab0t auth service URL
            config: Pre-built AuthConfig
            org_id: Default organization ID
            audience: Expected JWT audience
            auto_authenticate: Run authentication on every request
        """
        self.app = app
        self._config: AuthConfig | None = config
        self._auth_url = auth_url
        self._org_id = org_id
        self._audience = audience
        self._auto_authenticate = auto_authenticate

        # Components (initialized in init_app)
        self._jwk_client = None
        self._token_cache: TokenCache | None = None
        self._permission_cache: PermissionCache | None = None
        self._jwks_cache: JWKSCache | None = None
        self._logger = get_logger("ab0t_auth.flask")
        self._metrics = AuthMetrics()

        if app is not None:
            self.init_app(app, auth_url=auth_url)

    def init_app(
        self,
        app: Flask,
        auth_url: str | None = None,
        *,
        config: AuthConfig | None = None,
    ) -> None:
        """
        Initialize extension with Flask app.

        Call this when using factory pattern.
        """
        # Build configuration
        url = auth_url or self._auth_url or app.config.get("AB0T_AUTH_URL")
        if config:
            self._config = config
        elif url:
            self._config = create_config(
                auth_url=url,
                org_id=self._org_id or app.config.get("AB0T_AUTH_ORG_ID"),
                audience=self._audience or app.config.get("AB0T_AUTH_AUDIENCE"),
            )
        else:
            raise ValueError(
                "Must provide auth_url or set AB0T_AUTH_URL in app config"
            )

        # Initialize components
        self._token_cache, self._permission_cache, self._jwks_cache = create_caches(
            self._config
        )

        if self._config.enable_jwt_auth:
            self._jwk_client = create_jwk_client(self._config)

        # Store extension on app
        if not hasattr(app, "extensions"):
            app.extensions = {}
        app.extensions["ab0t_auth"] = self

        # Register before_request handler if auto_authenticate
        if self._auto_authenticate:
            app.before_request(self._authenticate_request)

        # Register error handlers
        app.register_error_handler(AuthError, self._handle_auth_error)
        app.register_error_handler(TokenNotFoundError, self._handle_auth_error)
        app.register_error_handler(TokenInvalidError, self._handle_auth_error)
        app.register_error_handler(PermissionDeniedError, self._handle_auth_error)

        self._logger.info(
            "Ab0tAuth initialized",
            auth_url=self._config.auth_url,
            auto_authenticate=self._auto_authenticate,
        )

    @property
    def config(self) -> AuthConfig:
        """Get auth configuration."""
        if self._config is None:
            raise RuntimeError("Ab0tAuth not initialized. Call init_app first.")
        return self._config

    @property
    def metrics(self) -> AuthMetrics:
        """Get auth metrics."""
        return self._metrics

    # =========================================================================
    # Authentication
    # =========================================================================

    def _authenticate_request(self) -> None:
        """
        Before-request handler to authenticate incoming requests.

        Sets g.auth_user and g.auth_context.
        """
        # Skip for excluded paths (configure via app config)
        excluded = getattr(self.app, "config", {}).get("AB0T_AUTH_EXCLUDE_PATHS", [])
        if request.path in excluded:
            g.auth_user = None
            g.auth_context = None
            return

        # Get credentials
        authorization = request.headers.get("Authorization")
        api_key = request.headers.get(self.config.api_key_header)

        # Authenticate
        result = self.authenticate(authorization, api_key)

        # Set on flask.g
        g.auth_user = result.user
        g.auth_context = AuthContext(
            user=result.user,
            is_authenticated=result.success,
            token=authorization,
            request_id=request.headers.get("X-Request-ID"),
        )

        # Also set context var for thread safety
        _current_user.set(result.user)

    def authenticate(
        self,
        authorization: str | None = None,
        api_key: str | None = None,
    ) -> AuthResult:
        """
        Authenticate using token or API key.

        Returns AuthResult with success status and user.
        """
        # Try JWT first
        if authorization and self.config.enable_jwt_auth:
            result = self._authenticate_jwt(authorization)
            self._metrics.record_auth_attempt(result.success)
            if result.success:
                return result

        # Try API key
        if api_key and self.config.enable_api_key_auth:
            result = self._authenticate_api_key(api_key)
            self._metrics.record_auth_attempt(result.success)
            return result

        return AuthResult.fail("NO_CREDENTIALS", "No valid credentials provided")

    def _authenticate_jwt(self, authorization: str) -> AuthResult:
        """Authenticate using JWT token."""
        token = parse_token_header(authorization, self.config.header_prefix)
        if not token:
            return AuthResult.fail("INVALID_HEADER", "Invalid Authorization header")

        # Check cache
        if self._token_cache:
            cached = self._token_cache.get(token)
            if cached:
                self._metrics.record_cache_access(hit=True)
                return AuthResult.ok(cached.user)
            self._metrics.record_cache_access(hit=False)

        # Validate token
        try:
            if not self._jwk_client:
                return AuthResult.fail("JWT_DISABLED", "JWT auth not enabled")

            user, claims = validate_token_pipeline(
                token, self._jwk_client, self.config
            )

            # Cache result
            if self._token_cache:
                self._token_cache.set(token, user, claims)

            return AuthResult.ok(user)

        except AuthError as e:
            return AuthResult.fail(e.code, e.message)
        except Exception as e:
            return AuthResult.fail("VALIDATION_ERROR", str(e))

    def _authenticate_api_key(self, api_key: str) -> AuthResult:
        """Authenticate using API key (sync wrapper)."""
        try:
            # Run async validation in sync context
            loop = asyncio.new_event_loop()
            try:
                client = create_http_client()
                response = loop.run_until_complete(
                    validate_api_key(client, self.config, api_key)
                )
                loop.run_until_complete(client.aclose())
            finally:
                loop.close()

            if not response.valid:
                return AuthResult.fail("INVALID_API_KEY", response.error or "Invalid API key")

            user = AuthenticatedUser(
                user_id=response.user_id or "api_key_user",
                email=response.email,
                org_id=response.org_id,
                permissions=response.permissions,
                auth_method=AuthMethod.API_KEY,
                token_type=TokenType.API_KEY,
            )
            return AuthResult.ok(user)

        except Exception as e:
            return AuthResult.fail("API_KEY_ERROR", str(e))

    # =========================================================================
    # Authorization
    # =========================================================================

    def check_permission(self, permission: str) -> bool:
        """Check if current user has permission."""
        user = get_current_user()
        if not user:
            return False
        result = check_permission(user, permission)
        self._metrics.record_permission_check(result.allowed)
        return result.allowed

    def require_permission(self, permission: str) -> None:
        """Require permission or raise PermissionDeniedError."""
        user = get_current_user()
        if not user:
            raise TokenNotFoundError("Authentication required")

        result = check_permission(user, permission)
        if not result.allowed:
            raise PermissionDeniedError(
                f"Permission '{permission}' required",
                required_permission=permission,
                user_permissions=list(user.permissions),
            )

    # =========================================================================
    # Error Handling
    # =========================================================================

    def _handle_auth_error(self, error: AuthError) -> tuple[Response, int]:
        """Handle authentication errors."""
        response = jsonify(error.to_dict())
        response.status_code = error.status_code
        return response, error.status_code

    # =========================================================================
    # Cache Management
    # =========================================================================

    def invalidate_token(self, token: str) -> bool:
        """Invalidate cached token."""
        if self._token_cache:
            return self._token_cache.invalidate(token)
        return False

    def clear_caches(self) -> None:
        """Clear all caches."""
        if self._token_cache:
            self._token_cache.clear()
        if self._permission_cache:
            self._permission_cache.clear()
        if self._jwks_cache:
            self._jwks_cache.clear()


# =============================================================================
# Auth Check Helper
# =============================================================================


def _run_auth_checks_sync(
    user: AuthenticatedUser,
    check: AuthCheckSync | None,
    checks: Sequence[AuthCheckSync] | None,
    check_mode: Literal["all", "any"],
    check_error: str,
) -> None:
    """
    Run authorization checks synchronously and raise PermissionDeniedError on failure.

    For Flask, check callback receives only user since request is global.
    """
    all_checks: list[AuthCheckSync] = []

    if check is not None:
        all_checks.append(check)
    if checks is not None:
        all_checks.extend(checks)

    if not all_checks:
        return  # No checks to run

    for check_fn in all_checks:
        result = check_fn(user)

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
# Decorators
# =============================================================================


def login_required(
    f: Callable[P, T] | None = None,
    *,
    check: AuthCheckSync | None = None,
    checks: Sequence[AuthCheckSync] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[P, T] | Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator to require authentication.

    Can be used with or without parentheses:
        @login_required
        def route(): ...

        @login_required()
        def route(): ...

        @login_required(check=my_check)
        def route(): ...

    Args:
        f: The function to decorate (when used without parentheses)
        check: Single authorization check callback (optional)
        checks: List of authorization check callbacks (optional)
        check_mode: "all" requires all checks pass, "any" requires one
        check_error: Error message when check fails

    The check callback receives only the user (request is global in Flask):
        def my_check(user: AuthenticatedUser) -> bool:
            return user.org_id == request.view_args.get("org_id")

    Example:
        @app.route("/protected")
        @login_required
        def protected():
            return {"user": current_user.user_id}

        # With authorization check
        def can_access_tenant(user: AuthenticatedUser) -> bool:
            tenant_id = request.view_args.get("tenant_id")
            return user.org_id == tenant_id

        @app.route("/tenants/<tenant_id>/data")
        @login_required(check=can_access_tenant)
        def tenant_data(tenant_id):
            return {"tenant": tenant_id}
    """
    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        def decorated(*args: P.args, **kwargs: P.kwargs) -> T:
            user = get_current_user()
            if user is None:
                raise TokenNotFoundError(
                    "Authentication required",
                    expected_header="Authorization",
                )

            # Run authorization checks if provided
            _run_auth_checks_sync(user, check, checks, check_mode, check_error)

            return func(*args, **kwargs)
        return decorated  # type: ignore

    # Support both @login_required and @login_required()
    if f is not None:
        return decorator(f)
    return decorator


def permission_required(
    permission: str,
    *,
    check: AuthCheckSync | None = None,
    checks: Sequence[AuthCheckSync] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator to require specific permission.

    Authorization checks run AFTER permission check.

    Args:
        permission: Permission string to require
        check: Single authorization check callback (optional)
        checks: List of authorization check callbacks (optional)
        check_mode: "all" requires all checks pass, "any" requires one
        check_error: Error message when check fails

    Example:
        @app.route("/admin")
        @permission_required("admin:access")
        def admin():
            return {"admin": True}
    """
    def decorator(f: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(f)
        def decorated(*args: P.args, **kwargs: P.kwargs) -> T:
            user = get_current_user()
            if user is None:
                raise TokenNotFoundError("Authentication required")

            result = check_permission(user, permission)
            if not result.allowed:
                raise PermissionDeniedError(
                    f"Permission '{permission}' required",
                    required_permission=permission,
                    user_permissions=list(user.permissions),
                )

            # Run authorization checks if provided
            _run_auth_checks_sync(user, check, checks, check_mode, check_error)

            return f(*args, **kwargs)
        return decorated  # type: ignore
    return decorator


def permissions_required(
    *permissions: str,
    require_all: bool = True,
    check: AuthCheckSync | None = None,
    checks: Sequence[AuthCheckSync] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator to require multiple permissions.

    Authorization checks run AFTER permission checks.

    Args:
        *permissions: Permission strings to check
        require_all: If True, require all permissions. If False, any permission suffices.
        check: Single authorization check callback (optional)
        checks: List of authorization check callbacks (optional)
        check_mode: "all" requires all checks pass, "any" requires one
        check_error: Error message when check fails

    Example:
        @app.route("/sensitive")
        @permissions_required("data:read", "data:write")
        def sensitive():
            return {"access": "granted"}

        @app.route("/any-admin")
        @permissions_required("admin:access", "super:admin", require_all=False)
        def any_admin():
            return {"admin": True}
    """
    def decorator(f: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(f)
        def decorated(*args: P.args, **kwargs: P.kwargs) -> T:
            user = get_current_user()
            if user is None:
                raise TokenNotFoundError("Authentication required")

            if require_all:
                result = check_all_permissions(user, *permissions)
            else:
                result = check_any_permission(user, *permissions)

            if not result.allowed:
                raise PermissionDeniedError(
                    result.reason or "Permission denied",
                    required_permission=",".join(permissions),
                    user_permissions=list(user.permissions),
                )

            # Run authorization checks if provided
            _run_auth_checks_sync(user, check, checks, check_mode, check_error)

            return f(*args, **kwargs)
        return decorated  # type: ignore
    return decorator


def role_required(
    role: str,
    *,
    check: AuthCheckSync | None = None,
    checks: Sequence[AuthCheckSync] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator to require specific role.

    Authorization checks run AFTER role check.

    Args:
        role: Role string to require
        check: Single authorization check callback (optional)
        checks: List of authorization check callbacks (optional)
        check_mode: "all" requires all checks pass, "any" requires one
        check_error: Error message when check fails

    Example:
        @app.route("/admin")
        @role_required("admin")
        def admin():
            return {"admin": True}
    """
    def decorator(f: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(f)
        def decorated(*args: P.args, **kwargs: P.kwargs) -> T:
            user = get_current_user()
            if user is None:
                raise TokenNotFoundError("Authentication required")

            if role not in user.roles:
                raise PermissionDeniedError(
                    f"Role '{role}' required",
                    required_permission=f"role:{role}",
                )

            # Run authorization checks if provided
            _run_auth_checks_sync(user, check, checks, check_mode, check_error)

            return f(*args, **kwargs)
        return decorated  # type: ignore
    return decorator


def permission_pattern_required(
    pattern: str,
    *,
    check: AuthCheckSync | None = None,
    checks: Sequence[AuthCheckSync] | None = None,
    check_mode: Literal["all", "any"] = "all",
    check_error: str = "Authorization check failed",
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator to require permission matching pattern.

    Authorization checks run AFTER pattern check.

    Args:
        pattern: Glob pattern to match against permissions
        check: Single authorization check callback (optional)
        checks: List of authorization check callbacks (optional)
        check_mode: "all" requires all checks pass, "any" requires one
        check_error: Error message when check fails

    Example:
        @app.route("/admin/anything")
        @permission_pattern_required("admin:*")
        def admin_anything():
            return {"pattern": "matched"}
    """
    def decorator(f: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(f)
        def decorated(*args: P.args, **kwargs: P.kwargs) -> T:
            user = get_current_user()
            if user is None:
                raise TokenNotFoundError("Authentication required")

            result = check_permission_pattern(user, pattern)
            if not result.allowed:
                raise PermissionDeniedError(
                    f"Permission matching '{pattern}' required",
                    required_permission=pattern,
                    user_permissions=list(user.permissions),
                )

            # Run authorization checks if provided
            _run_auth_checks_sync(user, check, checks, check_mode, check_error)

            return f(*args, **kwargs)
        return decorated  # type: ignore
    return decorator


# =============================================================================
# Blueprint Support
# =============================================================================


def init_blueprint_auth(auth: Ab0tAuth) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Create a before_request handler for blueprints.

    Example:
        api = Blueprint("api", __name__, url_prefix="/api")

        @api.before_request
        @init_blueprint_auth(auth)
        def authenticate():
            pass  # Authentication handled by decorator
    """
    def decorator(f: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(f)
        def decorated(*args: P.args, **kwargs: P.kwargs) -> T:
            auth._authenticate_request()
            return f(*args, **kwargs)
        return decorated  # type: ignore
    return decorator


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "Ab0tAuth",
    "get_current_user",
    "login_required",
    "permission_required",
    "permissions_required",
    "role_required",
    "permission_pattern_required",
    "init_blueprint_auth",
]
