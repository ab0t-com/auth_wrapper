"""
Ab0t Auth - Authentication and authorization library for FastAPI and Flask.

A functional, async-first authentication library for web applications
using Ab0t auth service as the backend.

FastAPI Example:
    from fastapi import FastAPI, Depends
    from ab0t_auth import AuthGuard, require_auth, require_permission

    app = FastAPI()
    auth = AuthGuard(auth_url="https://auth.service.ab0t.com")

    @app.get("/protected")
    async def protected_route(user: AuthenticatedUser = Depends(require_auth(auth))):
        return {"user_id": user.user_id}

Flask Example:
    from flask import Flask
    from ab0t_auth.flask import Ab0tAuth, login_required, permission_required

    app = Flask(__name__)
    auth = Ab0tAuth(app, auth_url="https://auth.service.ab0t.com")

    @app.route("/protected")
    @login_required
    def protected():
        from ab0t_auth.flask import get_current_user
        return {"user_id": get_current_user().user_id}
"""

from ab0t_auth.core import (
    AuthenticatedUser,
    AuthContext,
    TokenClaims,
    Permission,
    AuthConfig,
)
from ab0t_auth.guard import AuthGuard
from ab0t_auth.errors import (
    AuthError,
    TokenExpiredError,
    TokenInvalidError,
    TokenNotFoundError,
    PermissionDeniedError,
    AuthServiceError,
)
from ab0t_auth.tenant import (
    TenantContext,
    TenantConfig,
    TenantExtractionStrategy,
    Organization,
    TenantError,
    TenantRequiredError,
    TenantAccessDeniedError,
    OrgAccessDeniedError,
    OrgNotFoundError,
)

# FastAPI imports (may fail if fastapi not installed)
try:
    from ab0t_auth.dependencies import (
        require_auth,
        require_permission,
        require_any_permission,
        require_all_permissions,
        optional_auth,
        get_current_user,
    )
    from ab0t_auth.middleware import AuthMiddleware
    from ab0t_auth.decorators import protected, permission_required

    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False
    # Provide stub functions that raise helpful errors
    def _fastapi_not_installed(*args, **kwargs):
        raise ImportError(
            "FastAPI is not installed. Install with: pip install 'ab0t-auth[fastapi]'"
        )

    require_auth = _fastapi_not_installed
    require_permission = _fastapi_not_installed
    require_any_permission = _fastapi_not_installed
    require_all_permissions = _fastapi_not_installed
    optional_auth = _fastapi_not_installed
    get_current_user = _fastapi_not_installed
    AuthMiddleware = None  # type: ignore
    protected = _fastapi_not_installed
    permission_required = _fastapi_not_installed

__version__ = "0.1.0"

__all__ = [
    # Core types
    "AuthenticatedUser",
    "AuthContext",
    "TokenClaims",
    "Permission",
    "AuthConfig",
    # Main guard
    "AuthGuard",
    # FastAPI Dependencies
    "require_auth",
    "require_permission",
    "require_any_permission",
    "require_all_permissions",
    "optional_auth",
    "get_current_user",
    # FastAPI Middleware
    "AuthMiddleware",
    # FastAPI Decorators
    "protected",
    "permission_required",
    # Multi-tenancy
    "TenantContext",
    "TenantConfig",
    "TenantExtractionStrategy",
    "Organization",
    "TenantError",
    "TenantRequiredError",
    "TenantAccessDeniedError",
    "OrgAccessDeniedError",
    "OrgNotFoundError",
    # Errors
    "AuthError",
    "TokenExpiredError",
    "TokenInvalidError",
    "TokenNotFoundError",
    "PermissionDeniedError",
    "AuthServiceError",
]
