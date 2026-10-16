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

from ab0t_auth.cache import MeshTokenCache
from ab0t_auth.core import (
    AuthConfig,
    AuthContext,
    AuthenticatedUser,
    MeshToken,
    Permission,
    TokenClaims,
)
from ab0t_auth.errors import (
    AuthError,
    AuthServiceError,
    ClientAuthError,
    ClientNotEnabledError,
    ConfigurationError,
    ConsentRequiredError,
    MeshTokenError,
    NoConnectionError,
    PermissionDeniedError,
    ReauthenticateRequired,
    ScopeNotAllowedError,
    TokenExpiredError,
    TokenInvalidError,
    TokenNotFoundError,
)
from ab0t_auth.guard import AuthGuard
from ab0t_auth.tenant import (
    OrgAccessDeniedError,
    Organization,
    OrgNotFoundError,
    TenantAccessDeniedError,
    TenantConfig,
    TenantContext,
    TenantError,
    TenantExtractionStrategy,
    TenantRequiredError,
)
from ab0t_auth.token_for import new_pkce, token_for

# FastAPI imports (may fail if fastapi not installed)
try:
    from ab0t_auth.decorators import permission_required, protected
    from ab0t_auth.dependencies import (
        get_current_user,
        optional_auth,
        require_all_permissions,
        require_any_permission,
        require_auth,
        require_permission,
    )
    from ab0t_auth.middleware import AuthMiddleware

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

__version__ = "0.1.4"

__all__ = [
    # Core types
    "AuthenticatedUser",
    "AuthContext",
    "TokenClaims",
    "Permission",
    "AuthConfig",
    "MeshToken",
    # Main guard
    "AuthGuard",
    # Mesh token exchange (token_for / P3)
    "token_for",
    "new_pkce",
    "MeshTokenCache",
    "MeshTokenError",
    "ReauthenticateRequired",
    "NoConnectionError",
    "ConsentRequiredError",
    "ScopeNotAllowedError",
    "ClientAuthError",
    "ClientNotEnabledError",
    "ConfigurationError",
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
