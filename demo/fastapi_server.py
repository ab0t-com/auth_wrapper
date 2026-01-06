"""
FastAPI Demo Server using Ab0t Auth.

Run with: uvicorn fastapi_server:app --reload --port 8000
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse

from ab0t_auth import (
    AuthGuard,
    AuthenticatedUser,
    AuthMiddleware,
    require_auth,
    require_permission,
    require_any_permission,
    optional_auth,
    AuthError,
)
from ab0t_auth.dependencies import require_role, get_auth_context
from ab0t_auth.core import AuthContext
from ab0t_auth.decorators import (
    protected,
    permission_required as perm_decorator,
    permissions_required,
    role_required as role_decorator,
    Auth,
)


# =============================================================================
# Configuration
# =============================================================================

AUTH_URL = "https://auth.service.ab0t.com"  # Replace with your Ab0t auth URL

# Initialize auth guard
auth = AuthGuard(auth_url=AUTH_URL)


# =============================================================================
# App Lifespan
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup auth guard."""
    await auth.initialize()
    print(f"✅ Auth initialized with {AUTH_URL}")
    yield
    await auth.shutdown()
    print("👋 Auth shutdown complete")


# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(
    title="Ab0t Auth Demo (FastAPI)",
    description="Demo server showing Ab0t Auth integration",
    version="1.0.0",
    lifespan=lifespan,
)


# Custom error handler for auth errors
@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError):
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_dict(),
    )


# =============================================================================
# Public Routes
# =============================================================================

@app.get("/")
async def root():
    """Public endpoint - no auth required."""
    return {
        "message": "Welcome to Ab0t Auth Demo!",
        "docs": "/docs",
        "endpoints": {
            "public": ["/", "/health"],
            "protected": ["/me", "/protected"],
            "permissions": ["/users", "/admin", "/reports"],
        },
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "auth_initialized": auth.is_initialized,
        "metrics": auth.metrics.to_dict(),
    }


# =============================================================================
# Protected Routes (Require Authentication)
# =============================================================================

@app.get("/me")
async def get_me(user: AuthenticatedUser = Depends(require_auth(auth))):
    """Get current user info - requires authentication."""
    return {
        "user_id": user.user_id,
        "email": user.email,
        "org_id": user.org_id,
        "permissions": list(user.permissions),
        "roles": list(user.roles),
        "auth_method": user.auth_method.value,
    }


@app.get("/protected")
async def protected_route(user: AuthenticatedUser = Depends(require_auth(auth))):
    """Protected endpoint - any authenticated user."""
    return {
        "message": f"Hello, {user.email or user.user_id}!",
        "authenticated": True,
    }


@app.get("/context")
async def get_context(ctx: AuthContext = Depends(get_auth_context(auth))):
    """Get full auth context including request metadata."""
    return {
        "user_id": ctx.user.user_id if ctx.user else None,
        "is_authenticated": ctx.is_authenticated,
        "request_id": ctx.request_id,
        "timestamp": ctx.timestamp.isoformat(),
    }


# =============================================================================
# Permission-Based Routes
# =============================================================================

@app.get("/users")
async def list_users(
    user: AuthenticatedUser = Depends(require_permission(auth, "users:read"))
):
    """List users - requires 'users:read' permission."""
    return {
        "users": [
            {"id": 1, "name": "Alice"},
            {"id": 2, "name": "Bob"},
        ],
        "requested_by": user.user_id,
    }


@app.post("/users")
async def create_user(
    user: AuthenticatedUser = Depends(require_permission(auth, "users:write"))
):
    """Create user - requires 'users:write' permission."""
    return {
        "created": True,
        "created_by": user.user_id,
    }


@app.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    user: AuthenticatedUser = Depends(require_permission(auth, "users:delete"))
):
    """Delete user - requires 'users:delete' permission."""
    return {
        "deleted": user_id,
        "deleted_by": user.user_id,
    }


@app.get("/admin")
async def admin_panel(
    user: AuthenticatedUser = Depends(require_permission(auth, "admin:access"))
):
    """Admin panel - requires 'admin:access' permission."""
    return {
        "admin": True,
        "user": user.user_id,
        "cache_stats": {
            "hit_rate": auth.metrics.cache_hit_rate,
            "total_validations": auth.metrics.token_validations,
        },
    }


@app.get("/reports")
async def get_reports(
    user: AuthenticatedUser = Depends(
        require_any_permission(auth, "reports:read", "admin:access")
    )
):
    """Reports - requires 'reports:read' OR 'admin:access'."""
    return {
        "reports": [
            {"id": 1, "title": "Q1 Sales"},
            {"id": 2, "title": "User Growth"},
        ],
        "requested_by": user.user_id,
    }


# =============================================================================
# Role-Based Routes
# =============================================================================

@app.get("/admin/dashboard")
async def admin_dashboard(
    user: AuthenticatedUser = Depends(require_role(auth, "admin"))
):
    """Admin dashboard - requires 'admin' role."""
    return {
        "dashboard": "admin",
        "user": user.user_id,
    }


# =============================================================================
# Optional Auth Routes
# =============================================================================

@app.get("/content")
async def get_content(
    user: AuthenticatedUser | None = Depends(optional_auth(auth))
):
    """Content that varies based on auth status."""
    if user:
        return {
            "content": "Premium content for authenticated users",
            "user": user.user_id,
            "tier": "premium",
        }
    return {
        "content": "Basic content for anonymous users",
        "tier": "free",
    }


# =============================================================================
# Decorator Pattern Examples (Alternative to Depends)
# =============================================================================

# You can also use decorators similar to Flask style.
# These require the request object and inject auth_user into kwargs.


@app.get("/decorator/protected")
@protected(auth)
async def decorator_protected(request: Request, auth_user: AuthenticatedUser):
    """Protected route using decorator pattern."""
    return {
        "message": f"Hello from decorator pattern, {auth_user.email}!",
        "pattern": "decorator",
    }


@app.get("/decorator/permission")
@perm_decorator(auth, "users:read")
async def decorator_permission(request: Request, auth_user: AuthenticatedUser):
    """Permission check using decorator pattern."""
    return {
        "permission": "users:read",
        "user": auth_user.user_id,
        "pattern": "decorator",
    }


@app.get("/decorator/multi-permission")
@permissions_required(auth, "users:read", "reports:read", require_all=True)
async def decorator_multi_permission(request: Request, auth_user: AuthenticatedUser):
    """Multiple permissions using decorator pattern."""
    return {
        "permissions": ["users:read", "reports:read"],
        "user": auth_user.user_id,
        "pattern": "decorator",
    }


@app.get("/decorator/any-permission")
@permissions_required(auth, "admin:access", "super:user", require_all=False)
async def decorator_any_permission(request: Request, auth_user: AuthenticatedUser):
    """Any of multiple permissions using decorator pattern."""
    return {
        "requires_any": ["admin:access", "super:user"],
        "user": auth_user.user_id,
        "pattern": "decorator",
    }


@app.get("/decorator/role")
@role_decorator(auth, "admin")
async def decorator_role(request: Request, auth_user: AuthenticatedUser):
    """Role check using decorator pattern."""
    return {
        "role": "admin",
        "user": auth_user.user_id,
        "pattern": "decorator",
    }


# =============================================================================
# Class-Based Decorator Pattern (Most Similar to Flask/slowapi)
# =============================================================================

# Create a decorator factory instance - similar to slowapi's Limiter
auth_decorator = Auth(auth)


@app.get("/class/protected")
@auth_decorator.protected()
async def class_protected(request: Request, auth_user: AuthenticatedUser):
    """Protected route using class-based decorator."""
    return {
        "message": f"Hello {auth_user.email}!",
        "pattern": "class_decorator",
    }


@app.get("/class/permission")
@auth_decorator.permission("users:write")
async def class_permission(request: Request, auth_user: AuthenticatedUser):
    """Permission check using class-based decorator."""
    return {
        "permission": "users:write",
        "user": auth_user.user_id,
        "pattern": "class_decorator",
    }


@app.get("/class/role")
@auth_decorator.role("editor")
async def class_role(request: Request, auth_user: AuthenticatedUser):
    """Role check using class-based decorator."""
    return {
        "role": "editor",
        "user": auth_user.user_id,
        "pattern": "class_decorator",
    }


@app.get("/class/pattern")
@auth_decorator.pattern("users:*")
async def class_pattern(request: Request, auth_user: AuthenticatedUser):
    """Pattern permission check using class-based decorator."""
    return {
        "pattern_match": "users:*",
        "user_permissions": list(auth_user.permissions),
        "pattern": "class_decorator",
    }


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
