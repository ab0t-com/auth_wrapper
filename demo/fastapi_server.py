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
# Advanced Authorization (Check Callbacks)
# =============================================================================

# Check callbacks allow dynamic authorization based on request context.
# The callback receives (user, request) and returns True/False.


def can_access_tenant(user: AuthenticatedUser, request: Request) -> bool:
    """Check if user belongs to the requested tenant."""
    tenant_id = request.path_params.get("tenant_id")
    return user.org_id == tenant_id or user.has_permission("admin:cross_tenant")


def can_access_domain(user: AuthenticatedUser, request: Request) -> bool:
    """Check if user can access the requested domain scope."""
    domain = request.path_params.get("domain", "")
    scope = domain.split('.')[0]  # e.g., "public" from "public.example.com"

    return user.has_any_permission(
        f"controller.write.services_{scope}",
        "controller.write.services_all",
        "controller.admin",
    )


# Reusable dependency with check callback
tenant_access = require_auth(auth, check=can_access_tenant)
domain_access = require_auth(
    auth,
    check=can_access_domain,
    check_error="Not authorized for this domain",
)


@app.get("/tenants/{tenant_id}/data")
async def get_tenant_data(
    tenant_id: str,
    user: AuthenticatedUser = Depends(tenant_access),
):
    """Tenant-scoped data - uses check callback to verify tenant membership."""
    return {
        "tenant_id": tenant_id,
        "user_org": user.org_id,
        "data": {"example": "tenant-specific data"},
    }


@app.post("/{domain}/services")
async def register_domain_service(
    domain: str,
    user: AuthenticatedUser = Depends(domain_access),
):
    """
    Domain-scoped service registration.

    Uses check callback to verify user has permission for this domain scope.
    For example:
    - User with 'controller.write.services_public' can access public.example.com
    - User with 'controller.write.services_all' can access any domain
    - User with 'controller.admin' can access any domain
    """
    return {
        "registered": True,
        "domain": domain,
        "scope": domain.split('.')[0],
        "by_user": user.user_id,
    }


@app.delete("/{domain}/services/{service_id}")
async def delete_domain_service(
    domain: str,
    service_id: str,
    user: AuthenticatedUser = Depends(domain_access),
):
    """Delete service - reuses same domain access check."""
    return {
        "deleted": service_id,
        "domain": domain,
        "by_user": user.user_id,
    }


# Multiple checks with "any" mode (owner OR admin can delete)
def is_resource_owner(user: AuthenticatedUser, request: Request) -> bool:
    """Check if user owns the resource (simplified - would normally check DB)."""
    resource_id = request.path_params.get("resource_id")
    # In real app: return await db.check_owner(resource_id, user.user_id)
    return resource_id.startswith(user.user_id[:4])  # Demo: ownership by prefix


def is_admin(user: AuthenticatedUser, request: Request) -> bool:
    """Check if user is an admin."""
    return user.has_permission("admin:access")


@app.delete("/resources/{resource_id}")
async def delete_resource(
    resource_id: str,
    user: AuthenticatedUser = Depends(require_auth(
        auth,
        checks=[is_resource_owner, is_admin],
        check_mode="any",  # Owner OR admin can delete
        check_error="Must be owner or admin to delete",
    )),
):
    """Delete resource - owner OR admin can delete."""
    return {
        "deleted": resource_id,
        "by_user": user.user_id,
    }


# Multiple checks with "all" mode (must be verified AND have subscription)
def is_verified_user(user: AuthenticatedUser, request: Request) -> bool:
    """Check if user is verified."""
    return user.metadata.get("email_verified", True)  # Demo: assume verified


def has_premium_subscription(user: AuthenticatedUser, request: Request) -> bool:
    """Check if user has premium subscription."""
    return user.has_permission("premium:access")


@app.post("/premium/features")
async def premium_feature(
    user: AuthenticatedUser = Depends(require_auth(
        auth,
        checks=[is_verified_user, has_premium_subscription],
        check_mode="all",  # Both must pass
        check_error="Premium subscription with verified account required",
    )),
):
    """Premium feature - requires verified account AND premium subscription."""
    return {
        "feature": "premium",
        "user": user.user_id,
        "access_granted": True,
    }


# Permission check combined with custom check callback
@app.get("/admin/tenants/{tenant_id}/settings")
async def admin_tenant_settings(
    tenant_id: str,
    user: AuthenticatedUser = Depends(require_permission(
        auth,
        "admin:settings",
        check=can_access_tenant,
        check_error="Tenant access denied",
    )),
):
    """
    Admin settings for tenant - requires permission AND tenant access.

    This combines:
    1. Permission check: user must have 'admin:settings' permission
    2. Check callback: user must belong to this tenant (or have cross-tenant access)
    """
    return {
        "tenant_id": tenant_id,
        "settings": {"theme": "dark"},
        "admin_user": user.user_id,
    }


# =============================================================================
# Alternative: Manual Check in Route (Simple Cases)
# =============================================================================

@app.post("/manual/{domain}/services")
async def manual_domain_check(
    domain: str,
    user: AuthenticatedUser = Depends(require_auth(auth)),
):
    """
    Alternative approach: manual permission check in route.

    Use this for simple, one-off checks. Use check callbacks for
    reusable logic across multiple routes.
    """
    from fastapi import HTTPException

    scope = domain.split('.')[0]

    if not user.has_any_permission(
        f"controller.write.services_{scope}",
        "controller.write.services_all",
        "controller.admin",
    ):
        raise HTTPException(403, f"Not authorized for domain scope: {scope}")

    return {
        "registered": True,
        "domain": domain,
        "approach": "manual_check",
    }


# =============================================================================
# Decorator Pattern Examples (Alternative to Depends)
# =============================================================================

# You can also use decorators similar to Flask style.
# These require the request object and inject auth_user into kwargs.
# Note: auth_user must have a default value (=None) to avoid FastAPI
# interpreting it as a request body.


@app.get("/decorator/protected")
@protected(auth)
async def decorator_protected(request: Request, auth_user=None):
    """Protected route using decorator pattern."""
    return {
        "message": f"Hello from decorator pattern, {auth_user.email}!",
        "pattern": "decorator",
    }


@app.get("/decorator/permission")
@perm_decorator(auth, "users:read")
async def decorator_permission(request: Request, auth_user=None):
    """Permission check using decorator pattern."""
    return {
        "permission": "users:read",
        "user": auth_user.user_id,
        "pattern": "decorator",
    }


@app.get("/decorator/multi-permission")
@permissions_required(auth, "users:read", "reports:read", require_all=True)
async def decorator_multi_permission(request: Request, auth_user=None):
    """Multiple permissions using decorator pattern."""
    return {
        "permissions": ["users:read", "reports:read"],
        "user": auth_user.user_id,
        "pattern": "decorator",
    }


@app.get("/decorator/any-permission")
@permissions_required(auth, "admin:access", "super:user", require_all=False)
async def decorator_any_permission(request: Request, auth_user=None):
    """Any of multiple permissions using decorator pattern."""
    return {
        "requires_any": ["admin:access", "super:user"],
        "user": auth_user.user_id,
        "pattern": "decorator",
    }


@app.get("/decorator/role")
@role_decorator(auth, "admin")
async def decorator_role(request: Request, auth_user=None):
    """Role check using decorator pattern."""
    return {
        "role": "admin",
        "user": auth_user.user_id,
        "pattern": "decorator",
    }


# Decorator with check callback (using @protected)
def decorator_tenant_check(user: AuthenticatedUser, request: Request) -> bool:
    """Check tenant access for decorator pattern."""
    tenant_id = request.path_params.get("tenant_id")
    return user.org_id == tenant_id


@app.get("/decorator/tenants/{tenant_id}/data")
@protected(auth, check=decorator_tenant_check, check_error="Tenant access denied")
async def decorator_tenant_data(request: Request, tenant_id: str, auth_user=None):
    """Tenant data with check callback using decorator pattern."""
    return {
        "tenant_id": tenant_id,
        "user": auth_user.user_id,
        "pattern": "decorator_with_check",
    }


# Permission decorator with check callback (combines permission + dynamic check)
@app.get("/decorator/admin/tenants/{tenant_id}/settings")
@perm_decorator(auth, "admin:settings", check=decorator_tenant_check, check_error="Tenant access denied")
async def decorator_admin_tenant_settings(request: Request, tenant_id: str, auth_user=None):
    """
    Admin settings for tenant - requires permission AND tenant access.

    This combines:
    1. Permission check: user must have 'admin:settings' permission
    2. Check callback: user must belong to this tenant
    """
    return {
        "tenant_id": tenant_id,
        "settings": {"theme": "dark"},
        "admin_user": auth_user.user_id,
        "pattern": "decorator_permission_with_check",
    }


# =============================================================================
# Class-Based Decorator Pattern (Most Similar to Flask/slowapi)
# =============================================================================

# Create a decorator factory instance - similar to slowapi's Limiter
auth_decorator = Auth(auth)


@app.get("/class/protected")
@auth_decorator.protected()
async def class_protected(request: Request, auth_user=None):
    """Protected route using class-based decorator."""
    return {
        "message": f"Hello {auth_user.email}!",
        "pattern": "class_decorator",
    }


@app.get("/class/permission")
@auth_decorator.permission("users:write")
async def class_permission(request: Request, auth_user=None):
    """Permission check using class-based decorator."""
    return {
        "permission": "users:write",
        "user": auth_user.user_id,
        "pattern": "class_decorator",
    }


@app.get("/class/role")
@auth_decorator.role("editor")
async def class_role(request: Request, auth_user=None):
    """Role check using class-based decorator."""
    return {
        "role": "editor",
        "user": auth_user.user_id,
        "pattern": "class_decorator",
    }


@app.get("/class/pattern")
@auth_decorator.pattern("users:*")
async def class_pattern(request: Request, auth_user=None):
    """Pattern permission check using class-based decorator."""
    return {
        "pattern_match": "users:*",
        "user_permissions": list(auth_user.permissions),
        "pattern": "class_decorator",
    }


# Class-based decorator with check callback
def class_domain_check(user: AuthenticatedUser, request: Request) -> bool:
    """Check domain access for class-based decorator pattern."""
    domain = request.path_params.get("domain", "")
    scope = domain.split('.')[0]
    return user.has_any_permission(
        f"controller.write.services_{scope}",
        "controller.write.services_all",
    )


def class_tenant_check(user: AuthenticatedUser, request: Request) -> bool:
    """Check tenant access for class-based decorator pattern."""
    tenant_id = request.path_params.get("tenant_id")
    return user.org_id == tenant_id


@app.post("/class/{domain}/services")
@auth_decorator.protected(check=class_domain_check, check_error="Domain access denied")
async def class_domain_service(request: Request, domain: str, auth_user=None):
    """Domain service using class-based decorator with check callback."""
    return {
        "domain": domain,
        "user": auth_user.user_id,
        "pattern": "class_decorator_with_check",
    }


# Class-based permission decorator with check callback
@app.get("/class/admin/tenants/{tenant_id}/settings")
@auth_decorator.permission("admin:settings", check=class_tenant_check, check_error="Tenant access denied")
async def class_admin_tenant_settings(request: Request, tenant_id: str, auth_user=None):
    """
    Admin settings for tenant using class-based decorator.

    Combines permission check with tenant access check.
    """
    return {
        "tenant_id": tenant_id,
        "settings": {"theme": "dark"},
        "admin_user": auth_user.user_id,
        "pattern": "class_decorator_permission_with_check",
    }


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
