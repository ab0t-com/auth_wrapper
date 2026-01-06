# Ab0t Auth

A functional, async-first authentication and authorization library for **FastAPI** and **Flask** applications using Ab0t auth service.

## Features

- **Multi-Framework Support** - First-class support for both FastAPI and Flask
- **Pure Functional Design** - Business logic as pure functions, classes only for infrastructure
- **Async-First** - All I/O operations are non-blocking for high throughput
- **Type-Safe** - Full type hints with immutable dataclasses
- **Local JWT Validation** - Validate tokens locally using JWKS (no API calls)
- **Flexible Auth Methods** - JWT tokens and API keys supported
- **Permission System** - Client-side and server-side permission checking
- **Pattern Matching** - Glob-style permission patterns (e.g., `admin:*`)
- **Multi-Tenancy** - Built-in support for tenant and organization isolation
- **Multiple Integration Styles** - Dependencies, middleware, or decorators
- **Built-in Caching** - Token and permission caching for performance
- **Observability** - Structured logging with metrics at key decision points

## Installation

```bash
# Install with FastAPI support
pip install ab0t-auth[fastapi]

# Install with Flask support
pip install ab0t-auth[flask]

# Install with both frameworks
pip install ab0t-auth[all]
```

## Quick Start

### FastAPI Setup

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from ab0t_auth import AuthGuard, require_auth, AuthenticatedUser

# Initialize the auth guard
auth = AuthGuard(auth_url="https://auth.service.ab0t.com")

# Setup lifespan for proper initialization/cleanup
@asynccontextmanager
async def lifespan(app: FastAPI):
    async with auth.lifespan():
        yield

app = FastAPI(lifespan=lifespan)

# Protect a route
@app.get("/protected")
async def protected_route(user: AuthenticatedUser = Depends(require_auth(auth))):
    return {"user_id": user.user_id, "email": user.email}
```

### With Permissions

```python
from ab0t_auth import require_permission, require_any_permission

@app.delete("/users/{id}")
async def delete_user(
    id: int,
    user: AuthenticatedUser = Depends(require_permission(auth, "users:delete"))
):
    return {"deleted": id}

@app.get("/admin")
async def admin_panel(
    user: AuthenticatedUser = Depends(require_any_permission(auth, "admin:access", "super:admin"))
):
    return {"admin": True}
```

### Using Middleware

```python
from ab0t_auth import AuthMiddleware, setup_auth_middleware

# Option 1: Simple setup
setup_auth_middleware(
    app, auth,
    exclude_paths=["/health", "/docs"],
    require_auth_paths=["/api/*"],
)

# Option 2: Manual middleware
app.add_middleware(
    AuthMiddleware,
    guard=auth,
    exclude_paths=["/health", "/docs", "/openapi.json"],
)

# Access user in routes
@app.get("/me")
async def get_me(request: Request):
    user = request.state.auth_user  # Set by middleware
    return {"user_id": user.user_id if user else None}
```

### Using Decorators (slowapi-style)

```python
from ab0t_auth import protected, permission_required

@app.get("/dashboard")
@protected(auth)
async def dashboard(request: Request, auth_user: AuthenticatedUser):
    return {"user": auth_user.user_id}

@app.post("/admin/action")
@permission_required(auth, "admin:write")
async def admin_action(request: Request, auth_user: AuthenticatedUser):
    return {"performed": True}
```

### Class-Based Decorators

```python
from ab0t_auth.decorators import Auth

# Create decorator instance
auth_decorator = Auth(auth)

@app.get("/profile")
@auth_decorator.protected()
async def profile(request: Request, auth_user: AuthenticatedUser):
    return {"user": auth_user.email}

@app.delete("/resource")
@auth_decorator.permission("resources:delete")
async def delete_resource(request: Request, auth_user: AuthenticatedUser):
    return {"deleted": True}
```

### Flask Setup

```python
from flask import Flask
from ab0t_auth.flask import (
    Ab0tAuth,
    get_current_user,
    login_required,
    permission_required,
)

app = Flask(__name__)
auth = Ab0tAuth(app, auth_url="https://auth.service.ab0t.com")

@app.route("/protected")
@login_required
def protected_route():
    user = get_current_user()
    return {"user_id": user.user_id, "email": user.email}

@app.route("/admin")
@permission_required("admin:access")
def admin_panel():
    user = get_current_user()
    return {"admin": True, "user": user.user_id}
```

### Flask with Permissions

```python
from ab0t_auth.flask import (
    permissions_required,
    role_required,
    permission_pattern_required,
)

# Require all permissions
@app.route("/sensitive")
@permissions_required("data:read", "data:write", require_all=True)
def sensitive_data():
    return {"data": "sensitive"}

# Require any permission
@app.route("/reports")
@permissions_required("reports:read", "admin:access", require_all=False)
def get_reports():
    return {"reports": [...]}

# Role-based access
@app.route("/admin/dashboard")
@role_required("admin")
def admin_dashboard():
    return {"dashboard": "admin"}

# Pattern matching
@app.route("/users/settings")
@permission_pattern_required("users:*")
def user_settings():
    return {"settings": {...}}
```

### Flask Factory Pattern

```python
from flask import Flask
from ab0t_auth.flask import Ab0tAuth

auth = Ab0tAuth()

def create_app():
    app = Flask(__name__)
    app.config["AB0T_AUTH_URL"] = "https://auth.service.ab0t.com"

    auth.init_app(app)

    return app
```

## Configuration

### Environment Variables

```bash
AB0T_AUTH_AUTH_URL=https://auth.service.ab0t.com
AB0T_AUTH_ORG_ID=your_org_id
AB0T_AUTH_AUDIENCE=your-api
AB0T_AUTH_ISSUER=https://auth.service.ab0t.com
AB0T_AUTH_DEBUG=false
AB0T_AUTH_JWKS_CACHE_TTL=300
AB0T_AUTH_TOKEN_CACHE_TTL=60
```

### Programmatic Configuration

```python
from ab0t_auth import AuthGuard, AuthConfig
from ab0t_auth.config import create_config

# Using AuthConfig directly
config = AuthConfig(
    auth_url="https://auth.service.ab0t.com",
    org_id="my_org",
    audience="my-api",
    algorithms=("RS256",),
    jwks_cache_ttl=300,
    token_cache_ttl=60,
    enable_api_key_auth=True,
    enable_jwt_auth=True,
)

auth = AuthGuard(config=config)

# Or using factory function
config = create_config(
    auth_url="https://auth.service.ab0t.com",
    org_id="my_org",
    audience="my-api",
)
```

## Permission Checking

### Client-Side (Fast, Offline)

```python
from ab0t_auth.permissions import (
    check_permission,
    check_any_permission,
    check_all_permissions,
    check_permission_pattern,
)

# Single permission
result = check_permission(user, "users:read")
if result.allowed:
    # Proceed

# Any of multiple
result = check_any_permission(user, "admin:access", "super:admin")

# All required
result = check_all_permissions(user, "billing:read", "billing:write")

# Pattern matching
result = check_permission_pattern(user, "users:*")  # Matches users:read, users:write, etc.
```

### Server-Side (Authoritative)

```python
from ab0t_auth.permissions import verify_permission

# Make API call to Ab0t service for authoritative check
result = await verify_permission(
    client, config, token, user,
    permission="sensitive:action",
    resource_id="resource_123",
)
```

### Predicate Builders

```python
from ab0t_auth.permissions import has_permission, has_role, has_permission_pattern

# Create reusable predicates
is_admin = has_role("admin")
can_write = has_permission("data:write")
has_admin_access = has_permission_pattern("admin:*")

if is_admin(user) or can_write(user):
    # Proceed
```

## Error Handling

```python
from ab0t_auth.errors import (
    AuthError,
    TokenExpiredError,
    TokenInvalidError,
    TokenNotFoundError,
    PermissionDeniedError,
    AuthServiceError,
)
from ab0t_auth.middleware import register_auth_exception_handlers

# Register exception handlers for consistent error responses
register_auth_exception_handlers(app)

# Or handle manually
@app.exception_handler(PermissionDeniedError)
async def handle_permission_denied(request: Request, exc: PermissionDeniedError):
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_dict(),
    )
```

## API Key Authentication

```python
# API keys are supported by default
# Send via X-API-Key header

# Disable API key auth if not needed
auth = AuthGuard(
    auth_url="https://auth.service.ab0t.com",
    enable_api_key_auth=False,
)

# Or per-route
@app.get("/jwt-only")
async def jwt_only(
    user: AuthenticatedUser = Depends(require_auth(auth, allow_api_key=False))
):
    return {"method": user.auth_method}
```

## Cache Management

```python
# Invalidate specific token
auth.invalidate_token(token)

# Invalidate user's cached permissions
auth.invalidate_user_permissions(user_id)

# Clear all caches
auth.clear_caches()

# Access metrics
print(auth.metrics.to_dict())
# {
#     "auth_attempts": 1000,
#     "auth_successes": 950,
#     "cache_hit_rate": 0.85,
#     ...
# }
```

## Advanced Usage

### Optional Authentication

```python
from ab0t_auth import optional_auth

@app.get("/content")
async def get_content(user: AuthenticatedUser | None = Depends(optional_auth(auth))):
    if user:
        return {"content": "premium", "user": user.user_id}
    return {"content": "basic"}
```

### Organization-Scoped Routes

```python
from ab0t_auth.dependencies import require_org_membership, require_org

@app.get("/org/settings")
async def org_settings(
    user: AuthenticatedUser = Depends(require_org_membership(auth))
):
    return {"org_id": user.org_id}

@app.get("/orgs/acme/data")
async def acme_data(
    user: AuthenticatedUser = Depends(require_org(auth, "acme"))
):
    return {"data": "acme-specific"}
```

### Full Auth Context

```python
from ab0t_auth.dependencies import get_auth_context
from ab0t_auth.core import AuthContext

@app.get("/audit")
async def audit(ctx: AuthContext = Depends(get_auth_context(auth))):
    return {
        "user_id": ctx.user.user_id if ctx.user else None,
        "request_id": ctx.request_id,
        "timestamp": ctx.timestamp.isoformat(),
        "is_authenticated": ctx.is_authenticated,
    }
```

## Multi-Tenancy

Ab0t Auth includes built-in multi-tenancy support where each user is a tenant and can belong to organizations (including nested organizations).

### FastAPI Multi-Tenancy

```python
from ab0t_auth.tenant import (
    TenantConfig,
    require_tenant,
    require_org,
    require_tenant_permission,
)

# Configure tenant behavior
tenant_config = TenantConfig(
    enforce_tenant_isolation=True,
    enforce_org_isolation=False,
    allow_cross_tenant_admin=True,
    enable_org_hierarchy=True,
)

# Require tenant context
@app.get("/tenant/data")
async def tenant_data(
    tenant_ctx = Depends(require_tenant(auth, tenant_config))
):
    return {
        "tenant_id": tenant_ctx.tenant_id,
        "org_id": tenant_ctx.org_id,
    }

# Require specific organization
@app.get("/orgs/{org_id}/data")
async def org_data(
    org_id: str,
    tenant_ctx = Depends(require_org(auth, tenant_config, org_id))
):
    return {"org_id": org_id, "data": "org-specific"}

# Tenant-scoped permissions
@app.delete("/tenant/users/{user_id}")
async def delete_tenant_user(
    user_id: str,
    tenant_ctx = Depends(require_tenant_permission(auth, tenant_config, "users:delete"))
):
    return {"deleted": user_id}
```

### Flask Multi-Tenancy

```python
from ab0t_auth.tenant import TenantConfig, tenant_required

tenant_config = TenantConfig(
    enforce_tenant_isolation=True,
    enable_org_hierarchy=True,
)

@app.route("/tenant/dashboard")
@tenant_required(tenant_config)
def tenant_dashboard():
    from flask import g
    tenant_ctx = g.tenant_context
    return {"tenant_id": tenant_ctx.tenant_id}
```

### Tenant Extraction Strategies

```python
from ab0t_auth.tenant import TenantExtractionStrategy

# From JWT token claims (default)
TenantExtractionStrategy.TOKEN

# From X-Tenant-ID header
TenantExtractionStrategy.HEADER

# From URL path (/tenants/{id}/...)
TenantExtractionStrategy.PATH

# From subdomain (tenant.example.com)
TenantExtractionStrategy.SUBDOMAIN

# From query parameter (?tenant_id=...)
TenantExtractionStrategy.QUERY
```

### Cross-Tenant Admin Access

```python
tenant_config = TenantConfig(
    allow_cross_tenant_admin=True,
    cross_tenant_permission="admin:cross_tenant",
)

# Users with "admin:cross_tenant" permission can access any tenant
```

## Architecture

This library follows functional programming principles:

1. **Pure Functions** - Business logic has no side effects
2. **Immutable Data** - All data structures are frozen dataclasses
3. **Explicit Dependencies** - All inputs passed explicitly
4. **Async I/O** - Non-blocking for 1000+ req/sec throughput
5. **Type Safety** - Full type hints throughout

```
ab0t_auth/
├── core.py           # Immutable types and schemas
├── guard.py          # Main AuthGuard coordinator
├── jwt.py            # JWT validation functions
├── permissions.py    # Permission checking functions
├── tenant.py         # Multi-tenancy support
├── client.py         # Async HTTP client
├── cache.py          # Token/permission caching
├── dependencies.py   # FastAPI dependencies
├── middleware.py     # ASGI middleware
├── decorators.py     # FastAPI route decorators
├── flask.py          # Flask extension and decorators
├── config.py         # Configuration management
├── errors.py         # Error types
└── logging.py        # Structured logging
```

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# With coverage
pytest --cov=ab0t_auth --cov-report=html
```

## License

MIT License - see LICENSE file for details.
