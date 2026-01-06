# Tenant Integration Improvement Proposal

## Current Architecture Problems

### 1. Separate Auth and Tenant Flows
Currently, users need two separate dependencies:

```python
# Current: Two dependencies, redundant auth
@app.get("/tenant/{tenant_id}/users")
async def get_users(
    tenant_id: str,
    user: AuthenticatedUser = Depends(require_auth(auth)),
    tenant_ctx: TenantContext = Depends(require_tenant(auth, config)),
):
    # tenant_ctx authenticates AGAIN internally
    ...
```

### 2. Redundant Authentication
`require_tenant` calls `guard.authenticate_or_raise()` again, wasting resources.

### 3. No Unified Context
`AuthContext` and `TenantContext` are separate - no single object with all info.

### 4. Tenant Not Part of Core
Tenant is an add-on module, not integrated into the main auth flow.

---

## Proposed Architecture

### 1. Unified `RequestContext`

Create a single context object that includes everything:

```python
@dataclass(frozen=True, slots=True)
class RequestContext:
    """Unified request context with auth + tenant."""

    # Authentication
    user: AuthenticatedUser | None = None
    is_authenticated: bool = False
    auth_method: AuthMethod | None = None

    # Tenant
    tenant_id: str | None = None
    org_id: str | None = None
    org_path: tuple[str, ...] = field(default_factory=tuple)

    # Request metadata
    request_id: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Validation state
    is_validated: bool = False
    is_cross_tenant: bool = False

    # Helper methods
    def require_tenant(self) -> str:
        if not self.tenant_id:
            raise TenantRequiredError()
        return self.tenant_id

    def require_org(self) -> str:
        if not self.org_id:
            raise OrgRequiredError()
        return self.org_id
```

### 2. Enhanced `AuthGuard` with Tenant Support

```python
class AuthGuard:
    def __init__(
        self,
        auth_url: str,
        *,
        tenant_config: TenantConfig | None = None,  # NEW
        ...
    ):
        self._tenant_config = tenant_config or TenantConfig()

    async def authenticate_with_context(
        self,
        authorization: str | None = None,
        api_key: str | None = None,
        *,
        tenant_id: str | None = None,  # From path/header
        org_id: str | None = None,
    ) -> RequestContext:
        """
        Authenticate and build full request context.

        Single method that does both auth and tenant in one pass.
        """
        # 1. Authenticate user
        user = await self.authenticate_or_raise(authorization, api_key)

        # 2. Extract tenant info from token
        token_tenant, token_org = extract_tenant_from_user(user)
        org_path = extract_org_path_from_claims(user)

        # 3. Resolve requested vs token tenant
        resolved_tenant = tenant_id or token_tenant
        resolved_org = org_id or token_org

        # 4. Validate access
        is_cross_tenant = False
        if tenant_id and tenant_id != token_tenant:
            allowed, _ = validate_tenant_access(user, tenant_id, self._tenant_config)
            if not allowed:
                raise TenantAccessDeniedError(tenant_id)
            is_cross_tenant = True

        # 5. Build unified context
        return RequestContext(
            user=user,
            is_authenticated=True,
            auth_method=user.auth_method,
            tenant_id=resolved_tenant,
            org_id=resolved_org,
            org_path=org_path,
            is_validated=True,
            is_cross_tenant=is_cross_tenant,
        )
```

### 3. Single Unified Dependency

```python
def require_context(
    guard: AuthGuard,
    *,
    require_tenant: bool = True,
    require_org: bool = False,
    permission: str | None = None,
) -> Callable[..., Awaitable[RequestContext]]:
    """
    Single dependency for all auth + tenant needs.

    Examples:
        # Just auth
        ctx = Depends(require_context(auth, require_tenant=False))

        # Auth + tenant
        ctx = Depends(require_context(auth))

        # Auth + tenant + permission
        ctx = Depends(require_context(auth, permission="users:read"))

        # Auth + tenant + org
        ctx = Depends(require_context(auth, require_org=True))
    """
    async def dependency(
        request: Request,
        authorization: AuthorizationHeader = None,
        x_api_key: ApiKeyHeader = None,
    ) -> RequestContext:
        # Extract tenant/org from path params
        tenant_id = request.path_params.get("tenant_id")
        org_id = request.path_params.get("org_id")

        # Or from headers
        if not tenant_id:
            tenant_id = request.headers.get("X-Tenant-ID")
        if not org_id:
            org_id = request.headers.get("X-Org-ID")

        # Authenticate with context
        ctx = await guard.authenticate_with_context(
            authorization,
            x_api_key,
            tenant_id=tenant_id,
            org_id=org_id,
        )

        # Validate requirements
        if require_tenant:
            ctx.require_tenant()
        if require_org:
            ctx.require_org()

        # Check permission
        if permission and ctx.user:
            if not ctx.user.has_permission(permission):
                raise PermissionDeniedError(permission)

        return ctx

    return dependency
```

### 4. Clean Usage Examples

```python
# Initialize once with tenant config
auth = AuthGuard(
    auth_url="https://auth.ab0t.com",
    tenant_config=TenantConfig(
        enforce_tenant_isolation=True,
        allow_cross_tenant_admin=True,
    ),
)

# Simple protected route (auto-extracts tenant from token)
@app.get("/dashboard")
async def dashboard(ctx: RequestContext = Depends(require_context(auth))):
    return {
        "user": ctx.user.user_id,
        "tenant": ctx.tenant_id,
    }

# Route with path-based tenant
@app.get("/tenants/{tenant_id}/users")
async def get_users(
    tenant_id: str,
    ctx: RequestContext = Depends(require_context(auth)),
):
    # tenant_id from path is auto-validated against user's permissions
    return {"tenant": ctx.tenant_id, "users": [...]}

# Route with permission
@app.delete("/tenants/{tenant_id}/users/{user_id}")
async def delete_user(
    tenant_id: str,
    user_id: str,
    ctx: RequestContext = Depends(require_context(auth, permission="users:delete")),
):
    return {"deleted": user_id}

# Route requiring org
@app.get("/orgs/{org_id}/settings")
async def org_settings(
    org_id: str,
    ctx: RequestContext = Depends(require_context(auth, require_org=True)),
):
    return {"org": ctx.org_id, "settings": {...}}
```

---

## Implementation Plan

### Phase 1: Add `RequestContext` to Core
1. Create `RequestContext` dataclass in `core.py`
2. Add helper methods for common checks
3. Keep backward compatibility with existing types

### Phase 2: Enhance `AuthGuard`
1. Add `tenant_config` parameter to `__init__`
2. Add `authenticate_with_context()` method
3. Keep existing methods for backward compatibility

### Phase 3: Create Unified Dependencies
1. Add `require_context()` to `dependencies.py`
2. Create type alias: `Context = Annotated[RequestContext, Depends(require_context(auth))]`
3. Deprecate separate tenant dependencies (soft deprecation)

### Phase 4: Update Middleware
1. Enhance `AuthMiddleware` to set `RequestContext` on `request.state`
2. Add tenant extraction in middleware for auto-auth paths

### Phase 5: Documentation & Migration
1. Update README with new patterns
2. Create migration guide
3. Update demo servers

---

## Benefits

| Aspect | Before | After |
|--------|--------|-------|
| Dependencies per route | 2+ | 1 |
| Auth calls per request | 2 (redundant) | 1 |
| Context types | 3 (User, AuthContext, TenantContext) | 1 (RequestContext) |
| Tenant validation | Manual | Automatic |
| Cross-tenant handling | Custom code | Built-in |
| Type safety | Fragmented | Unified |

---

## Backward Compatibility

All existing code continues to work:

```python
# OLD - still works
@app.get("/old-style")
async def old_style(user: AuthenticatedUser = Depends(require_auth(auth))):
    return {"user": user.user_id}

# NEW - recommended
@app.get("/new-style")
async def new_style(ctx: RequestContext = Depends(require_context(auth))):
    return {"user": ctx.user.user_id, "tenant": ctx.tenant_id}
```

---

## Type Annotations for Clean Code

```python
from typing import Annotated
from fastapi import Depends

# Define once
Auth = Annotated[RequestContext, Depends(require_context(auth))]
AuthWithPermission = Annotated[
    RequestContext,
    Depends(require_context(auth, permission="users:read"))
]

# Use cleanly
@app.get("/users")
async def list_users(ctx: Auth):
    return {"users": [...]}

@app.get("/admin")
async def admin(ctx: AuthWithPermission):
    return {"admin": True}
```
