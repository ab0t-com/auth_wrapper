# Implementation Details Reference

## Full Auth Module Pattern (app/auth.py)

```python
"""
Authentication & Authorization for Your Service.

Uses ab0t-auth with:
- Global AuthGuard configuration
- Multi-tenant isolation via TenantConfig
- Permission-based access control
- Check callbacks for resource-level ownership verification
"""
from typing import Annotated
from fastapi import Depends, Request

from ab0t_auth import (
    AuthGuard, AuthenticatedUser,
    require_auth, require_permission, require_any_permission, optional_auth,
)
from ab0t_auth.middleware import register_auth_exception_handlers
from ab0t_auth.errors import PermissionDeniedError
from ab0t_auth.tenant import TenantConfig

from .config import settings


# =============================================================================
# Global Configuration
# =============================================================================

auth = AuthGuard(
    auth_url=settings.AB0T_AUTH_URL,
    audience=settings.AB0T_AUTH_AUDIENCE,
    debug=settings.AB0T_AUTH_DEBUG,
    permission_check_mode=settings.AB0T_AUTH_PERMISSION_CHECK_MODE,
)

tenant_config = TenantConfig(
    enforce_tenant_isolation=True,       # Every resource belongs to exactly one org
    enforce_org_isolation=True,          # Strict — no accidental cross-org leaks
    allow_cross_tenant_admin=True,       # Platform support staff need cross-org access
    cross_tenant_permission="myservice.cross_tenant",  # Must match .permissions.json
    enable_org_hierarchy=True,           # Parent orgs can manage child org resources
    allow_ancestor_access=True,          # Parent org is the billing/management entity
    allow_descendant_access=False,       # Child orgs should not see parent's resources
)
```

### AuthGuard Parameters

| Parameter | Purpose |
|-----------|---------|
| `auth_url` | Auth service URL for JWKS fetch and server-side permission checks |
| `audience` | Only accept JWTs with this audience claim. Rejects tokens meant for other services. |
| `debug` | Enable verbose logging. When combined with `AB0T_AUTH_BYPASS=true`, enables auth bypass. |
| `permission_check_mode` | `"client"` = check JWT claims locally, `"server"` = call auth service API |

### TenantConfig

```python
tenant_config = TenantConfig(
    enforce_tenant_isolation=True,
    enforce_org_isolation=True,
    allow_cross_tenant_admin=True,
    cross_tenant_permission="resource.cross_tenant",
    enable_org_hierarchy=True,
    allow_ancestor_access=True,
    allow_descendant_access=False,
)
```

**How to configure for your service:** Most services want both `enforce_tenant_isolation` and `enforce_org_isolation` as `True`. Hierarchy settings depend on parent/child org relationships. If not applicable, set both `allow_ancestor_access` and `allow_descendant_access` to `False`.

## Check Callbacks

Functions with signature `(user: AuthenticatedUser, request: Request) -> bool`. Run AFTER permission verification, BEFORE route handler. Return `True` to allow, `False` to deny.

**Why needed beyond permissions?** Permissions answer "CAN this user do this type of action?" but not "SHOULD they right now?" A user might have the permission but be suspended, over quota, or requesting resources in someone else's org.

```python
def belongs_to_org(user: AuthenticatedUser, request: Request) -> bool:
    """
    User must belong to the org specified in path or query.
    Platform admins with cross_tenant bypass this.

    WHY: Used for operations where org membership is sufficient —
    reading, creating, listing. You don't need to own a specific resource
    to list resources in your org or create a new one.
    """
    org_id = request.path_params.get("org_id") or request.query_params.get("org_id")
    if not org_id:
        return True
    return user.org_id == org_id or user.has_permission("myservice.cross_tenant")


def is_resource_owner(user: AuthenticatedUser, request: Request) -> bool:
    """
    User must own the resource OR be admin in same org.

    WHY: Used for mutation operations (write, delete, scale, execute).
    Unlike belongs_to_org, this ensures you can only modify YOUR resources,
    not just any resource in your org. Admins bypass because they manage
    all resources in the org.
    """
    user_id = request.path_params.get("user_id")
    if not user_id:
        return True
    return user.user_id == user_id or user.has_permission("myservice.admin")


def is_not_suspended(user: AuthenticatedUser, request: Request) -> bool:
    """
    Suspended users cannot create/write/delete.

    WHY: Suspension is an account-level override. A suspended user keeps their
    permissions (so reactivation is instant) but cannot mutate state or incur costs.
    Read operations are still allowed.
    """
    return not user.metadata.get("suspended", False)


def is_within_quota(user: AuthenticatedUser, request: Request) -> bool:
    """Preliminary quota check. Catches over-quota users before business logic."""
    if user.metadata.get("quota_exceeded", False):
        return False
    return True
```

### Using Check Callbacks

**Single check** — `check=callback`:
```python
ResourceReader = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.read", check=belongs_to_org)
)]
```

**Multiple checks (ALL must pass)** — `checks=[...], check_mode="all"`:
```python
ResourceAllocator = Annotated[AuthenticatedUser, Depends(
    require_any_permission(
        auth,
        "resource.create.allocations",
        "resource.create.deployments",
        checks=[belongs_to_org, is_not_suspended, is_within_quota],
        check_mode="all",
    )
)]
```

## Complete Type Alias Listing

### Basic Auth

```python
# Any authenticated user (JWT or API key)
CurrentUser = Annotated[AuthenticatedUser, Depends(require_auth(auth))]

# Optional auth — returns None if not authenticated
OptionalUser = Annotated[AuthenticatedUser | None, Depends(optional_auth(auth))]
```

### Permission-Based with Checks

```python
# Read operations — must be in same org
ResourceReader = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.read", check=belongs_to_org)
)]

# Create operations — org check + not suspended + within quota
ResourceAllocator = Annotated[AuthenticatedUser, Depends(
    require_any_permission(
        auth, "resource.create.allocations", "resource.create.deployments",
        checks=[belongs_to_org, is_not_suspended, is_within_quota], check_mode="all",
    )
)]

# Write/update — must own resource or be admin
ResourceWriter = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.write", check=is_resource_owner)
)]

# Delete/terminate — must own resource or be admin
ResourceTerminator = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.delete", check=is_resource_owner)
)]

# Execute commands — must own resource, not suspended
ResourceExecutor = Annotated[AuthenticatedUser, Depends(
    require_any_permission(
        auth, "resource.execute.instances", "resource.execute.containers",
        checks=[is_resource_owner, is_not_suspended], check_mode="all",
    )
)]

# Scale operations — must own resource or be admin
ResourceScaler = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.scale", check=is_resource_owner)
)]

# Admin — org-level access
ResourceAdmin = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.admin", check=belongs_to_org)
)]

# Platform admin — cross-tenant access (no org check)
PlatformAdmin = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.admin.config")
)]
```

### Specialized Access

```python
# SSH/console access — explicit permission, not default-granted
SSHUser = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.ssh.instances",
        checks=[is_resource_owner, is_not_suspended], check_mode="all")
)]

# Log viewer
LogViewer = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.logs", check=is_resource_owner)
)]

# Metrics viewer
MetricsViewer = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.metrics", check=is_resource_owner)
)]

# Workflow executor — org check + not suspended
WorkflowExecutor = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.execute.workflows",
        checks=[belongs_to_org, is_not_suspended], check_mode="all")
)]

# Workflow creator
WorkflowCreator = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.create.workflows", check=belongs_to_org)
)]

# Cost admin — org-level cost management
CostAdmin = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.admin.costs", check=belongs_to_org)
)]

# Cost reader
CostReader = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.read.costs", check=belongs_to_org)
)]

# Quota admin
QuotaAdmin = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.admin.quotas", check=belongs_to_org)
)]

# Quota reader
QuotaReader = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.read.quotas", check=belongs_to_org)
)]
```

### Type Alias Selection Table

| Operation | Type Alias | Permission | Checks |
|-----------|------------|------------|--------|
| View resources | `ResourceReader` | `resource.read` | belongs_to_org |
| Create/deploy | `ResourceAllocator` | `resource.create.*` | belongs_to_org, not_suspended, within_quota |
| Update/modify | `ResourceWriter` | `resource.write` | is_resource_owner |
| Delete/terminate | `ResourceTerminator` | `resource.delete` | is_resource_owner |
| Run commands | `ResourceExecutor` | `resource.execute.*` | is_resource_owner, not_suspended |
| Scale up/down | `ResourceScaler` | `resource.scale` | is_resource_owner |
| View logs | `LogViewer` | `resource.logs` | is_resource_owner |
| View metrics | `MetricsViewer` | `resource.metrics` | is_resource_owner |
| SSH access | `SSHUser` | `resource.ssh.instances` | is_resource_owner, not_suspended |
| Org admin | `ResourceAdmin` | `resource.admin` | belongs_to_org |
| Platform admin | `PlatformAdmin` | `resource.admin.config` | (none — cross-tenant) |
| View costs | `CostReader` | `resource.read.costs` | belongs_to_org |
| Manage costs | `CostAdmin` | `resource.admin.costs` | belongs_to_org |

## Phase 2 Verification Functions

Phase 1 (dependency) checks permission and basic conditions. Phase 2 checks access to a **specific resource** after fetching it from the database.

**Why can't Phase 1 handle everything?** Phase 1 runs before your route handler — before any database query. It knows who the user is and what permissions they have, but not which resource they're accessing. Only after you fetch the allocation do you know its `org_id` and `user_id`.

**When to think about Phase 2:** Any route that takes a resource ID in the path (e.g., `/allocations/{allocation_id}`). Routes that create new resources or list with filters do NOT need it.

```python
def verify_allocation_access(allocation, user: AuthenticatedUser) -> None:
    """
    Verify user can access this specific allocation.
    Rules:
    1. Owner can always access their allocation
    2. Admin in same org can access org's allocations
    3. Platform admin (cross_tenant) can access any allocation
    """
    if allocation.user_id == user.user_id:
        return
    if user.has_permission("resource.admin") and allocation.org_id == user.org_id:
        return
    if user.has_permission("resource.cross_tenant"):
        return
    raise PermissionDeniedError(
        "Access denied to this allocation",
        required_permission="resource.admin",
    )


def verify_org_access(resource_org_id: str, user: AuthenticatedUser) -> None:
    """Verify user can access resources in this org."""
    if user.org_id == resource_org_id:
        return
    if user.has_permission("resource.cross_tenant"):
        return
    raise PermissionDeniedError(
        "Access denied - different organization",
        required_permission="resource.cross_tenant",
    )


def verify_instance_access(instance, allocation, user: AuthenticatedUser) -> None:
    """Instance access inherits from allocation access."""
    verify_allocation_access(allocation, user)
```

### Critical: Always Check for None Before Phase 2

```python
# WRONG — crashes if allocation is None
allocation = await db.get_allocation(allocation_id)
verify_allocation_access(allocation, user)

# RIGHT — 404 before 403
allocation = await db.get_allocation(allocation_id)
if not allocation:
    raise HTTPException(404, "Allocation not found")
verify_allocation_access(allocation, user)
```

## Database Query Scoping (Multi-Tenant)

**Why filter at the database layer?** Phase 2 only works for single-resource access. List endpoints return many resources — you can't run `verify_allocation_access()` on hundreds of results. Scope the query so the database only returns what the user can see.

```python
def get_user_filter(user: AuthenticatedUser) -> dict:
    """
    Three tiers:
    - Regular users see only their own resources
    - Org admins see everyone's resources in their org
    - Platform admins see everything across all orgs
    """
    if user.has_permission("resource.cross_tenant"):
        return {}
    if user.has_permission("resource.admin"):
        return {"org_id": user.org_id}
    return {"user_id": user.user_id, "org_id": user.org_id}
```

Usage:
```python
@router.get("/allocations")
async def list_allocations(user: ResourceReader):
    filters = get_user_filter(user)
    return await db.list_allocations(**filters)
```

## main.py Integration

Two things must happen:

1. **Lifespan** — AuthGuard fetches JWKS keys on startup and caches them. Without initialization, the first request fails.
2. **Exception handlers** — Without these, auth errors bubble up as unhandled 500s instead of structured 401/403 JSON responses.

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from .auth import auth, register_auth_exception_handlers

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with auth.lifespan():
        # ... other startup code ...
        yield
        # ... shutdown code ...

app = FastAPI(title="My Service", lifespan=lifespan)
register_auth_exception_handlers(app)
```

## Migration from Old User Model

| Old (`app/models/auth.py`) | New (`AuthenticatedUser`) |
|---|---|
| `user.id` | `user.user_id` |
| `user.name` | `user.metadata.get("name")` |
| `user.permissions` (list) | `user.permissions` (tuple, immutable) |
| `user.is_active` | `not user.metadata.get("suspended", False)` |
| — | `user.has_permission("resource.admin")` |
| — | `user.has_role("resource-admin")` |
| — | `user.auth_method` |
