---
name: ab0t-auth-fastapi
description: Integrate ab0t-auth authentication and authorization into FastAPI microservices. Use when creating a new service that needs auth, migrating from legacy auth patterns, designing permissions for a service, protecting routes with permission-based access control, implementing multi-tenant isolation, registering a service with the auth system, creating API keys for inter-service communication, or debugging auth failures (401/403). Covers the full lifecycle from permission design through .permissions.json, service registration via shell script, auth module implementation (AuthGuard, type aliases, check callbacks, Phase 2 verification), route protection patterns, and testing.
---

# AB0T-AUTH FastAPI Integration

Integrate `ab0t-auth` into FastAPI services. The Resource Service (`resource/output/app/auth.py`) is the canonical reference implementation.

## Agentic Workflow

When integrating auth into a new service, reason about **your** codebase at each stage:

1. **Audit routes** — read every route handler. Ask: "What can users DO? What data can they see? What can they modify or delete?"
2. **Map operations to verbs** — each handler implies an action (read, write, create, delete, execute, scale). Group them.
3. **Identify resources** — what are the nouns? (allocations, instances, jobs, reports). These become permission resources.
4. **Decide ownership granularity** — which operations need resource-level ownership checks vs org-level? Mutations need ownership; reads need org membership.
5. **Work backwards from attacks** — for each route: "What if User A calls this with User B's resource ID?" That determines Phase 2 needs.

## How Auth Works

```
User Request → ab0t-auth library (in your service)
  1. Extract token (Authorization: Bearer / X-API-Key)
  2. Validate JWT via JWKS
  3. Check permission (client-side or server-side)
  4. Run check callbacks (belongs_to_org, is_not_suspended, etc.)
  5. Return AuthenticatedUser
       → Your route handler
           6. Fetch resource from DB
           7. Phase 2: verify_resource_access()
           8. Process request
```

**Two token types:** JWT (`Authorization: Bearer <token>`, expires) and API Key (`X-API-Key: ab0t_sk_...`, revocable).

## Three Security Levels

1. **Authentication** — "Who are you?" (JWT/API key validation)
2. **Authorization** — "Do you have permission?" (permission check)
3. **Ownership** — "Is this YOUR resource?" (Phase 2 verification)

All three must pass. Why three? Authentication proves identity but not capability. Authorization proves capability but not scope — an admin in Org A shouldn't touch Org B. Ownership binds permission to a specific resource.

## Permission Design

**Format:** `{service}.{action}.{resource}` — e.g., `resource.create.allocations`

Every service has a `.permissions.json` in its root. It's the single source of truth consumed by the shell registration script, the auth service API, and your Python code. See `assets/permissions-template.json` for the full production example.

**Agentic thinking:** Scan your route handlers, categorize them:
- Return data without side effects → `read`
- Modify existing records → `write`
- Create new records (cost/resources) → `create`
- Permanently remove data → `delete`
- Run user-provided code → `execute`

Then look at domain models — each top-level model is a resource.

**Key principles:**
- Not every action×resource needs a permission — only define what routes actually check
- `admin` uses `implies` to bundle lower permissions — avoids granting 15 individually
- `cross_tenant` is NEVER implied by admin, never default-granted (conscious separate grant)
- `ssh` defaults to false — interactive access bypasses structured command logging

→ **Full schema, actions table, roles, design principles:** See [references/permissions-design.md](references/permissions-design.md)

## Service Registration

The `scripts/register-service-permissions.sh` script registers your service with the Auth Service. It is **idempotent** — safe to run multiple times. It reads from `.permissions.json`.

**6 steps:** Create admin account → Create org → Login with org context → Register permissions → Create API key → (Optional) proxy registration

**Why a shell script?** Registration happens before your service starts (deployment, CI/CD, bare machine). Shell needs only `curl` and `jq`.

→ **Full registration details, granting permissions, API keys:** See [references/registration.md](references/registration.md)

## Implementation

### Install

```
# requirements.txt
git+https://github.com/ab0t-com/auth_wrapper.git
```

### Config (app/config.py)

```python
class Settings(BaseSettings):
    AB0T_AUTH_URL: str = "https://auth.service.ab0t.com"
    AB0T_AUTH_AUDIENCE: str = "your-service-slug"  # From credentials/{service}.json → service_audience
    AB0T_AUTH_DEBUG: bool = False
    AB0T_AUTH_BYPASS: bool = False  # DEVELOPMENT ONLY — requires DEBUG=true too
    AB0T_AUTH_AUDIENCE_SKIP: bool = False  # TEMPORARY transition flag
    AB0T_AUTH_PERMISSION_CHECK_MODE: str = "server"  # "client" or "server"
```

**Why `server` mode?** Revoking a compromised user's access takes effect immediately — not 15 min later when their JWT expires. The extra API call per request is worth the security guarantee.

### Auth Module (app/auth.py)

**Why one centralized module?** Auth config must be consistent across all routes. One file = one import = one audit point.

```python
from ab0t_auth import AuthGuard, AuthenticatedUser, require_auth, require_permission, require_any_permission, optional_auth
from ab0t_auth.middleware import register_auth_exception_handlers
from ab0t_auth.errors import PermissionDeniedError
from ab0t_auth.tenant import TenantConfig
from .config import settings

auth = AuthGuard(
    auth_url=settings.AB0T_AUTH_URL,
    audience=settings.AB0T_AUTH_AUDIENCE,
    debug=settings.AB0T_AUTH_DEBUG,
    permission_check_mode=settings.AB0T_AUTH_PERMISSION_CHECK_MODE,
)
```

### Check Callbacks

Functions `(user, request) -> bool` that run AFTER permission check, BEFORE route handler.

**Why needed?** Permissions answer "CAN this user do this action type?" but not "SHOULD they right now?" A user might have the permission but be suspended, over quota, or in the wrong org.

**How to decide which callbacks:** For each type alias, ask "What could go wrong even with the right permission?"
- Wrong org → `belongs_to_org`
- Someone else's resource → `is_resource_owner`
- Account suspended → `is_not_suspended`
- Over limits → `is_within_quota`

### Type Aliases

Replace `Depends(get_current_user)` — encode permission + checks in the function signature. Self-documenting security.

```python
# Read — org membership sufficient
ResourceReader = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.read", check=belongs_to_org)
)]

# Create — org + not suspended + within quota
ResourceAllocator = Annotated[AuthenticatedUser, Depends(
    require_any_permission(auth, "resource.create.allocations", "resource.create.deployments",
        checks=[belongs_to_org, is_not_suspended, is_within_quota], check_mode="all")
)]

# Write/delete/scale — must own resource
ResourceWriter = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.write", check=is_resource_owner)
)]
```

**Choosing the right alias:** Ask these questions:
1. Read-only or mutates state? → Read gets `belongs_to_org`; mutation gets `is_resource_owner`
2. Creates something new (cost)? → Add `is_not_suspended` + `is_within_quota`
3. Accesses specific existing resource? → Need Phase 2 in route body
4. Org-wide admin operation? → `ResourceAdmin` with `belongs_to_org`
5. No org boundary? → `PlatformAdmin` with no checks

### Phase 2 Verification

Phase 1 (dependency) runs before your route — it doesn't know WHICH resource. Phase 2 runs after DB fetch when you know the resource's `org_id` and `user_id`.

```python
def verify_allocation_access(allocation, user: AuthenticatedUser) -> None:
    if allocation.user_id == user.user_id: return          # Owner
    if user.has_permission("resource.admin") and allocation.org_id == user.org_id: return  # Org admin
    if user.has_permission("resource.cross_tenant"): return  # Platform admin
    raise PermissionDeniedError("Access denied", required_permission="resource.admin")
```

**When needed:** Any route with a resource ID in the path (`/allocations/{id}`). NOT needed for create (assigns ownership) or list (scoped by `get_user_filter()`).

### Database Query Scoping

```python
def get_user_filter(user: AuthenticatedUser) -> dict:
    if user.has_permission("resource.cross_tenant"): return {}           # See everything
    if user.has_permission("resource.admin"): return {"org_id": user.org_id}  # Org-wide
    return {"user_id": user.user_id, "org_id": user.org_id}            # Own only
```

### main.py Integration

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    async with auth.lifespan():  # JWKS fetch, cache setup
        yield

app = FastAPI(title="My Service", lifespan=lifespan)
register_auth_exception_handlers(app)  # Proper 401/403 JSON responses
```

→ **Full check callbacks, all 19 type aliases, TenantConfig, Phase 2 functions:** See [references/implementation-details.md](references/implementation-details.md)

## Route Protection

Choose the pattern by asking:
- Returns a collection? → **Pattern 1** (list + filter)
- Fetches specific resource by ID? → **Pattern 2** (get + Phase 2)
- Creates something new? → **Pattern 3** (create, no Phase 2 needed)
- Deletes/terminates? → **Pattern 4** (destructive + Phase 2)
- Nested resource (instance in allocation)? → **Pattern 5** (verify parent first)
- Org-wide admin action? → **Pattern 6** (admin-only)
- Works without auth? → **Pattern 7** (optional auth)

→ **All 7 patterns with code, route table by module:** See [references/route-patterns.md](references/route-patterns.md)

## File Checklist

When integrating, create/modify in this order (each depends on previous):

| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `.permissions.json` | Create | Permission definitions, roles, multi-tenancy config |
| 2 | `register-service-permissions.sh` | Create | Registration script (copy from `scripts/`) |
| 3 | `credentials/` | Gitignore | Generated by registration script |
| 4 | `app/config.py` | Add settings | `AB0T_AUTH_URL`, `AB0T_AUTH_AUDIENCE`, etc. |
| 5 | `app/auth.py` | Create | AuthGuard, TenantConfig, callbacks, type aliases, Phase 2 |
| 6 | `app/main.py` | Modify | `auth.lifespan()` + `register_auth_exception_handlers(app)` |
| 7 | `app/api/*.py` | Modify | Replace old auth with type aliases, add Phase 2 |
| 8 | `app/dependencies.py` | Clean up | Remove old `get_current_user` functions |
| 9 | `requirements.txt` | Add line | `git+https://github.com/ab0t-com/auth_wrapper.git` |

## Common Mistakes

1. **Forgetting Phase 2** — any authenticated user reads any resource by ID. Audit every route with a resource ID path param.
2. **Unfiltered list queries** — `list_allocations()` without `get_user_filter()` returns all orgs.
3. **Wrong permission level** — `ResourceWriter` for delete (should be `ResourceTerminator`). Write=modify, delete=remove.
4. **None before verify** — `verify_allocation_access(None, user)` → `AttributeError`. Always 404 before 403.
5. **`user.id` vs `user.user_id`** — old model uses `.id`, library uses `.user_id`. Silently returns `None`.
6. **No audience set** — tokens from billing service accepted by resource service.
7. **Stale API key permissions** — re-running registration reuses existing keys without updating permissions. Use `PUT /api-keys/{id}`.

## Reference Files

| File | Content | When to read |
|------|---------|--------------|
| [references/permissions-design.md](references/permissions-design.md) | Full .permissions.json schema, actions table, roles, design principles | Designing permissions for a new service |
| [references/registration.md](references/registration.md) | Registration script details, granting/revoking permissions, API keys | Registering service or managing permissions |
| [references/implementation-details.md](references/implementation-details.md) | All check callbacks, 19 type aliases, Phase 2 functions, TenantConfig | Building app/auth.py |
| [references/route-patterns.md](references/route-patterns.md) | All 7 route protection patterns with code, route-module table | Protecting routes |
| [references/library-api.md](references/library-api.md) | Core imports, AuthenticatedUser, AuthGuard, permission functions, errors | Looking up function signatures (quick reference) |
| [references/auth-wrapper-library-full.md](references/auth-wrapper-library-full.md) | Complete ab0t-auth library reference — all modules, all signatures, decorators, middleware, JWT utilities, logging, tenant module | Deep library lookup, advanced features, decorator/middleware patterns |
| [references/testing-troubleshooting.md](references/testing-troubleshooting.md) | Security testing, auth bypass, troubleshooting table, debug checklist | Testing or debugging auth issues |
| [references/migration-guide-full.md](references/migration-guide-full.md) | Full migration guide from legacy auth to ab0t-auth — step-by-step migration patterns, before/after examples | Migrating an existing service from old auth patterns |
| [references/auth-service-api.md](references/auth-service-api.md) | Auth service REST API — login, register, validate tokens/keys, grant/revoke permissions, manage API keys, orgs, quotas | Testing auth flows, granting permissions, creating API keys, debugging with curl |
| [references/org-hierarchy-guide.md](references/org-hierarchy-guide.md) | Org hierarchy, nested orgs, teams, service accounts, delegation, cross-service mesh, decision trees, worked examples | Confused about how orgs/teams/hierarchy work, designing multi-tenant structure, setting up inter-service auth |
| [references/org-hierarchy-guide-additional_detail.md](references/org-hierarchy-guide-additional_detail.md) | Deep-dive into "everything is an org" model — orgs as universal primitive, org types (platform_service, customer, personal), service orgs, nested orgs, teams-as-orgs, registration flow dissected, permission scoping, delegation, cross-org mesh, Zanzibar, worked scenarios, common agent mistakes | Need the full mental model for how orgs/teams/users/services all map to the same primitive, or designing complex multi-tenant architectures |
| [references/auth-service-organization-guide.md](references/auth-service-organization-guide.md) | Auth service enterprise features — OAuth 2.1, PKCE, organization management, super-admin, delegation, federation | Setting up OAuth providers, org hierarchy, enterprise SSO |
