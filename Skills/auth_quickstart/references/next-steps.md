# Next Steps After Scaffolding

## Add More Permissions

The starter template ships with `read`, `write`, `delete`, `admin`, and `cross_tenant`. Real services need more granularity.

**Identify what to add:**
1. Read every route handler — what can users DO?
2. Map actions to verbs: `read`, `write`, `create`, `delete`, `execute`, `scale`
3. Identify resources (the nouns): items, reports, uploads, configs
4. Combine: `myservice.create.reports`, `myservice.execute.jobs`

**Add to `.permissions.json`:**
```json
{
  "id": "myservice.create.reports",
  "name": "Create Reports",
  "description": "Generate new reports",
  "risk_level": "medium",
  "cost_impact": false,
  "default_grant": true
}
```

**Add matching type alias in `auth.py`:**
```python
ReportCreator = Annotated[
    AuthenticatedUser,
    Depends(require_permission(auth, "myservice.create.reports", check=belongs_to_org)),
]
```

## Add Check Callbacks

Check callbacks answer: "Even with the right permission, should this user be allowed right now?"

```python
def is_not_suspended(user: AuthenticatedUser, request: Request) -> bool:
    # Check against your DB or user metadata
    return not getattr(user, "suspended", False)

def is_within_quota(user: AuthenticatedUser, request: Request) -> bool:
    # Check usage limits
    return True  # Implement with your quota system

# Combine checks — all must pass
ResourceCreator = Annotated[
    AuthenticatedUser,
    Depends(require_permission(
        auth, "myservice.create.items",
        checks=[belongs_to_org, is_not_suspended, is_within_quota],
        check_mode="all",
    )),
]
```

## Add Phase 2 Ownership Verification

Any route with a resource ID in the path needs Phase 2. The template's `verify_resource_access` handles this:

```python
@router.get("/{item_id}")
async def get_item(item_id: str, user: Reader):
    item = await db.get(item_id)
    if not item:
        raise HTTPException(404, "Item not found")  # 404 before 403
    verify_resource_access(item, user)  # Phase 2
    return item
```

**NOT needed for:** create routes (ownership assigned at creation), list routes (scoped by `get_user_filter()`).

## Register With Auth Service

Copy the registration script from the auth_fastapi_skill:
```bash
cp path/to/auth_fastapi_skill/scripts/register-service-permissions.sh ./scripts/
./scripts/register-service-permissions.sh
```

Or see the [auth_fastapi_skill registration reference](../../auth_fastapi_skill/references/registration.md) for details.

## Add Multi-Tenancy

For tenant-scoped routes with org hierarchy:

```python
from ab0t_auth.tenant import TenantConfig, require_tenant

tenant_config = TenantConfig(
    enforce_tenant_isolation=True,
    enable_org_hierarchy=True,
)

@app.get("/tenants/{tenant_id}/data")
async def tenant_data(tenant_id: str, ctx=Depends(require_tenant(auth, config=tenant_config))):
    return {"tenant": ctx.tenant_id}
```

## Add Middleware (Optional)

For blanket auth on all routes except health/docs:

```python
from ab0t_auth.middleware import AuthMiddleware

app.add_middleware(
    AuthMiddleware,
    guard=auth,
    exclude_paths=["/health", "/docs", "/openapi.json"],
)
```

## Connect to Database

The template uses placeholder comments for DB calls. Wire up your ORM/driver:

1. Add `sqlalchemy` or `motor` or your driver to `requirements.txt`
2. Create `app/db.py` with connection setup
3. Replace `# TODO: query DB` comments with real queries
4. Use `get_user_filter(user)` to scope all list queries

## Testing with Auth Bypass

For local development and tests:

```bash
AB0T_AUTH_DEBUG=true AB0T_AUTH_BYPASS=true uvicorn app.main:app --reload
```

Both env vars must be `"true"`. Bypass creates a synthetic user with configurable permissions:

```bash
AB0T_AUTH_BYPASS_PERMISSIONS=myservice:read,myservice:write
AB0T_AUTH_BYPASS_ROLES=myservice-user
```

## Production Checklist

- [ ] `AB0T_AUTH_DEBUG=false` and `AB0T_AUTH_BYPASS=false`
- [ ] `AB0T_AUTH_PERMISSION_CHECK_MODE=server` for instant revocation
- [ ] `AB0T_AUTH_AUDIENCE` set to your service slug
- [ ] `.permissions.json` registered via registration script
- [ ] `credentials/` in `.gitignore`
- [ ] Phase 2 on every route with a resource ID path param
- [ ] `get_user_filter()` on every list/search query
- [ ] `cross_tenant` NOT implied by `admin`
