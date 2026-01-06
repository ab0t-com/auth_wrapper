# Architecture Discussion: Tenant Integration

## Question

> I have not approved it yet, are those improvements worth it? Like we have an org id, service accounts and nested orgs, each organization has many organizations within it.

---

## Analysis: Is the Unified Context Worth It?

### Your Architecture

```
Tenant (Company)
└── Organization (root)
    ├── Sub-Org A
    │   ├── Sub-Org A1
    │   └── Sub-Org A2
    └── Sub-Org B
        └── Sub-Org B1

+ Service Accounts (non-human identities)
```

### Current Approach: Separate Modules

**Pros:**
- Simple to understand
- Users who don't need tenant features don't pay for complexity
- Easier to test in isolation
- Service accounts can use auth without tenant logic

**Cons:**
- Redundant authentication calls (minor performance hit)
- Two objects to manage (`AuthenticatedUser` + `TenantContext`)

### Proposed Unified Approach

**Pros:**
- Single dependency, single context object
- One auth call per request
- Cleaner API

**Cons:**
- More complexity upfront
- Service accounts might not fit the tenant model
- Harder to use auth-only without tenant baggage

---

## Recommendation: **Keep Them Separate**

For your use case with nested orgs and service accounts, the current modular approach is actually better because:

1. **Service accounts are different** - They may authenticate at org level without being "tenants"

2. **Nested orgs add complexity** - You might need to query the org hierarchy from the backend, not just validate tokens

3. **Flexibility** - Some endpoints need auth only, some need tenant, some need both

### What Would Actually Help

Instead of unifying, I'd suggest **improving the tenant module**:

```python
# Better: Composable dependencies that share auth
@app.get("/orgs/{org_id}/data")
async def get_data(
    org_id: str,
    user: AuthenticatedUser = Depends(require_auth(auth)),
    org: Organization = Depends(require_org_access(auth, org_id)),  # Uses cached user
):
    ...

# For service accounts
@app.get("/service/internal")
async def internal(
    service: ServiceAccount = Depends(require_service_account(auth)),
):
    ...
```

**Future improvements to consider:**
1. Better org hierarchy validation (parent/child access rules)
2. Service account support
3. Caching the auth result so tenant doesn't re-authenticate
