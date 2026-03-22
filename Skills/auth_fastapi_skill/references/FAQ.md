# AB0T-AUTH Frequently Asked Questions

Organized by customer journey stage. Each answer is wrapped in grepable delimiters.
Search with: `grep -A 20 'FAQ:keyword' FAQ.md`

---

## Section 1: Getting Started & Overview

### Q: What is ab0t-auth and why can't I just validate JWTs myself?

<!-- FAQ:what-is-ab0t-auth -->
ab0t-auth is a wrapper library that handles JWT validation, API key authentication, permission checking, multi-tenant isolation, and check callbacks in a single package. You *could* validate JWTs yourself with PyJWT, but you'd need to:
- Fetch and cache JWKS keys, handle rotation
- Support both JWT and API key auth
- Build permission checking (client-side and server-side)
- Build multi-tenant isolation
- Handle token expiry, revocation, audience validation
- Return proper 401/403 JSON error responses

ab0t-auth does all of this with a single `AuthGuard` instance and type aliases. It's the difference between writing 400 lines of auth boilerplate or importing a library and writing 50 lines of configuration.
<!-- /FAQ -->

### Q: Do I need to run my own auth service?

<!-- FAQ:auth-service-hosting -->
No. The central auth service runs at `https://auth.service.ab0t.com` and is shared across all platform services. Your service connects to it — you don't deploy your own. The ab0t-auth library in your service talks to this central auth service for JWKS keys, token validation, and server-side permission checks.
<!-- /FAQ -->

### Q: What's the absolute minimum I need to get auth working?

<!-- FAQ:minimum-setup -->
Four things:
1. `pip install git+https://github.com/ab0t-com/auth_wrapper.git`
2. Create an `AuthGuard` instance with `auth_url`
3. Add `async with auth.lifespan()` to your FastAPI lifespan
4. Use `Depends(require_auth(auth))` on a route

That gives you authentication. For authorization (permissions), you also need `.permissions.json`, the registration script, and type aliases. See the SKILL.md file checklist for the full sequence.
<!-- /FAQ -->

### Q: What's the difference between authentication, authorization, and ownership?

<!-- FAQ:authn-authz-ownership -->
- **Authentication (AuthN)**: "Who are you?" — validates the JWT or API key. Result: you know it's user X.
- **Authorization (AuthZ)**: "What can you do?" — checks if user X has `resource.create.allocations`. Result: you know they're allowed to create allocations.
- **Ownership**: "Is this YOUR resource?" — checks if user X owns allocation ABC-123. Result: you know they're not accessing someone else's stuff.

All three are required. A valid user with the right permission can still be denied if the resource belongs to someone else in a different org.
<!-- /FAQ -->

### Q: How do tokens work? JWT vs API key?

<!-- FAQ:token-types -->
**JWT tokens** are short-lived (15-60 min), issued after login, and carry claims (user_id, org_id, permissions) in the token itself. They're used for user sessions and web apps. Send via `Authorization: Bearer <token>` header.

**API keys** are long-lived, don't expire (but can be revoked), and are validated by calling the auth service. They're used for scripts, CI/CD, service-to-service calls, and testing. Send via `X-API-Key: ab0t_sk_live_...` header.

The ab0t-auth library handles both transparently — your route code doesn't need to know which was used. The `user.auth_method` field tells you if you need to know (JWT, API_KEY, or BYPASS).
<!-- /FAQ -->

---

## Section 2: Permission Design & Strategy

### Q: How do I figure out what permissions my service needs?

<!-- FAQ:designing-permissions -->
Walk through every route handler in your service and ask two questions:
1. **What verb is this?** — GET = read, POST = create/execute, PUT/PATCH = write, DELETE = delete
2. **What noun does it act on?** — allocations, instances, reports, config

The verbs become your `actions`, the nouns become your `resources`. Then ask: "Does every user need this, or only some?" That determines `default_grant` and `risk_level`.

Example thought process for a billing service:
- `GET /invoices` → action: read, resource: invoices → `billing.read.invoices`, low risk, default yes
- `POST /invoices/{id}/refund` → action: write, resource: invoices → `billing.write.invoices`, high risk, default no
- `GET /reports/revenue` → action: read, resource: reports → `billing.read.reports`, medium risk, default no (only finance team)
<!-- /FAQ -->

### Q: What's the difference between `resource.read` and `resource.read.allocations`?

<!-- FAQ:permission-granularity -->
`resource.read` is a broad permission — read anything. `resource.read.allocations` is a scoped permission — read only allocations. Use broad permissions when you want simplicity (one read permission for everything). Use scoped permissions when different resources need different access levels.

The Resource Service uses both: `resource.read` grants read access to all resources, while `resource.read.costs` is separate because cost data might be restricted to finance users even though everyone can read allocations.

Rule of thumb: start broad, add scoped permissions only when you discover real access control needs.
<!-- /FAQ -->

### Q: Why can't I just use roles instead of individual permissions?

<!-- FAQ:roles-vs-permissions -->
You should use both. Roles are for user management (assigning bundles). Permissions are for enforcement (checking in code). Here's why:

- Roles make administration easy: "Make Jane a resource-admin" instead of granting 15 permissions individually.
- Permissions make enforcement precise: your code checks `resource.delete`, not "is admin" — because admins in different services have different capabilities.
- Roles can change without code changes. If you add a new permission, you update the role definition in `.permissions.json` and re-register. No code change needed.

Think of roles as the HR-facing concept and permissions as the engineering-facing concept.
<!-- /FAQ -->

### Q: Should every route have its own permission?

<!-- FAQ:permission-per-route -->
No. Group routes by the operation they perform, not by URL. Multiple routes can share one permission:

- `GET /allocations`, `GET /allocations/{id}`, `GET /allocations/{id}/metrics` → all use `resource.read`
- `POST /allocations/{id}/scale`, `PUT /allocations/{id}/instances` → both use `resource.write` or `resource.scale`

Create a new permission only when you need to grant different access. If everyone who can read allocations should also be able to read instances, one `resource.read` permission is fine.
<!-- /FAQ -->

### Q: What happens when I add new permissions later?

<!-- FAQ:adding-permissions-later -->
Three steps:
1. Add the new permission to `.permissions.json` (actions, resources, and/or permissions array)
2. Re-run `register-service-permissions.sh` — it re-registers all permissions with the auth service (idempotent)
3. **Important**: Existing API keys are NOT automatically updated. You must explicitly update them via `PUT /api-keys/{key_id}` with the new permissions.

Existing users with roles that don't include the new permission won't have it. You either update the role definition and re-register, or grant individually via `POST /permissions/grant`.
<!-- /FAQ -->

### Q: What does `implies` actually do?

<!-- FAQ:implies-field -->
When a permission has `"implies": ["perm.a", "perm.b"]`, granting the parent permission automatically grants the implied ones. This is resolved by the auth service at grant time.

Example: granting `resource.admin` automatically grants `resource.read`, `resource.write`, `resource.delete`, etc. The user's token will contain ALL the implied permissions — your code doesn't need to resolve implies chains, they're already expanded.

Use `implies` for admin-tier permissions. Don't use it for `cross_tenant` — that should always be a conscious, separate grant.
<!-- /FAQ -->

### Q: How do I decide `default_grant: true` vs `false`?

<!-- FAQ:default-grant -->
Ask: "Should a brand new user who just joined this org be able to do this without anyone explicitly approving it?"

- `true`: Reading data, viewing logs, creating their own resources — basic operational access
- `false`: Admin operations, SSH access, cross-tenant access, cost management — needs explicit approval

When in doubt, default to `false`. It's easier to grant a permission than to revoke one after a security incident.
<!-- /FAQ -->

---

## Section 3: Registration & Service Setup

### Q: Why does each service need its own org?

<!-- FAQ:service-org-isolation -->
Permission isolation. Each service's permissions live in its own org namespace. This means:
- `resource.read` in the Resource Service org is a completely different permission from `billing.read` in the Billing Service org
- Compromise of one service's admin credentials doesn't affect other services
- API keys are scoped to one org — a key for the resource service can't be used to manage billing permissions

Think of orgs as security boundaries between services.
<!-- /FAQ -->

### Q: What happens if I run the registration script twice?

<!-- FAQ:idempotent-registration -->
It's safe — the script is idempotent. On second run:
- Step 1: Logs in instead of creating a new account
- Step 2: Finds the existing org instead of creating one
- Step 3: Normal login
- Step 4: Re-registers permissions (updates the registration)
- Step 5: **Reuses the existing API key** — this is a gotcha! It does NOT update the key's permissions. If you added new permissions, you need to manually update the key via `PUT /api-keys/{id}`.
- Step 6: Optional proxy registration

The credentials file is overwritten with fresh tokens but the same org/key IDs.
<!-- /FAQ -->

### Q: Where do I find my org UUID after registration?

<!-- FAQ:org-uuid -->
In the credentials file created by the registration script:

```bash
cat credentials/resource.json | jq '.organization.id'
# Returns: "020caf72-d9cd-48b1-bbfc-2bc8c67f0cc5"
```

The `service_audience` value goes into your `app/config.py` as `AB0T_AUTH_AUDIENCE = "resource-service"` (the service slug, not the UUID).
<!-- /FAQ -->

### Q: What if the auth service is down when I try to register?

<!-- FAQ:auth-service-down-registration -->
Registration will fail at step 1 (can't login/register). The script does not retry automatically. Wait for the auth service to come back and run again — it's idempotent so there's no risk of partial state.

If the auth service goes down AFTER registration (during normal operation), your service's behavior depends on `permission_check_mode`:
- `"client"`: Service continues working using cached JWKS keys and JWT claims. New tokens can't be issued but existing valid tokens still work.
- `"server"`: Permission checks fail with 503. The library returns `AuthServiceError`.
<!-- /FAQ -->

### Q: How do I register from CI/CD?

<!-- FAQ:cicd-registration -->
Set the auth service URL and run the script:

```bash
AUTH_SERVICE_URL=https://auth.service.ab0t.com ./register-service-permissions.sh
```

The script reads from `.permissions.json` in the current directory. Store the generated `credentials/{service}.json` as a CI/CD secret — it contains the API key and admin credentials. Don't commit it to git (add `credentials/` to `.gitignore`).
<!-- /FAQ -->

---

## Section 4: Implementation & Code Patterns

### Q: Why a single centralized app/auth.py instead of auth in each route file?

<!-- FAQ:centralized-auth-module -->
Three reasons:
1. **Consistency**: One AuthGuard instance, one TenantConfig, one set of check callbacks. If each route file had its own, settings could drift.
2. **Auditability**: Security reviewers look at one file to understand the entire auth posture. "Show me your auth" → `app/auth.py`.
3. **DRY**: Type aliases are defined once, imported everywhere. Changing a check callback affects all routes that use it.
<!-- /FAQ -->

### Q: What's the difference between `check=` and `checks=[]`?

<!-- FAQ:check-vs-checks -->
`check=` takes a single callback function. `checks=[]` takes a list of callbacks combined with `check_mode`.

```python
# Single check — just org membership
ResourceReader = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "resource.read", check=belongs_to_org)
)]

# Multiple checks — ALL must pass (check_mode="all")
ResourceAllocator = Annotated[AuthenticatedUser, Depends(
    require_any_permission(auth, "resource.create.allocations", "resource.create.deployments",
        checks=[belongs_to_org, is_not_suspended, is_within_quota],
        check_mode="all")
)]
```

Use `check=` when you have one condition. Use `checks=[]` when multiple conditions must be met (or any, with `check_mode="any"`).
<!-- /FAQ -->

### Q: When do I use `require_permission` vs `require_any_permission` vs `require_all_permissions`?

<!-- FAQ:require-permission-variants -->
- `require_permission(auth, "perm")` — user needs exactly this one permission
- `require_any_permission(auth, "perm.a", "perm.b")` — user needs at least one of these (OR)
- `require_all_permissions(auth, "perm.a", "perm.b")` — user needs ALL of these (AND)

Most common: `require_permission` for single-action routes (read, write, delete). Use `require_any_permission` when an action can be satisfied by different permissions — e.g., creating allocations OR deployments both satisfy "can create resources."
<!-- /FAQ -->

### Q: Why `permission_check_mode="server"` instead of `"client"`?

<!-- FAQ:server-vs-client-mode -->
**Client mode** checks permissions from the JWT claims. Fast (no network call), but stale — if you revoke a permission, the user keeps access until their JWT expires (15-60 min).

**Server mode** calls the auth service API on every request. Slower (one extra HTTP call), but real-time — revoked permissions take effect immediately.

Choose server mode when:
- Your service manages expensive or sensitive resources
- Instant revocation matters (security incidents, billing disputes)
- You can tolerate ~5-20ms extra latency per request

Choose client mode when:
- Latency is critical and permission changes are rare
- You're in development/testing
- The auth service is in a different region (high latency)
<!-- /FAQ -->

### Q: Why do I need `auth.lifespan()` in main.py?

<!-- FAQ:lifespan-requirement -->
AuthGuard fetches JWKS keys (public keys for JWT verification) on startup and caches them. Without `lifespan()`:
- The first request triggers a synchronous JWKS fetch, causing a timeout or blocking
- JWKS key rotation isn't handled
- Caches aren't initialized
- You get `AuthGuard not initialized` errors

The lifespan also handles graceful shutdown — clearing caches and closing HTTP connections.
<!-- /FAQ -->

### Q: What does `register_auth_exception_handlers(app)` do?

<!-- FAQ:exception-handlers -->
Without it, auth errors from the library (TokenExpiredError, PermissionDeniedError, etc.) bubble up as unhandled Python exceptions, returning raw 500 Internal Server Error responses.

With it, these errors are caught and converted to proper JSON responses:
- `TokenExpiredError` → `401 {"detail": "Token has expired"}`
- `PermissionDeniedError` → `403 {"detail": "Permission denied", "required": "resource.admin"}`
- `AuthServiceError` → `503 {"detail": "Authentication service unavailable"}`

This is both better UX and better security (no stack traces leaked).
<!-- /FAQ -->

### Q: What's `AB0T_AUTH_AUDIENCE` and what happens if I don't set it?

<!-- FAQ:audience-explained -->
The audience is a JWT claim that identifies the intended recipient of the token. Format: the service slug (e.g., `billing-service`, `sandbox-platform`). This is set by the `service_audience` field on the org record at creation time.

If you don't set it, your service accepts JWTs from ANY service in the platform. A token issued for the billing service would work on the resource service. This is a security vulnerability — it means compromising any service's tokens compromises all services.

Setting audience ensures your service only accepts tokens meant for it. Get the value from `credentials/{service}.json` → `service_audience` after registration.
<!-- /FAQ -->

---

## Section 5: API Keys & Inter-Service Communication

### Q: Why must API keys be created in the TARGET service's org?

<!-- FAQ:api-key-target-org -->
Permissions are org-scoped. `resource.create.allocations` only exists in the Resource Service org. If Sandbox Platform needs this permission on an API key, the key must be created in the Resource Service org — because that's where the permission is registered.

Think of it like needing a badge for the building you're visiting. You get the badge from the visited building's security desk, not from your own building.

The practical flow: log in as admin of the Resource Service org → create API key with the permissions the calling service needs → give the key to the calling service to use in its `X-API-Key` header.
<!-- /FAQ -->

### Q: How do I rotate an API key without downtime?

<!-- FAQ:api-key-rotation -->
1. Create a new API key with the same permissions in the target org
2. Update the calling service's config to use the new key
3. Verify the new key works
4. Revoke the old key via `DELETE /api-keys/{old_key_id}`

There's no automatic rotation. For zero-downtime rotation, the calling service should support reading the key from an environment variable that can be hot-swapped.
<!-- /FAQ -->

### Q: What permissions should an inter-service API key have?

<!-- FAQ:inter-service-key-permissions -->
The absolute minimum the calling service needs. Common patterns:

- **Sandbox → Resource**: `resource.create.allocations`, `resource.read`, `resource.delete`, `resource.scale` (needs to provision, monitor, and clean up)
- **Billing → Resource**: `resource.read.costs`, `resource.read.quotas` (only reads cost data)
- **API Gateway → Any Service**: `{service}.read` (health checks and routing)

Never give inter-service keys `admin` or `cross_tenant` unless there's a specific, documented reason. A compromised inter-service key with admin access is a major security incident.
<!-- /FAQ -->

### Q: How do I test with API keys locally?

<!-- FAQ:testing-api-keys -->
After running the registration script, use the key from `credentials/{service}.json`:

```bash
API_KEY=$(jq -r '.api_key.key' credentials/resource.json)

# Test a protected endpoint
curl -s http://localhost:8007/resources/allocations \
  -H "X-API-Key: $API_KEY" | jq
```

For testing with different permission levels, create additional API keys with restricted permissions:

```bash
# Create a read-only test key
curl -X POST "$AUTH_URL/api-keys/" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"name": "test-readonly", "permissions": ["resource.read"]}'
```
<!-- /FAQ -->

---

## Section 6: Multi-Tenancy & Isolation

### Q: What is multi-tenant isolation in simple terms?

<!-- FAQ:multi-tenancy-simple -->
Every user belongs to an organization (tenant). Every resource belongs to an organization. Users can only see and interact with resources in their own organization.

If Company A and Company B both use the platform, Company A's employees cannot see Company B's resources, even if they have the same permissions. This is enforced at three layers: the auth dependency (Phase 1), the route handler (Phase 2), and the database query (get_user_filter).
<!-- /FAQ -->

### Q: What's the difference between `belongs_to_org` and `is_resource_owner`?

<!-- FAQ:belongs-vs-owner -->
They answer different questions:

**`belongs_to_org`**: "Is this user a member of the org referenced in this request?" Used for operations where org membership is enough — listing resources, creating new resources, reading org-wide data. Any user in the org can do these.

**`is_resource_owner`**: "Does this user own the specific resource they're trying to modify?" Used for mutation operations — writing, deleting, scaling, executing. Only the resource owner (or an admin) can do these.

Example: User A and User B are both in Org-1.
- User A can LIST all allocations in Org-1 (belongs_to_org passes)
- User A CANNOT delete User B's allocation (is_resource_owner fails)
- An admin in Org-1 CAN delete User B's allocation (is_resource_owner passes for admins)
<!-- /FAQ -->

### Q: What does `cross_tenant` actually allow?

<!-- FAQ:cross-tenant-explained -->
The `cross_tenant` permission bypasses all org boundaries. A user with `resource.cross_tenant` can:
- Read resources in ANY org (get_user_filter returns `{}` — no filter)
- Access specific resources in ANY org (verify_allocation_access allows it)
- Bypass belongs_to_org checks

This is reserved for platform support staff who need to troubleshoot customer issues. It should NEVER be:
- Implied by `admin` (admin is org-scoped)
- Default-granted to any role
- Given to inter-service API keys (use specific permissions instead)

All cross-tenant access should be logged and auditable.
<!-- /FAQ -->

### Q: What happens if I forget `get_user_filter()` on a list endpoint?

<!-- FAQ:missing-user-filter -->
Your endpoint returns ALL resources across ALL organizations. This is a data leak — User A sees User B's resources, Org-1 sees Org-2's data.

This is one of the most common and dangerous mistakes. It "works" in development (you see data, tests pass) because you're usually testing with one user. It only becomes visible in production when multiple orgs exist.

Prevention: grep your route files for list/query endpoints and verify every one uses `get_user_filter()`. Add this to your security testing checklist.
<!-- /FAQ -->

### Q: How does TenantConfig's org hierarchy work?

<!-- FAQ:org-hierarchy -->
Organizations can have parent/child relationships. The TenantConfig controls access across this hierarchy:

- `allow_ancestor_access=True`: A parent org can see child org resources (useful: parent is the billing entity)
- `allow_descendant_access=False`: A child org CANNOT see parent org resources (security: subsidiaries shouldn't see parent's internal data)

If your platform doesn't have parent/child orgs, set both to `False` and ignore hierarchy. Most services use the Resource Service's config: ancestors can access, descendants cannot.
<!-- /FAQ -->

---

## Section 7: Route Protection & Phase 2

### Q: Why do I need Phase 2 if Phase 1 already checked permissions?

<!-- FAQ:why-phase-2 -->
Phase 1 runs as a FastAPI dependency — BEFORE your route handler executes. At that point, all it knows is:
- Who the user is (user_id, org_id)
- What permissions they have
- What the request path looks like

It does NOT know which specific resource the user is trying to access. The `allocation_id` in `/allocations/{allocation_id}` is just a string — Phase 1 can't look it up in the database.

Phase 2 runs INSIDE your route handler, AFTER you've fetched the resource from the database. Now you know the resource's `org_id` and `user_id`, and you can verify: "Does this user actually own this resource, or are they trying to access someone else's?"

Without Phase 2, any user with `resource.read` could read ANY allocation by guessing UUIDs.
<!-- /FAQ -->

### Q: Which routes need Phase 2 and which don't?

<!-- FAQ:phase-2-decision -->
**Needs Phase 2**: Any route that takes a resource identifier in the path and fetches a specific resource.
- `GET /allocations/{allocation_id}` — yes
- `DELETE /allocations/{allocation_id}` — yes
- `POST /allocations/{allocation_id}/scale` — yes
- `GET /allocations/{allocation_id}/instances/{instance_id}` — yes (verify parent allocation)

**Does NOT need Phase 2**:
- `POST /allocate` — creates a new resource (assigns ownership to the calling user)
- `GET /allocations` — list endpoint (scoped by `get_user_filter()` instead)
- `GET /health` — no resource access
- `GET /public-stats` — public data

Rule of thumb: if there's a `{resource_id}` in the URL and you fetch it from DB, add Phase 2.
<!-- /FAQ -->

### Q: Why 404 before 403? Does the order matter?

<!-- FAQ:404-before-403 -->
Yes, the order matters for both security and correctness:

```python
# CORRECT order
allocation = await db.get_allocation(allocation_id)
if not allocation:
    raise HTTPException(404, "Allocation not found")  # 1. Does it exist?
verify_allocation_access(allocation, user)              # 2. Can you access it?
```

Why security: if you return 403 for resources that exist and 404 for ones that don't, an attacker can enumerate valid resource IDs by checking which ones return 403. By always returning 404 for non-existent resources first, you don't leak existence information.

Why correctness: `verify_allocation_access(None, user)` crashes with `AttributeError` because `None` has no `.user_id` attribute.
<!-- /FAQ -->

### Q: How do I protect nested resources (instance within allocation)?

<!-- FAQ:nested-resources -->
Verify the parent, then verify the child belongs to that parent:

```python
# 1. Fetch and verify parent
allocation = await db.get_allocation(allocation_id)
if not allocation: raise HTTPException(404)
verify_allocation_access(allocation, user)

# 2. Fetch child and verify it belongs to parent
instance = await db.get_instance(instance_id)
if not instance or instance.allocation_id != allocation_id:
    raise HTTPException(404)  # Prevents IDOR: accessing instance via wrong allocation
```

The `instance.allocation_id != allocation_id` check is critical — without it, a user could access Instance-B (belonging to Allocation-B) by requesting `/allocations/{their-allocation-A}/instances/{instance-B}`.
<!-- /FAQ -->

---

## Section 8: Testing & Development

### Q: How do I test without the auth service running?

<!-- FAQ:testing-without-auth -->
Enable auth bypass by setting TWO environment variables (both required as defense-in-depth):

```bash
AB0T_AUTH_DEBUG=true
AB0T_AUTH_BYPASS=true
```

This creates a synthetic bypass user. Configure it:
```bash
AB0T_AUTH_BYPASS_USER_ID=test_user
AB0T_AUTH_BYPASS_EMAIL=test@localhost
AB0T_AUTH_BYPASS_ORG_ID=test_org
AB0T_AUTH_BYPASS_PERMISSIONS=resource.read,resource.create.allocations,resource.admin
AB0T_AUTH_BYPASS_ROLES=resource-admin
```

Your routes work as normal — the `AuthenticatedUser` object is populated from these env vars instead of a real token.
<!-- /FAQ -->

### Q: How do I write unit tests for my auth functions?

<!-- FAQ:unit-testing-auth -->
Mock the AuthenticatedUser and Request objects:

```python
from unittest.mock import Mock

def make_user(user_id, org_id, permissions=None):
    user = Mock()
    user.user_id = user_id
    user.org_id = org_id
    user._perms = permissions or []
    user.has_permission = lambda p: p in user._perms
    user.metadata = {}
    return user

def make_request(path_params=None):
    req = Mock()
    req.path_params = path_params or {}
    req.query_params = {}
    return req

# Test: same org user passes belongs_to_org
assert belongs_to_org(make_user("u1", "org1"), make_request({"org_id": "org1"}))

# Test: different org user fails
assert not belongs_to_org(make_user("u1", "org1"), make_request({"org_id": "org2"}))

# Test: admin in different org can't access allocation
with pytest.raises(PermissionDeniedError):
    alloc = Mock(user_id="u2", org_id="org2")
    verify_allocation_access(alloc, make_user("u1", "org1", ["resource.admin"]))
```
<!-- /FAQ -->

### Q: How do I test that unauthorized access is properly denied?

<!-- FAQ:red-team-testing -->
Create test API keys with different permission levels and verify each endpoint returns the expected status code:

```bash
# No auth → 401
curl -s -o /dev/null -w "%{http_code}" http://localhost:8007/resources/allocations
# Expected: 401

# Read-only key trying to create → 403
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8007/resources/allocate \
  -H "X-API-Key: $READ_ONLY_KEY" -H "Content-Type: application/json" -d '{}'
# Expected: 403

# User A trying to access User B's resource → 403
curl -s -o /dev/null -w "%{http_code}" http://localhost:8007/resources/allocations/$USER_B_ALLOC \
  -H "X-API-Key: $USER_A_KEY"
# Expected: 403
```

Test all 7 attack vectors: no auth, invalid token, missing permission, cross-user, cross-org, path traversal, injection. See references/testing-troubleshooting.md for the full checklist.
<!-- /FAQ -->

### Q: Can I use auth bypass in staging/QA?

<!-- FAQ:bypass-in-staging -->
You can, but be careful. Auth bypass disables ALL permission checks — it doesn't test your auth logic at all. Use it for:
- Unit testing business logic that isn't auth-related
- Development when iterating on features

Do NOT use it for:
- Integration testing (you need real auth flows)
- Staging environments that mirror production
- Any environment accessible from outside your machine

For staging, use real API keys with appropriate permissions — this tests the actual auth flow.
<!-- /FAQ -->

---

## Section 9: Debugging & Troubleshooting

### Q: I'm getting 401 but my token looks valid. What's wrong?

<!-- FAQ:debug-401 -->
Check these in order:
1. **Token expired?** JWTs expire in 15-60 min. Decode it at jwt.io and check `exp`.
2. **Wrong audience?** Your token's `aud` claim must match `AB0T_AUTH_AUDIENCE`. If your service expects `billing-service` but the token has `sandbox-platform`, it's rejected. (Legacy tokens may use `LOCAL:{uuid}` format.)
3. **JWKS not fetched?** If AuthGuard isn't initialized (missing lifespan), it can't verify signatures. Check for `AuthGuard not initialized` in logs.
4. **Wrong header?** JWT goes in `Authorization: Bearer <token>`, API key goes in `X-API-Key: <key>`.
5. **Auth service unreachable?** Server-mode permission checks call the auth service. If it's down, you get 401 or 503.

Debug by printing the user object in a working route:
```python
@app.get("/debug-auth")
async def debug(user: CurrentUser):
    return {"user_id": user.user_id, "auth_method": str(user.auth_method), "permissions": user.permissions}
```
<!-- /FAQ -->

### Q: I'm getting 403 but I have the permission. What's wrong?

<!-- FAQ:debug-403 -->
403 means authentication passed but authorization failed. Check:

1. **Check callback failing?** The permission check passed, but a callback like `belongs_to_org` or `is_resource_owner` returned False. Print the user's org_id and compare with the request's org_id.
2. **Phase 2 failing?** You have the permission but don't own the specific resource. Check `allocation.user_id == user.user_id` and `allocation.org_id == user.org_id`.
3. **Stale permissions?** In client mode, permissions come from JWT claims. If a permission was just granted, the user needs a new token (re-login or refresh). In server mode, check with `GET /auth/me`.
4. **Wrong permission string?** Permission strings are case-sensitive and exact. `resource.Read` ≠ `resource.read`. Check spelling.
5. **Suspended user?** If `is_not_suspended` callback is used, check `user.metadata.get("suspended")`.
<!-- /FAQ -->

### Q: Permission changes aren't taking effect. What's going on?

<!-- FAQ:stale-permissions -->
This depends on your `permission_check_mode`:

**Client mode (`"client"`)**: Permissions are read from the JWT token claims. The token was issued at login time. Changes to permissions don't affect existing tokens — the user must get a new token (re-login, refresh). JWT expiry is typically 15-60 minutes, so there's a delay.

**Server mode (`"server"`)**: Permissions are checked against the auth service in real-time. Changes should take effect immediately. If they don't:
- The auth service might be caching. Wait a few seconds.
- The API key might have old permissions. Check with `POST /auth/validate-api-key`.
- You might have granted the permission in the wrong org.

This is the #1 reason we recommend server mode for production.
<!-- /FAQ -->

### Q: How do I check what permissions a user/key actually has?

<!-- FAQ:check-permissions -->
```bash
# Check JWT user's permissions
curl -s https://auth.service.ab0t.com/auth/me \
  -H "Authorization: Bearer $TOKEN" | jq '.permissions'

# Check API key's permissions
curl -s -X POST https://auth.service.ab0t.com/auth/validate-api-key \
  -H "Content-Type: application/json" \
  -d '{"api_key": "ab0t_sk_live_..."}' | jq '.permissions'

# Check a specific user's permissions (admin)
curl -s https://auth.service.ab0t.com/permissions/user/$USER_ID \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.permissions'
```
<!-- /FAQ -->

### Q: I see `AuthGuard not initialized` — what did I miss?

<!-- FAQ:authguard-not-initialized -->
You forgot to add the lifespan context manager in `main.py`:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    async with auth.lifespan():   # ← This is missing
        yield

app = FastAPI(lifespan=lifespan)
```

The lifespan initializes JWKS fetching, cache setup, and HTTP clients. Without it, AuthGuard can't verify any tokens.
<!-- /FAQ -->

---

## Section 10: Security & Operations

### Q: What happens if someone steals a JWT?

<!-- FAQ:stolen-jwt -->
They can impersonate the user until the token expires (15-60 min). Mitigations:
- Short token expiry (15 min default) limits the window
- Server-mode permission checks mean you can revoke the user's permissions immediately
- `POST /auth/revoke` revokes a specific token
- `DELETE /organizations/{org_id}/sessions` revokes all sessions for a user in an org

JWTs can't be "invalidated" in client mode because they're self-contained. This is why server mode is recommended for sensitive services.
<!-- /FAQ -->

### Q: What happens if someone steals an API key?

<!-- FAQ:stolen-api-key -->
API keys don't expire, so the exposure is indefinite until revoked. Immediate response:
1. Revoke the key: `DELETE /api-keys/{key_id}`
2. Create a new key with the same permissions
3. Update the service that uses it
4. Audit access logs for unauthorized use

Prevention: limit API key permissions to the minimum needed. A key with only `resource.read` is less damaging than one with `resource.admin`.
<!-- /FAQ -->

### Q: Is `AB0T_AUTH_AUDIENCE_SKIP` safe to use?

<!-- FAQ:audience-skip -->
`AB0T_AUTH_AUDIENCE_SKIP=true` disables audience validation, meaning your service accepts tokens from ANY service. This exists only for transition periods when migrating to audience-based validation.

It is NOT safe for production. Use it only when:
- You're migrating and not all services have been updated yet
- You need a temporary grace period
- You have a concrete plan to disable it

Set a deadline and remove it. Every day it's enabled is a day where any compromised service's tokens work on your service.
<!-- /FAQ -->

### Q: How should I handle auth in health check endpoints?

<!-- FAQ:health-check-auth -->
Health check endpoints (`/health`, `/ready`, `/live`) should typically be public (no auth). They're called by load balancers, Kubernetes probes, and monitoring systems that don't have tokens.

```python
@app.get("/health")
async def health():
    return {"status": "healthy"}
```

If you use middleware-based auth, exclude these paths:
```python
setup_auth_middleware(app, auth, exclude_paths=["/health", "/ready", "/docs", "/openapi.json"])
```

For sensitive health endpoints (showing internal state), use admin-level auth:
```python
@app.get("/health/detailed")
async def detailed_health(user: ResourceAdmin):
    return {"db": "connected", "cache": "warm", "auth": "initialized"}
```
<!-- /FAQ -->

---

## Section 11: Migration & Upgrades

### Q: I'm using the old `Depends(get_current_user)` pattern. How do I migrate?

<!-- FAQ:migration-from-old-pattern -->
Replace step by step:

**Before:**
```python
from app.dependencies import get_current_user

@app.get("/resources")
async def list_resources(user = Depends(get_current_user)):
    return await db.list_all()  # No filtering!
```

**After:**
```python
from app.auth import ResourceReader, get_user_filter

@app.get("/resources")
async def list_resources(user: ResourceReader):
    filters = get_user_filter(user)
    return await db.list_resources(**filters)  # Tenant-filtered
```

Key changes:
1. Import from `app.auth` instead of `app.dependencies`
2. Use type alias (`ResourceReader`) instead of `Depends(get_current_user)`
3. Add `get_user_filter()` for list endpoints
4. Add `verify_*_access()` for single-resource endpoints
5. Replace `user.id` with `user.user_id`
<!-- /FAQ -->

### Q: What breaks when I switch from old User model to AuthenticatedUser?

<!-- FAQ:user-model-migration -->
| Old pattern | New pattern | What breaks if you don't change |
|---|---|---|
| `user.id` | `user.user_id` | Returns `None` silently — ownership checks fail open |
| `user.name` | `user.metadata.get("name")` | `AttributeError` |
| `user.permissions` (list) | `user.permissions` (tuple) | List mutations fail (`append`, `extend`) |
| `user.is_active` | `not user.metadata.get("suspended", False)` | `AttributeError` |
| `if user.is_admin` | `if user.has_permission("resource.admin")` | `AttributeError` |

The most dangerous: `user.id` → `user.user_id`. If you use `user.id` with the new model, it silently returns `None` (Python attribute lookup), and any comparison like `allocation.user_id == user.id` becomes `"abc" == None` → `False`. This means ownership checks reject the actual owner.
<!-- /FAQ -->

### Q: Can I migrate incrementally or do I have to do all routes at once?

<!-- FAQ:incremental-migration -->
You can migrate incrementally. The old `get_current_user` and new type aliases can coexist:

1. Create `app/auth.py` with AuthGuard, TenantConfig, type aliases
2. Add lifespan and exception handlers to `main.py`
3. Migrate one route file at a time — change imports and add Phase 2
4. Test each migrated file before moving to the next
5. Once all routes are migrated, remove old `get_current_user` from `dependencies.py`

The only hard requirement is that `main.py` has the lifespan and exception handlers before any route uses the new type aliases.
<!-- /FAQ -->

---

## Section 12: Edge Cases & Gotchas

### Q: Why does `user.id` return None instead of raising an error?

<!-- FAQ:user-id-none -->
`AuthenticatedUser` is a frozen dataclass. It has `user_id`, not `id`. When you access `user.id` on a dataclass, Python doesn't find a defined attribute but may return `None` from the metadata dict or raise `AttributeError` depending on the context.

The fix is always `user.user_id`. If you're migrating from the old `User(BaseModel)` which had `.id`, do a find-and-replace across all route files: `user.id` → `user.user_id`.
<!-- /FAQ -->

### Q: My registration script created an API key but it doesn't have the new permissions I added.

<!-- FAQ:stale-api-key -->
The registration script is idempotent — when it finds an existing API key with the same name, it reuses it WITHOUT updating its permissions. This is by design (to avoid accidentally changing production keys).

To fix: manually update the key's permissions:
```bash
# Find the key ID
curl -s "$AUTH_URL/api-keys/" -H "Authorization: Bearer $TOKEN" | jq '.[].id'

# Update permissions
curl -X PUT "$AUTH_URL/api-keys/$KEY_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"permissions": ["resource.read", "resource.create.allocations", "resource.new_permission"]}'
```

This was a real production bug — see ticket 20260205 for the full postmortem.
<!-- /FAQ -->

### Q: Admin of Org A can see Org B's resources — how?

<!-- FAQ:cross-org-leak -->
Check these in order:
1. **Does the user have `cross_tenant`?** Check `user.permissions` — if they have `resource.cross_tenant`, they intentionally bypass org boundaries.
2. **Is `get_user_filter()` used on the list endpoint?** Without it, the query returns all resources regardless of org.
3. **Is Phase 2 verification present?** Without `verify_allocation_access()`, any user with `resource.admin` in Org A can access specific resources in Org B because the admin check doesn't verify same-org.
4. **Is `belongs_to_org` check present on the type alias?** If the type alias uses no check callback, org membership isn't verified at Phase 1 either.

Most common cause: missing `get_user_filter()` on a list endpoint. Second most common: Phase 2 verification missing.
<!-- /FAQ -->

### Q: I have two services that need to share permissions. How?

<!-- FAQ:shared-permissions -->
Services should NOT share permissions. Each service registers its own permissions in its own org. If Service A needs to check Service B's permissions, it should:

1. Call Service B's API directly (with an inter-service API key)
2. Or ask the auth service about the user's permissions in Service B's org

Anti-pattern: registering `billing.read` in the Resource Service org. This breaks isolation — if Resource Service is compromised, billing permissions are compromised too.

If you truly need cross-service authorization, use the Zanzibar relationship-based model at `POST /zanzibar/check`.
<!-- /FAQ -->

### Q: What happens when the auth service is slow or timing out?

<!-- FAQ:auth-service-timeout -->
Behavior depends on your setup:

**Client mode**: No impact on request latency — permissions are checked locally from JWT claims. JWKS key refresh might be slow, but cached keys are used until refreshed.

**Server mode**: Every request includes a permission check API call. If the auth service is slow:
- Requests to your service are slow (waiting for auth check)
- If the auth service is completely down, requests fail with `503 AuthServiceError`

Mitigations:
- The library caches permission check results (configurable TTL)
- Set reasonable timeouts on the AuthGuard HTTP client
- Monitor auth service latency as an SLI for your service
- Consider falling back to client mode if the auth service is in a degraded state
<!-- /FAQ -->

### Q: Can I use ab0t-auth with Flask instead of FastAPI?

<!-- FAQ:flask-support -->
Yes, the library supports Flask via decorators:

```python
from ab0t_auth.decorators import protected, permission_required

@app.route("/protected")
@protected(auth)
def protected_route(auth_user):
    return {"user_id": auth_user.user_id}
```

However, the SKILL.md and all reference files focus on FastAPI (Dependencies pattern). For Flask, see the full library reference at `references/auth-wrapper-library-full.md`, Sections 4.3 (decorators) and 15.8 (Flask multi-tenancy).
<!-- /FAQ -->
