# Testing & Troubleshooting Reference

## Security Testing

### Red-Team Test Categories

Every service should test these attack vectors:

1. **No authentication** — protected endpoints return 401
2. **Invalid tokens** — malformed, expired, wrong service returns 401
3. **Missing permissions** — user without required permission gets 403
4. **Cross-user access** — User A cannot access User B's resources (403)
5. **Cross-org access** — Admin of Org A cannot access Org B resources (403)
6. **Path traversal** — `../../../etc/passwd` returns 404
7. **Injection** — SQL/command injection in resource IDs returns 404

### Test Helper

```bash
test_endpoint() {
    local description="$1"
    local expected_status="$2"
    local method="$3"
    local url="$4"
    local token="$5"

    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$url" \
        -H "X-API-Key: $token")

    if [ "$STATUS" = "$expected_status" ]; then
        echo "PASS: $description (got $STATUS)"
    else
        echo "FAIL: $description (expected $expected_status, got $STATUS)"
    fi
}

# Example tests
test_endpoint "No auth - allocations" "401" "GET" "$BASE_URL/resources/allocations" ""
test_endpoint "No perms - create" "403" "POST" "$BASE_URL/resources/allocate" "$NO_PERMS_KEY"
test_endpoint "User A - User B resource" "403" "GET" "$BASE_URL/resources/allocations/$USER_B_ALLOC" "$USER_A_KEY"
```

### Unit Tests for Auth Functions

```python
from unittest.mock import Mock
from fastapi import Request
from app.auth import belongs_to_org, verify_allocation_access
from ab0t_auth.errors import PermissionDeniedError
import pytest

def make_user(user_id, org_id, permissions=None):
    user = Mock()
    user.user_id = user_id
    user.org_id = org_id
    user._perms = permissions or []
    user.has_permission = lambda p: p in user._perms
    user.metadata = {}
    return user

def make_request(path_params=None, query_params=None):
    req = Mock(spec=Request)
    req.path_params = path_params or {}
    req.query_params = query_params or {}
    return req

class TestBelongsToOrg:
    def test_same_org(self):
        assert belongs_to_org(make_user("u1", "org1"), make_request({"org_id": "org1"}))

    def test_different_org_denied(self):
        assert not belongs_to_org(make_user("u1", "org1"), make_request({"org_id": "org2"}))

    def test_cross_tenant_bypass(self):
        user = make_user("u1", "org1", ["resource.cross_tenant"])
        assert belongs_to_org(user, make_request({"org_id": "org2"}))

class TestVerifyAllocationAccess:
    def test_owner_allowed(self):
        alloc = Mock(user_id="u1", org_id="org1")
        verify_allocation_access(alloc, make_user("u1", "org1"))  # no raise

    def test_admin_same_org(self):
        alloc = Mock(user_id="u2", org_id="org1")
        verify_allocation_access(alloc, make_user("u1", "org1", ["resource.admin"]))

    def test_admin_different_org_denied(self):
        alloc = Mock(user_id="u2", org_id="org2")
        with pytest.raises(PermissionDeniedError):
            verify_allocation_access(alloc, make_user("u1", "org1", ["resource.admin"]))

    def test_cross_tenant_allowed(self):
        alloc = Mock(user_id="u2", org_id="org2")
        verify_allocation_access(alloc, make_user("u1", "org1", ["resource.cross_tenant"]))
```

## Auth Bypass for Development

**Both env vars must be set** (defense-in-depth — requiring two flags means a single misconfiguration can't disable auth):

```bash
AB0T_AUTH_DEBUG=true
AB0T_AUTH_BYPASS=true

# Optional: configure the bypass user
AB0T_AUTH_BYPASS_USER_ID=test_user
AB0T_AUTH_BYPASS_EMAIL=test@localhost
AB0T_AUTH_BYPASS_PERMISSIONS=resource.read,resource.create.allocations,resource.admin
AB0T_AUTH_BYPASS_ROLES=resource-admin
AB0T_AUTH_BYPASS_ORG_ID=test_org
```

**Never enable bypass in production.** The library reads these directly from environment.

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `AuthGuard not initialized` | Missing lifespan | Add `async with auth.lifespan()` to lifespan |
| `401 Unauthorized` | Missing/invalid/expired token | Check token, refresh if expired |
| `403 Permission denied` | User lacks required permission | Grant permission via auth service |
| `403 Access denied to this allocation` | Phase 2 ownership check failed | User doesn't own the resource and isn't admin |
| `503 Authentication service unavailable` | Auth service down or unreachable | Check auth service health, check `AB0T_AUTH_URL` |
| Tokens from other services accepted | Audience not configured | Set `AB0T_AUTH_AUDIENCE` to your org UUID |
| Permission changes not taking effect | Using client-side check mode | Set `AB0T_AUTH_PERMISSION_CHECK_MODE=server` |

### Debug Checklist

```python
# In route handler, inspect user object:
print(f"user_id: {user.user_id}")
print(f"org_id: {user.org_id}")
print(f"permissions: {user.permissions}")
print(f"auth_method: {user.auth_method}")  # JWT, API_KEY, or BYPASS
print(f"has resource.admin: {user.has_permission('resource.admin')}")
```
