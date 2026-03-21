# Service Registration Reference

## The Registration Script

The `scripts/register-service-permissions.sh` script registers your service with the Auth Service. It is **idempotent** — safe to run multiple times. It reads from `.permissions.json`.

**Why a shell script and not Python?** Registration happens before your service starts — often during deployment, in CI/CD, or from a bare machine. Shell has no dependencies beyond `curl` and `jq`.

See `scripts/register-service-permissions.sh` for the complete production script.

### What It Does (6 Steps)

1. **Create/Login Admin Account** — Derives email from service ID: `mike+{service_id}@ab0t.com`. Why a dedicated admin per service? Compromise of one service's admin doesn't affect others.
2. **Create/Find Organization** — One org per service for isolation. Permissions are org-scoped — resource service permissions live in the resource org.
3. **Login with Org Context** — Gets org-scoped JWT token. Required because permission registration and API key creation must happen within an org context.
4. **Register Permissions** — Single POST to `/permissions/registry/register` with actions and resources from `.permissions.json`. Tells the auth service what permission strings are valid.
5. **Create API Key** — With all permissions from `.permissions.json`. This key is what your service uses for server-side permission checks.
6. **Proxy Registration** — Optional, registers with proxy controller for `*.service.ab0t.com` routing.

### Running It

```bash
# Default (uses https://auth.service.ab0t.com)
./register-service-permissions.sh

# Custom auth service URL
AUTH_SERVICE_URL=http://localhost:8001 ./register-service-permissions.sh

# With proxy registration enabled
REGISTER_PROXY=1 ./register-service-permissions.sh
```

### What It Creates

```
credentials/{service_id}.json
```

Contains:
```json
{
  "service": "resource",
  "organization": {
    "id": "020caf72-d9cd-48b1-bbfc-2bc8c67f0cc5",
    "name": "Resource Service",
    "slug": "resource"
  },
  "admin": {
    "email": "mike+resource@ab0t.com",
    "password": "...",
    "user_id": "...",
    "access_token": "...",
    "refresh_token": "..."
  },
  "api_key": {
    "id": "...",
    "key": "ab0t_sk_live_..."
  },
  "permissions_source": ".permissions.json",
  "created_at": "2026-02-04T12:00:00Z"
}
```

### The Registration API Call

The core call that registers all permission combinations:

```bash
curl -X POST "$AUTH_SERVICE_URL/permissions/registry/register" \
  -H "Authorization: Bearer $ORG_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "service": "resource",
    "description": "Resource Service",
    "actions": ["read", "write", "create", "delete", "scale", "execute", "admin", "ssh", "logs", "metrics", "cross_tenant"],
    "resources": ["allocations", "instances", "deployments", "containers", "workflows", "costs", "quotas", "pools", "config", "health"]
  }'
```

This generates the permission matrix: `{service}.{action}.{resource}` for all combinations.

## Finding and Granting Permissions

### List Registered Services

```bash
curl -s https://auth.service.ab0t.com/permissions/registry/services | jq '.services[].service'
```

### List Valid Permissions for a Service

```bash
curl -s https://auth.service.ab0t.com/permissions/registry/valid-permissions | \
  jq '.permissions | map(select(startswith("resource")))'
```

### Grant a Permission to a User

```bash
curl -X POST "$AUTH_URL/permissions/grant?user_id=$USER_ID&org_id=$ORG_ID&permission=resource.admin" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Grant Multiple Permissions (Role-Based)

The registration script handles this for admin users via the `implies` field. For other users, use the invite endpoint:

```bash
curl -X POST "$AUTH_URL/organizations/$ORG_ID/invite" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@company.com",
    "role": "resource-user",
    "permissions": ["resource.read", "resource.create.allocations"]
  }'
```

### Check a User's Permissions

```bash
# Via /auth/me endpoint (JWT)
curl -s "$AUTH_URL/auth/me" \
  -H "Authorization: Bearer $USER_TOKEN" | jq '.permissions'

# Via API key validation
curl -s -X POST "$AUTH_URL/auth/validate-api-key" \
  -H "Content-Type: application/json" \
  -d '{"api_key": "ab0t_sk_live_..."}' | jq '.permissions'
```

### Revoke a Permission

```bash
curl -X DELETE "$AUTH_URL/permissions/revoke?user_id=$USER_ID&org_id=$ORG_ID&permission=resource.admin" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## API Keys for Inter-Service Auth

When one service needs to call another, it uses an API key created in the **target service's org**.

**Why in the target's org?** Permissions are org-scoped. If Sandbox Platform needs `resource.create.allocations`, that permission only exists in the Resource Service org. Think of it like needing a badge for the building you're visiting, not the building you work in.

### Create API Key

```bash
curl -X POST "$AUTH_URL/api-keys/" \
  -H "Authorization: Bearer $ORG_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "sandbox-to-resource",
    "permissions": ["resource.create.allocations", "resource.read", "resource.delete"],
    "rate_limit": 100000,
    "metadata": {
      "purpose": "Sandbox Platform calling Resource Service",
      "service_type": "inter-service"
    }
  }'
```

Grant only the minimum permissions the calling service needs.

### Update API Key Permissions

```bash
curl -X PUT "$AUTH_URL/api-keys/$KEY_ID" \
  -H "Authorization: Bearer $ORG_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"permissions": ["resource.create.allocations", "resource.read", "resource.delete", "resource.scale"]}'
```

### List / Revoke API Keys

```bash
# List
curl -s "$AUTH_URL/api-keys/" -H "Authorization: Bearer $ORG_TOKEN" | jq '.[].name'

# Revoke
curl -X DELETE "$AUTH_URL/api-keys/$KEY_ID" -H "Authorization: Bearer $ORG_TOKEN"
```
