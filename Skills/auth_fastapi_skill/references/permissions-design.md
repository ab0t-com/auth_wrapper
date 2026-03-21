# Permission Design Reference

## The .permissions.json Schema

Every service has a `.permissions.json` file in its root directory. It serves three purposes:
1. **Documentation** — describes all permissions the service uses
2. **Registration** — tells the auth service what to register
3. **Reference** — other services know what permissions exist

**Why a JSON file instead of inline code?** Because permissions span three concerns: the auth service needs them for registration, the shell script reads them for API calls, and the Python code enforces them. A single JSON file is the source of truth that all three consume.

### Template

```json
{
  "$schema": "https://auth.service.ab0t.com/schemas/permissions/v2",

  "service": {
    "id": "myservice",
    "name": "My Service",
    "description": "What this service does",
    "version": "1.0.0",
    "audience": "my-service",
    "maintainer": "team@ab0t.com"
  },

  "registration": {
    "service": "myservice",
    "actions": ["read", "write", "create", "delete", "admin"],
    "resources": ["items", "users", "config"]
  },

  "permissions": [
    {
      "id": "myservice.read",
      "name": "Read All Resources",
      "description": "View resources",
      "intent": "Why this permission exists and who needs it",
      "risk_level": "low",
      "cost_impact": false,
      "default_grant": true
    },
    {
      "id": "myservice.admin",
      "name": "Administrator",
      "description": "Full org-level admin access",
      "risk_level": "critical",
      "cost_impact": true,
      "default_grant": false,
      "security_notes": "Admins can access all org resources but not other orgs.",
      "implies": [
        "myservice.read",
        "myservice.write",
        "myservice.delete"
      ]
    },
    {
      "id": "myservice.cross_tenant",
      "name": "Cross-Tenant Access",
      "description": "Access resources in any organization",
      "risk_level": "critical",
      "default_grant": false,
      "security_notes": "All cross-tenant access is logged. Grant only to senior staff."
    }
  ],

  "roles": [
    {
      "id": "myservice-user",
      "name": "Standard User",
      "permissions": ["myservice.read", "myservice.write", "myservice.create"],
      "default": true
    },
    {
      "id": "myservice-admin",
      "name": "Administrator",
      "permissions": ["myservice.admin"],
      "default": false
    }
  ],

  "multi_tenancy": {
    "isolation_model": "organization",
    "tenant_field": "org_id",
    "enforcement": "strict",
    "cross_tenant_permission": "myservice.cross_tenant"
  }
}
```

### Key Fields

| Field | Purpose |
|-------|---------|
| `service.id` | Unique service identifier. Becomes permission prefix. Cannot be changed later. Choose carefully. |
| `service.audience` | JWT audience claim. Without this, a JWT from billing service would be accepted by resource service. |
| `registration.actions` | Verbs registered with auth service. Start by listing every verb your routes use. |
| `registration.resources` | Nouns registered with auth service. Start by listing domain objects your service manages. |
| `permissions[].id` | The actual permission string. Format: `{service}.{action}` or `{service}.{action}.{resource}`. Only define ones your routes actually check. |
| `permissions[].implies` | When granted, these are also granted. Think: "If someone has admin, what else should they automatically get?" |
| `permissions[].default_grant` | Whether new users get this automatically. Ask: "Should a brand-new user be able to do this without explicit approval?" |
| `roles[].default` | Whether new users get this role automatically. Typically only the standard user role. |
| `multi_tenancy.cross_tenant_permission` | Permission for cross-org access. Always the most dangerous — keep separate from admin. |

## Designing Actions

**Agentic thinking process:** Scan every route handler and categorize:
- Routes that return data without side effects → `read`
- Routes that modify existing records → `write`
- Routes that create new records (especially if they cost money or consume resources) → `create`
- Routes that permanently remove data → `delete`
- Routes that run user-provided code or commands → `execute`
- Routes that change capacity or scale → `scale`
- Routes that provide interactive shell access → `ssh`

Then look at your domain models. Each top-level model is typically a resource. Don't create permissions for internal implementation details — only for things users interact with directly.

### Common Actions

| Action | Intent | Risk Level | Default Grant |
|--------|--------|------------|---------------|
| `read` | View data | Low | Yes |
| `write` | Modify existing data | Medium | Yes |
| `create` | Create new records | Medium | Yes |
| `delete` | Permanently remove | High | Usually yes (if recoverable) |
| `execute` | Run code/commands | High | Yes (within user's own container) |
| `scale` | Adjust capacity | Medium | Yes |
| `ssh` | Shell access | High | No |
| `logs` | View logs | Low | Yes |
| `metrics` | View monitoring data | Low | Yes |
| `admin` | Full org control | Critical | No |
| `cross_tenant` | Cross-org access | Critical | Never |

### Design Principles

1. **Not every action×resource combination is needed** — Only define permissions that map to actual route handlers.
2. **Use `implies` for admin permissions** — Avoids granting 15 individual permissions to admins. Think: "What is the minimal set a role needs?" then use `implies` to build up.
3. **`cross_tenant` is always separate** — never implied by `admin`, never default-granted. Org admins should never accidentally gain cross-org access. Requires a conscious, separate grant.
4. **`ssh` defaults to false** — SSH provides unmonitored, interactive access that bypasses structured `execute` command logging. Most users don't need it; operators do.

## Defining Roles

Roles are bundles of permissions assigned to users as a group. They exist because granting 15 individual permissions per user is error-prone and hard to audit.

**How to think about roles:** Ask "Who are the distinct personas using this service?" Each persona becomes a role.

### Role Hierarchy

- **viewer** — read-only (auditors, stakeholders). Needs visibility without ability to change anything.
- **user** — full CRUD on own resources (default). Can do everything to their own stuff but nothing to others'.
- **operator** — manage resources but not create (ops team). Needs to stop, restart, SSH, but shouldn't provision new resources or incur costs.
- **admin** — full org-level access (team leads). Sees and manages everyone's resources within the org. Cannot cross org boundaries.
- **platform-admin** — cross-tenant access (platform staff only). The only role that crosses org boundaries. Reserved for support.

### Resource Service Example

See `assets/permissions-template.json` for the complete production file.

The Resource Service defines:
- **11 actions**: read, write, create, delete, scale, execute, admin, ssh, logs, metrics, cross_tenant
- **10 resources**: allocations, instances, deployments, containers, workflows, costs, quotas, pools, config, health
- **21 permissions** with varying risk levels and default grants
- **5 roles**: resource-user (default), resource-viewer, resource-operator, resource-admin, platform-admin

### Resource Service Role Definitions

```json
{
  "id": "resource-user",
  "name": "Resource User",
  "description": "Standard user with full access to their own resources",
  "permissions": [
    "resource.create.allocations", "resource.create.deployments",
    "resource.read", "resource.write", "resource.scale", "resource.delete",
    "resource.execute.instances", "resource.execute.containers",
    "resource.logs", "resource.metrics",
    "resource.read.costs", "resource.read.quotas",
    "resource.read.workflows", "resource.create.workflows", "resource.execute.workflows"
  ],
  "default": true
}
```
