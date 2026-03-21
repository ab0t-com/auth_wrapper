# Organization Hierarchy, Teams & Multi-Tenant Architecture Guide

**The missing mental model.** This guide answers: "How should I structure my orgs, teams, and service accounts?" — the question that causes the most confusion.

---

## Table of Contents

1. [The Building Blocks](#1-the-building-blocks)
2. [How They Fit Together](#2-how-they-fit-together)
3. [Common Architecture Patterns](#3-common-architecture-patterns)
4. [Service Accounts & Inter-Service Auth](#4-service-accounts--inter-service-auth)
5. [Nested Organizations](#5-nested-organizations)
6. [Team Hierarchies](#6-team-hierarchies)
7. [Delegation (Act-As)](#7-delegation-act-as)
8. [Cross-Service Permission Mesh](#8-cross-service-permission-mesh)
9. [Decision Trees](#9-decision-trees)
10. [API Reference (Quick)](#10-api-reference-quick)
11. [Common Mistakes & Anti-Patterns](#11-common-mistakes--anti-patterns)
12. [Worked Examples](#12-worked-examples)

---

## 1. The Building Blocks

Five primitives. Everything is built from these.

```
┌─────────────────────────────────────────────────────────────────┐
│                        AUTH SERVICE                              │
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │   User   │    │   Org    │    │   Team   │    │ API Key  │  │
│  │          │    │          │    │          │    │ (service  │  │
│  │ human or │    │ security │    │ grouping │    │  account) │  │
│  │ machine  │    │ boundary │    │ within   │    │          │  │
│  │          │    │          │    │ an org   │    │          │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Permission                             │   │
│  │  {service}.{action}.{resource}                           │   │
│  │  Granted to users, teams, or API keys within an org      │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### User
A person or identity. Has an email, belongs to one or more orgs. Logs in with password/OAuth, receives JWT tokens. The `user_id` is globally unique.

### Organization (Org)
**A workspace and security boundary.** Think of an org as an isolated workspace — a namespace where permissions exist, resources live, and identities operate. An org isolates:
- Data — resources in Org A are invisible to Org B
- Permissions — `resource.admin` in Org A is meaningless in Org B
- API keys — created within an org, only work in that org's context

**WHY orgs exist:** Without them, every user on the platform could see every other user's data. Orgs are the walls between customers.

### Team
A group of users within an org. Teams can:
- Have their own permissions (inherited by all members)
- Be nested (parent/child teams)
- Represent departments, projects, or access levels

**WHY teams exist:** Orgs are too coarse for access control in large companies. You don't want every engineer to have billing admin access just because they're in the same org.

### API Key
A long-lived credential (`ab0t_sk_live_...`) created within an org. Used for:
- Scripts and automation
- Service-to-service communication
- CI/CD pipelines

An API key acts as a **service account** — it has specific permissions and represents a machine identity, not a human.

### Permission
The string `{service}.{action}.{resource}` that controls what actions are allowed. Permissions are:
- Defined by each service in `.permissions.json`
- Registered with the auth service
- Granted to users, teams, or API keys
- Scoped to an org (a permission in Org A doesn't affect Org B)

---

## 2. How They Fit Together

```
                    ┌─────────────────────────┐
                    │      Platform           │
                    │  (all orgs, all users)  │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                   ▼
     ┌────────────────┐ ┌────────────────┐  ┌────────────────┐
     │  Acme Corp     │ │  Widgets Inc   │  │  Resource Svc  │
     │  (customer)    │ │  (customer)    │  │  (infra org)   │
     │  org_id: aaa   │ │  org_id: bbb   │  │  org_id: ccc   │
     └───────┬────────┘ └───────┬────────┘  └───────┬────────┘
             │                  │                    │
      ┌──────┴───────┐   ┌─────┴──────┐      ┌─────┴──────┐
      │ Users        │   │ Users      │      │ API Keys   │
      │ - alice      │   │ - bob      │      │ (service   │
      │ - carol      │   │ - dave     │      │  accounts) │
      │              │   │            │      │            │
      │ Teams        │   │ Teams      │      │ No human   │
      │ - Engineering│   │ - Dev      │      │ users      │
      │ - Finance    │   │ - Sales    │      │            │
      │              │   │            │      │            │
      │ API Keys     │   │ API Keys   │      │            │
      │ - CI runner  │   │ - webhook  │      │            │
      └──────────────┘   └────────────┘      └────────────┘

      ISOLATION: Alice cannot see Bob's data.
      Acme's CI runner key cannot access Widgets' resources.
      Resource Service's API keys live in its own org.
```

### The Four Types of Orgs

1. **Customer orgs** — represent a company/tenant using the platform. Contain human users, teams, and possibly customer-created API keys.

2. **Personal orgs** — a user's personal workspace (like a GitHub personal account). Created on signup, `is_personal: true`. One owner, personal resources. Users can belong to personal orgs AND company orgs simultaneously.

3. **Service orgs** — represent a microservice in the platform. Contain API keys for inter-service communication. Typically no human users (only an admin account for management). Example: the Resource Service has org `020caf72-...`.

4. **Platform orgs** — management/admin orgs for platform operators. Contain staff users with `cross_tenant` access for support and debugging.

**WHY separate service orgs?** If the Sandbox Platform's API key for the Resource Service lived in the Sandbox Platform's customer org, compromising that org would also compromise Resource Service access. Separate orgs = separate blast radius.

---

## 3. Common Architecture Patterns

### Pattern 1: Simple SaaS (Most Common)

**When:** Multi-tenant SaaS with independent customers. Each customer is an org.

```
Platform
├── Customer A (org)
│   ├── Users: alice, bob
│   ├── Teams: engineering, sales
│   └── API Keys: ci-runner
├── Customer B (org)
│   ├── Users: carol, dave
│   └── Teams: dev
└── Service Orgs (infra)
    ├── Resource Service (org)
    ├── Billing Service (org)
    └── Sandbox Platform (org)
```

**TenantConfig:**
```python
tenant_config = TenantConfig(
    enforce_tenant_isolation=True,
    enforce_org_isolation=True,
    allow_cross_tenant_admin=True,       # Platform support staff
    cross_tenant_permission="myservice.cross_tenant",
    enable_org_hierarchy=False,          # No nested orgs
    allow_ancestor_access=False,
    allow_descendant_access=False,
)
```

**When to use:** You have independent customers who shouldn't see each other. No parent/child relationships. This is the simplest and most common pattern.

---

### Pattern 2: Enterprise with Departments

**When:** Large enterprises want sub-orgs for departments, each with their own resource budgets and admin.

```
Acme Corp (parent org)
├── Engineering (child org)
│   ├── Backend Team
│   ├── Frontend Team
│   └── DevOps Team
├── Finance (child org)
│   └── Accounting Team
└── Sales (child org)
    ├── Enterprise Team
    └── SMB Team
```

**TenantConfig:**
```python
tenant_config = TenantConfig(
    enforce_tenant_isolation=True,
    enforce_org_isolation=True,
    allow_cross_tenant_admin=True,
    cross_tenant_permission="myservice.cross_tenant",
    enable_org_hierarchy=True,           # Parent/child orgs
    allow_ancestor_access=True,          # Acme Corp admin can see all departments
    allow_descendant_access=False,       # Engineering can't see Finance's data
)
```

**WHY `allow_ancestor_access=True`:** The parent org is typically the billing/management entity. The CTO needs visibility across all engineering resources. Without ancestor access, they'd need `cross_tenant` (too powerful) or separate logins per department (terrible UX).

**WHY `allow_descendant_access=False`:** If Engineering could see Finance's data, any engineer could view salary information and financial reports. Departments should be isolated from each other; only the parent can look down.

---

### Pattern 3: Marketplace / Platform-of-Platforms

**When:** Your platform hosts other companies that themselves have customers.

```
Platform
├── ISV Partner A (org)           ← The software vendor
│   ├── Partner A's Customer 1 (child org)
│   ├── Partner A's Customer 2 (child org)
│   └── Partner A's Customer 3 (child org)
├── ISV Partner B (org)
│   └── Partner B's Customer 1 (child org)
└── Direct Customers (orgs)
    ├── Customer X (org)
    └── Customer Y (org)
```

**This requires:**
- Org hierarchy (partners manage their customers)
- `allow_ancestor_access=True` (partner sees all their customers)
- `allow_descendant_access=False` (customers don't see partner internals)
- Teams within each customer org for fine-grained access

---

### Pattern 4: Service Mesh (Inter-Service Communication)

**When:** Multiple microservices need to call each other.

```
┌─────────────────┐     API Key      ┌─────────────────┐
│ Sandbox Platform │ ──────────────→  │ Resource Service │
│ (org: sandbox)   │                  │ (org: resource)  │
│                  │                  │                  │
│ Has API key      │                  │ Validates key    │
│ created in       │                  │ against its own  │
│ RESOURCE org     │                  │ org permissions   │
└─────────────────┘                  └─────────────────┘
```

**Key rule:** API keys are created in the **target** service's org, not the caller's org. The Sandbox Platform holds a key that was created in the Resource Service's org with `resource.create.allocations` permission.

See [Section 4](#4-service-accounts--inter-service-auth) for details.

---

## 4. Service Accounts & Inter-Service Auth

### What Is a Service Account?

A service account is a machine identity — a credential for automated systems, scripts, or service-to-service calls. There are two ways to create one:

**Option 1: API Key (recommended for most cases)** — Create an API key via `POST /api-keys/` within an org. Simple, no user entity needed. This is what the registration scripts use and what most inter-service communication relies on.

**Option 2: Dedicated Service Account** — Create via `POST /admin/users/create-service-account`. This creates a user entity with `account_type: "service"` (exempt from password rotation) and auto-generates an API key. Use this when you need a trackable identity with audit trail tied to a user entity, or when enterprise compliance requires named machine identities.

### Creating a Service Account

**Option 1: API Key (simpler)**

```bash
# 1. Log in as the admin of the TARGET service's org
TOKEN=$(curl -s -X POST "$AUTH_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "mike+resource@ab0t.com",
    "password": "...",
    "org_id": "020caf72-d9cd-48b1-bbfc-2bc8c67f0cc5"
  }' | jq -r '.access_token')

# 2. Create an API key with minimal permissions
curl -s -X POST "$AUTH_URL/api-keys/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "sandbox-platform-service-account",
    "permissions": [
      "resource.create.allocations",
      "resource.read",
      "resource.delete",
      "resource.scale"
    ],
    "metadata": {
      "purpose": "Sandbox Platform → Resource Service",
      "created_by": "platform-team",
      "environment": "production"
    }
  }'
```

**Option 2: Dedicated Service Account (enterprise)**

```bash
curl -s -X POST "$AUTH_URL/admin/users/create-service-account" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "ci-runner@acme.internal",
    "name": "Acme CI Runner",
    "description": "CI/CD pipeline for production deployments",
    "permissions": ["resource.create.allocations", "resource.read"],
    "org_id": "acme-corp-uuid"
  }'
# Returns: { id: "svc_...", email, api_key: "sk_..." (shown once), permissions }
```

### Which Approach to Use?

| | API Key (`POST /api-keys/`) | Service Account (`POST /admin/.../create-service-account`) |
|---|---|---|
| **Complexity** | Simple — just a key | Creates user entity + key |
| **Identity** | Key string only | Named user (`svc_` prefix) + key |
| **Audit trail** | Key ID in logs | User ID + key ID in logs |
| **Password policy** | N/A | Exempt from rotation |
| **Best for** | Inter-service calls, scripts, CI/CD | Enterprise compliance, named machine identities |
| **Used by** | Registration scripts, most services | Enterprise admin workflows |

**Rule of thumb:** Start with an API key. It's simpler and covers 90% of use cases. Use dedicated service accounts when compliance or audit requirements demand a named machine identity.

### Service Account vs Human User

| | Human User | Service Account (API Key) |
|---|---|---|
| **Identity** | Email + password | Key string (`ab0t_sk_...`) or `svc_` user + key |
| **Auth method** | JWT (short-lived, 15min) | API Key (long-lived, no expiry) |
| **Permissions** | Granted to user, inherited from teams/roles | Explicit list on the key |
| **Org context** | Belongs to org via membership | Belongs to org where key was created |
| **Revocation** | Deactivate user, revoke sessions | `DELETE /api-keys/{id}` |
| **Rotation** | Password change | Create new key, update config, delete old |
| **Use case** | Interactive (browser, CLI) | Automated (service-to-service, CI/CD) |

### Service Account Best Practices

1. **One key per calling service** — Sandbox Platform gets its own key, API Gateway gets its own key. Don't share keys.
2. **Minimal permissions** — Only the permissions the calling service actually needs. Never `admin` or `cross_tenant` unless absolutely required.
3. **Descriptive metadata** — Include `purpose`, `created_by`, `environment` so you can audit later.
4. **Track key IDs** — Store the key ID (not just the key string) so you can update permissions later with `PUT /api-keys/{id}`.
5. **Rotate periodically** — Create new key → update caller's config → verify → delete old key.

### The Service Account Trap

The registration script (`register-service-permissions.sh`) creates an API key in step 5. If you re-run the script after adding new permissions, it **reuses the existing key without updating its permissions**. You must manually update:

```bash
# Find the key ID
KEY_ID=$(curl -s "$AUTH_URL/api-keys/" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

# Update with new permissions
curl -s -X PUT "$AUTH_URL/api-keys/$KEY_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "permissions": [
      "resource.create.allocations",
      "resource.read",
      "resource.delete",
      "resource.scale",
      "resource.read.costs"
    ]
  }'
```

---

## 5. Nested Organizations

### When to Use Nested Orgs

Use nested orgs when:
- A customer has **departments that need separate resource budgets** (Engineering vs Finance)
- A partner manages **sub-customers** that should be isolated from each other
- You need **billing rollup** where a parent pays for all children
- **Compliance** requires that different business units have separate data boundaries

Do NOT use nested orgs when:
- You just need to group users → use teams instead
- Users need access across departments → use permissions or cross_tenant
- You have flat customers with no internal structure → use single org + teams

### Creating an Org Hierarchy

```bash
# 1. Create parent org
PARENT=$(curl -s -X POST "$AUTH_URL/organizations/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corporation",
    "slug": "acme-corp"
  }')
PARENT_ID=$(echo "$PARENT" | jq -r '.id')

# 2. Create child orgs with parent_id
curl -s -X POST "$AUTH_URL/organizations/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Engineering",
    "slug": "acme-engineering",
    "parent_id": "'"$PARENT_ID"'"
  }'

curl -s -X POST "$AUTH_URL/organizations/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Finance",
    "slug": "acme-finance",
    "parent_id": "'"$PARENT_ID"'"
  }'
```

### Viewing the Hierarchy

```bash
# Get full hierarchy tree
curl -s "$AUTH_URL/organizations/$PARENT_ID/hierarchy" \
  -H "Authorization: Bearer $TOKEN" | jq

# Visualize with users and teams
curl -s -X POST "$AUTH_URL/zanzibar/visualize/hierarchy" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "'"$PARENT_ID"'",
    "include_users": true,
    "include_teams": true,
    "max_depth": 5
  }' | jq
```

### Setting Up Hierarchy in Zanzibar

For the relationship-based access model to understand your org tree:

```bash
# Register parent → child relationship
curl -s -X POST "$AUTH_URL/zanzibar/hierarchy/setup" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "'"$CHILD_ORG_ID"'",
    "parent_org_id": "'"$PARENT_ID"'"
  }'
```

### How Hierarchy Affects Access

With the TenantConfig from Pattern 2:

| User's Org | Target Resource's Org | `allow_ancestor_access` | `allow_descendant_access` | Result |
|---|---|---|---|---|
| Acme Corp (parent) | Acme Engineering (child) | `True` | - | **Allowed** — parent can see child |
| Acme Engineering | Acme Corp (parent) | - | `False` | **Denied** — child can't see parent |
| Acme Engineering | Acme Finance (sibling) | - | - | **Denied** — siblings can't see each other |
| Acme Corp | Acme Corp | - | - | **Allowed** — same org |

### Org Hierarchy in Your Code

The library's `TenantContext` handles hierarchy automatically when `enable_org_hierarchy=True`:

```python
from ab0t_auth.tenant import TenantContext, Organization, OrgRelationship

# The TenantContext knows the full org path
# ctx.org_path = ("acme-corp", "acme-engineering")

# Check relationship
ctx.can_access_org(
    target_org_id="child-org-id",
    allow_ancestors=True,      # Mirrors TenantConfig
    allow_descendants=False,
)

# Or in get_user_filter, hierarchy is respected:
def get_user_filter(user: AuthenticatedUser) -> dict:
    if user.has_permission("myservice.cross_tenant"):
        return {}
    if user.has_permission("myservice.admin"):
        # With hierarchy enabled, this returns org_id + all child org IDs
        return {"org_id": {"$in": get_accessible_org_ids(user)}}
    return {"user_id": user.user_id, "org_id": user.org_id}
```

---

## 6. Team Hierarchies

### Teams vs Orgs: When to Use Which

| Question | Use Teams | Use Nested Orgs |
|---|---|---|
| Do they need separate billing? | No → Teams | Yes → Orgs |
| Do they need hard data isolation? | No → Teams | Yes → Orgs |
| Do they share some resources? | Yes → Teams | No → Orgs |
| Is this a department in a company? | Usually Teams | Only if strict isolation needed |
| Is this a separate customer? | Never Teams | Yes → Orgs |
| Can users belong to multiple? | Yes → Teams | No (1 org per context) |

**Rule of thumb:** Teams are **soft boundaries** (grouping, permission inheritance). Orgs are **hard boundaries** (data isolation, separate namespaces).

### Creating a Team Hierarchy

```bash
# Create parent team
ENGINEERING=$(curl -s -X POST "$AUTH_URL/organizations/$ORG_ID/teams" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineering",
    "description": "All engineering staff",
    "permissions": ["myservice.read"]
  }')
ENG_TEAM_ID=$(echo "$ENGINEERING" | jq -r '.id')

# Create child teams
curl -s -X POST "$AUTH_URL/organizations/$ORG_ID/teams" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Backend",
    "description": "Backend engineering",
    "parent_team_id": "'"$ENG_TEAM_ID"'",
    "permissions": ["myservice.create.allocations", "myservice.execute.instances"]
  }'

curl -s -X POST "$AUTH_URL/organizations/$ORG_ID/teams" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Frontend",
    "description": "Frontend engineering",
    "parent_team_id": "'"$ENG_TEAM_ID"'",
    "permissions": ["myservice.read"]
  }'
```

### How Team Permissions Inherit

```
Engineering (team)
  permissions: [myservice.read]
    │
    ├── Backend (child team)
    │   permissions: [myservice.create.allocations, myservice.execute.instances]
    │   effective:   [myservice.read, myservice.create.allocations, myservice.execute.instances]
    │                ↑ inherited from parent
    │
    └── Frontend (child team)
        permissions: [myservice.read]
        effective:   [myservice.read]
```

Members of a child team inherit all permissions from parent teams. A Backend engineer gets `myservice.read` from Engineering plus `myservice.create.allocations` and `myservice.execute.instances` from Backend.

### Managing Team Members

```bash
# Add user to team
curl -s -X POST "$AUTH_URL/teams/$TEAM_ID/members" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user-uuid", "role": "member"}'

# Team roles: "member" (default) or "leader"
# Leaders can manage team members

# List team members
curl -s "$AUTH_URL/teams/$TEAM_ID/members" \
  -H "Authorization: Bearer $TOKEN" | jq

# Update role
curl -s -X PUT "$AUTH_URL/teams/$TEAM_ID/members/$USER_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "leader"}'

# Remove from team
curl -s -X DELETE "$AUTH_URL/teams/$TEAM_ID/members/$USER_ID" \
  -H "Authorization: Bearer $TOKEN"

# Check team permissions
curl -s "$AUTH_URL/teams/$TEAM_ID/permissions" \
  -H "Authorization: Bearer $TOKEN" | jq
```

### Teams in Zanzibar

Teams integrate with the relationship-based access model:

```bash
# Grant a team access to a resource
curl -s -X POST "$AUTH_URL/zanzibar/relationships" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "object": "document:doc_123",
    "relation": "editor",
    "subject": "team:backend"
  }'

# All Backend team members can now edit doc_123

# Manage team membership via Zanzibar
curl -s -X POST "$AUTH_URL/zanzibar/teams/membership" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user-uuid",
    "team_id": "backend",
    "role": "member"
  }'
```

---

## 7. Delegation (Act-As)

### What Delegation Solves

**Problem:** Alice (CEO) needs Bob (assistant) to manage her calendar. Options:
1. Share password — insecure, no audit trail
2. Give Bob all of Alice's permissions — too broad, persists forever
3. Make Bob admin — overkill
4. **Delegation** — scoped, time-limited, audited

### How It Works

```
Alice (target) ──grants delegation──→ Bob (actor)
                   ↓
         Scoped to: calendar.read, calendar.write
         Expires: 2026-12-31
                   ↓
Bob creates delegated token:
  POST /auth/delegate { target_user_id: "alice" }
                   ↓
Delegated token contains:
  sub (subject): alice     ← Actions appear as Alice
  act (actor): bob         ← Audit trail shows Bob
                   ↓
Bob uses delegated token to call services
  → Service sees Alice's identity
  → Audit log records "Bob acting as Alice"
```

### Setting Up Delegation

```bash
# Alice grants Bob permission to act on her behalf
curl -s -X POST "$AUTH_URL/delegation/grant" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "actor_id": "user_bob",
    "scope": ["calendar.read", "calendar.write", "email.send"],
    "expires_in_hours": 720
  }'

# Bob creates a delegated token
curl -s -X POST "$AUTH_URL/auth/delegate" \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_user_id": "user_alice"}'

# Check if delegation exists
curl -s "$AUTH_URL/delegation/check/user_alice?acting_as=user_bob" \
  -H "Authorization: Bearer $TOKEN"

# List all delegations for a user
curl -s "$AUTH_URL/delegation/list/user_alice" \
  -H "Authorization: Bearer $TOKEN"

# Revoke
curl -s -X DELETE "$AUTH_URL/delegation/revoke/user_bob" \
  -H "Authorization: Bearer $ALICE_TOKEN"
```

### Delegation Use Cases

| Scenario | Actor | Target | Scope | Duration |
|---|---|---|---|---|
| Executive assistant | Assistant | CEO | calendar.*, email.send | Long-term (months) |
| Support debugging | Support agent | Customer user | *.read | Short (hours) |
| Vacation coverage | Colleague | Absent employee | specific workflows | 1-2 weeks |
| Automated system | Service account | Any user | specific actions | Permanent |

### Delegation vs Cross-Tenant vs Admin

| Capability | Admin | Cross-Tenant | Delegation |
|---|---|---|---|
| Scope | Own org | All orgs | Specific user |
| Permissions | All in role | All in role | Only granted scope |
| Audit trail | "Admin did X" | "Admin did X in Org B" | "Bob did X as Alice" |
| Time-limited | No | No | Yes (expires_in_hours) |
| Requires approval | No | Requires explicit grant | Target user must grant |
| Use case | Org management | Platform support | Acting on behalf of |

---

## 8. Cross-Service Permission Mesh

### The Problem

You have 9 microservices. Some need to call each other. How do you manage the permissions?

### The Architecture

```
                    ┌──────────────────┐
                    │   Auth Service    │
                    │  (central brain)  │
                    │                  │
                    │  Orgs:           │
                    │  - resource-svc  │
                    │  - sandbox-svc   │
                    │  - billing-svc   │
                    │  - audit-svc     │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
    ┌─────────▼──────┐ ┌────▼────────┐ ┌──▼──────────────┐
    │ Sandbox        │ │ Billing     │ │ Resource         │
    │ Platform       │ │ Service     │ │ Service          │
    │                │ │             │ │                  │
    │ Holds keys for:│ │ Holds keys  │ │ Holds keys for:  │
    │ - Resource Svc │ │ for:        │ │ - Billing Svc    │
    │ - Billing Svc  │ │ - Resource  │ │ - Tool Registry  │
    └────────────────┘ └─────────────┘ └──────────────────┘
```

### Setting Up a Service-to-Service Connection

**Scenario:** Sandbox Platform needs to call Resource Service.

```
Step 1: Resource Service has org "020caf72-..." with registered permissions
        (resource.create.allocations, resource.read, etc.)

Step 2: Admin of Resource Service org creates an API key
        with permissions Sandbox needs

Step 3: Sandbox Platform stores that API key in its config
        as RESOURCE_SERVICE_API_KEY

Step 4: Sandbox Platform sends X-API-Key header when calling
        Resource Service endpoints
```

### Permission Mesh Map

Document which service calls which, with what permissions:

| Caller | Target | API Key Created In | Permissions on Key |
|---|---|---|---|
| Sandbox Platform | Resource Service | Resource Svc org | `resource.create.allocations`, `resource.read`, `resource.delete`, `resource.scale` |
| Sandbox Platform | Billing Service | Billing Svc org | `billing.read.invoices`, `billing.create.charges` |
| Resource Service | Billing Service | Billing Svc org | `billing.create.charges`, `billing.read.costs` |
| API Gateway | All services | Each svc's org | `{service}.read` (health checks) |
| Audit Service | All services | Each svc's org | `{service}.read` (event collection) |

### Mesh Anti-Patterns

1. **Shared API keys** — using the same key for multiple callers. If one caller is compromised, all are.
2. **Over-permissioned keys** — giving a billing-reader key `billing.admin`. Least privilege always.
3. **Keys in wrong org** — creating the key in the caller's org instead of the target's. Permissions won't resolve.
4. **Circular dependencies** — Service A needs B, B needs A, both created during registration. Solve by registering services in dependency order.

---

## 9. Decision Trees

### "What org structure should I use?"

```
Start here: How many customers do you have?
│
├── 1 (internal tool)
│   └── Single org + teams for departments
│
├── Multiple independent customers
│   │
│   ├── Do customers need internal departments?
│   │   ├── No → Flat orgs (Pattern 1)
│   │   └── Yes → Nested orgs (Pattern 2)
│   │
│   └── Do some customers manage sub-customers?
│       └── Yes → Marketplace pattern (Pattern 3)
│
└── It's a platform of microservices
    └── One org per service + customer orgs (Pattern 4)
```

### "Should this be a team or a nested org?"

```
Does this group need:
│
├── Separate billing? → Nested org
├── Hard data isolation? → Nested org
├── Its own API keys? → Nested org
├── Members in multiple groups? → Teams (users can be in multiple teams)
├── Permission inheritance? → Teams (child teams inherit parent permissions)
└── Just access control grouping? → Teams
```

### "How should this user access another service?"

```
Who needs access?
│
├── A human user at a browser
│   └── JWT token (login → get token → use Bearer header)
│       └── Permissions checked against the service's org
│
├── A microservice calling another microservice
│   └── API Key (created in target service's org)
│       └── Sent via X-API-Key header
│
├── A script / CI/CD pipeline
│   └── API Key (created in the service's org with minimal perms)
│
├── A user acting on behalf of another user
│   └── Delegation (target grants → actor creates delegated token)
│
└── A support engineer accessing customer data
    └── Cross-tenant permission (explicitly granted, not implied by admin)
    └── Or: Super-admin (time-limited, requires justification + MFA)
```

---

## 10. API Reference (Quick)

### Organization Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/organizations/` | Create org (set `parent_id` for nesting) |
| `GET` | `/organizations/{org_id}` | Get org details |
| `PUT` | `/organizations/{org_id}` | Update org |
| `GET` | `/organizations/{org_id}/hierarchy` | Get org tree |
| `GET` | `/organizations/{org_id}/users` | List org members |
| `POST` | `/organizations/{org_id}/invite` | Invite user to org |
| `GET` | `/organizations/{org_id}/invitations` | List pending invites |
| `DELETE` | `/organizations/{org_id}/invitations/{id}` | Cancel invite |
| `GET` | `/organizations/{org_id}/sessions` | View active sessions |
| `DELETE` | `/organizations/{org_id}/sessions` | Revoke all sessions |
| `POST` | `/auth/switch-organization` | Switch user's active org |
| `GET` | `/users/me/organizations` | List my orgs |

### Team Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/organizations/{org_id}/teams` | Create team (set `parent_team_id` for nesting) |
| `GET` | `/organizations/{org_id}/teams` | List org's teams |
| `GET` | `/teams/{team_id}` | Get team details |
| `PUT` | `/teams/{team_id}` | Update team |
| `DELETE` | `/teams/{team_id}` | Delete team |
| `POST` | `/teams/{team_id}/members` | Add member |
| `GET` | `/teams/{team_id}/members` | List members |
| `PUT` | `/teams/{team_id}/members/{user_id}` | Update member role |
| `DELETE` | `/teams/{team_id}/members/{user_id}` | Remove member |
| `GET` | `/teams/{team_id}/permissions` | Get team permissions |

### Delegation Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/delegation/grant` | Grant delegation (actor_id, scope, expires) |
| `GET` | `/delegation/check/{target_user_id}` | Check if delegation exists |
| `GET` | `/delegation/list/{user_id}` | List user's delegations |
| `DELETE` | `/delegation/revoke/{actor_id}` | Revoke delegation |
| `POST` | `/auth/delegate` | Create delegated token |

### Super-Admin Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/super-admin/grant` | Request elevated access (justification + MFA) |
| `POST` | `/super-admin/approve` | Approve another admin's request |
| `POST` | `/super-admin/extend` | Extend time on active grant |
| `POST` | `/super-admin/revoke` | Revoke elevated access |
| `GET` | `/super-admin/active-grants` | List who has super-admin now |
| `GET` | `/super-admin/audit-log` | Audit trail of all grants |

### Zanzibar Endpoints (Relationship-Based Access)

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/zanzibar/relationships` | Create relationship (`doc:123#editor@user:alice`) |
| `DELETE` | `/zanzibar/relationships` | Remove relationship |
| `GET` | `/zanzibar/relationships/{type}/{id}` | Get relationships for object |
| `POST` | `/zanzibar/check` | Check permission (does user have access?) |
| `POST` | `/zanzibar/check/bulk` | Check multiple permissions at once |
| `POST` | `/zanzibar/expand` | Who has this permission? (debug) |
| `POST` | `/zanzibar/namespaces` | Register custom namespace/schema |
| `GET` | `/zanzibar/namespaces` | List namespaces |
| `POST` | `/zanzibar/hierarchy/setup` | Set up org hierarchy in Zanzibar |
| `POST` | `/zanzibar/visualize/hierarchy` | Visualize org tree |
| `POST` | `/zanzibar/visualize/permissions` | Visualize user's permission paths |
| `POST` | `/zanzibar/teams/membership` | Manage team membership via Zanzibar |
| `POST` | `/zanzibar/migrate/setup-defaults` | Set up default namespaces |
| `POST` | `/zanzibar/migrate/permissions` | Migrate flat perms to relationships |

---

## 11. Common Mistakes & Anti-Patterns

### 1. Using Orgs When You Should Use Teams

**Mistake:** Creating a separate org for each department in a company.

**Why it's wrong:** Users in different department-orgs can't collaborate. Shared resources become impossible. The admin has to manage N orgs instead of 1.

**Fix:** Use one org per company, teams for departments. Orgs are for **hard** isolation (different customers). Teams are for **soft** isolation (different departments).

**Exception:** Use nested orgs when departments truly need separate billing, compliance boundaries, or hard data isolation (e.g., Finance cannot share data with Engineering for regulatory reasons).

### 2. Putting All Services in One Org

**Mistake:** Registering Resource Service, Billing Service, and Sandbox Platform all in the same org.

**Why it's wrong:** If one service's admin credentials are compromised, the attacker can modify permissions for all services. A `billing.admin` key could be used to grant `resource.admin`.

**Fix:** One org per service. Each service's permissions live in its own security boundary.

### 3. Confusing `admin` with `cross_tenant`

**Mistake:** Granting `cross_tenant` to org admins, or assuming admin implies cross_tenant.

**Why it's wrong:**
- `admin` = "manage everything in YOUR org" (org-scoped)
- `cross_tenant` = "access ANY org" (platform-scoped)

An admin in Acme Corp should manage Acme Corp. They should NOT see Widgets Inc's data. `cross_tenant` is for platform support staff only.

**Fix:** Never put `cross_tenant` in `implies` for admin. Always grant it separately and explicitly.

### 4. Circular Service Dependencies

**Mistake:** Service A's registration script creates a key in Service B's org, but Service B isn't registered yet.

**Why it's wrong:** The key creation fails because Service B's org doesn't exist.

**Fix:** Register services in dependency order. If circular, register both orgs first, then create keys.

### 5. Not Updating API Key Permissions After Adding New Permissions

**Mistake:** Adding `resource.read.costs` to `.permissions.json`, re-running registration, assuming the existing API key now has the new permission.

**Why it's wrong:** Registration script reuses existing keys without updating permissions.

**Fix:** After adding new permissions, explicitly update the key: `PUT /api-keys/{id}` with the full permission list.

### 6. No Hierarchy When You Need One

**Mistake:** Using flat orgs for a company with strict departmental isolation needs, then trying to hack cross-org access with `cross_tenant`.

**Why it's wrong:** `cross_tenant` is too broad — it grants access to ALL orgs, not just the sibling departments. And it bypasses all org isolation.

**Fix:** Use nested orgs. Parent org admin can see all children. Children are isolated from each other. No `cross_tenant` needed.

### 7. Treating Delegation Like Permission Granting

**Mistake:** Using delegation to permanently give Bob access to resources instead of granting Bob his own permissions.

**Why it's wrong:** Delegation creates tokens that act as the target user. If Alice's account is disabled, Bob's delegated access breaks. And the audit trail shows "Alice" doing things that were actually Bob's intent.

**Fix:** Use delegation for temporary, scoped access. For permanent access, grant permissions directly or add the user to the right team.

---

## 12. Worked Examples

### Example A: SaaS Startup

**Situation:** You're building a project management tool. You have 50 small business customers, each with 5-20 users.

**Structure:**
```
Platform
├── Customer orgs (50)
│   └── Each has: users, maybe 1-2 teams
└── Service orgs
    ├── project-service (org)
    ├── billing-service (org)
    └── notification-service (org)
```

**TenantConfig:** Simple. No hierarchy.
```python
TenantConfig(
    enforce_tenant_isolation=True,
    enforce_org_isolation=True,
    enable_org_hierarchy=False,
)
```

**Teams:** Optional. Small companies might not need them.

---

### Example B: Enterprise SaaS

**Situation:** You sell to Fortune 500 companies. Acme Corp has 5,000 employees across 4 divisions, each with their own VP and budget.

**Structure:**
```
Acme Corp (parent org)
├── Engineering (child org)
│   ├── Backend Team
│   ├── Frontend Team
│   ├── QA Team
│   └── DevOps Team
├── Sales (child org)
│   ├── Enterprise Team
│   └── SMB Team
├── Finance (child org)
│   └── Accounting Team
└── Legal (child org)
```

**TenantConfig:**
```python
TenantConfig(
    enforce_tenant_isolation=True,
    enforce_org_isolation=True,
    enable_org_hierarchy=True,
    allow_ancestor_access=True,     # Acme Corp CTO sees all divisions
    allow_descendant_access=False,  # Divisions can't see each other
)
```

**Why child orgs, not teams?** Because:
- Each division has its own budget (billing isolation)
- Legal requires that Finance data is firewalled from Engineering
- Each division VP needs admin access only to their division
- Teams are used WITHIN each division for finer grouping

---

### Example C: Platform with Partners

**Situation:** You run a cloud platform. Partners (ISVs) resell your services to their own customers.

**Structure:**
```
Platform
├── Partner: CloudTools Inc (org)
│   ├── CloudTools Customer 1 (child org)
│   ├── CloudTools Customer 2 (child org)
│   └── CloudTools Customer 3 (child org)
├── Partner: DevOps Pro (org)
│   └── DevOps Pro Customer 1 (child org)
└── Direct Customers
    ├── Startup X (org, no parent)
    └── Startup Y (org, no parent)
```

**Key decisions:**
- Partners can see all their customers (`allow_ancestor_access=True`)
- Customers can't see partner internals (`allow_descendant_access=False`)
- Customers can't see each other (sibling isolation)
- Direct customers have no parent (flat orgs)
- Partner gets `{service}.admin` in their org, which cascades to children
- `cross_tenant` only for your platform support staff

---

### Example D: Inter-Service Mesh

**Situation:** 4 services need to communicate.

**Permission mesh:**
```
Sandbox Platform ──→ Resource Service
  Key: "sandbox-to-resource"
  Permissions: resource.create.allocations, resource.read,
               resource.delete, resource.scale

Sandbox Platform ──→ Billing Service
  Key: "sandbox-to-billing"
  Permissions: billing.create.charges, billing.read.invoices

Resource Service ──→ Billing Service
  Key: "resource-to-billing"
  Permissions: billing.create.charges, billing.read.costs

All Services ──→ Auth Service
  Built-in: JWKS fetch (no key needed), token validation
```

**Setup script order:**
1. Auth Service (always first — others depend on it)
2. Resource Service (register org + permissions)
3. Billing Service (register org + permissions)
4. Sandbox Platform (register org + create keys in Resource + Billing orgs)
5. Create inter-service keys

---

## Related Files

| File | When to Read |
|---|---|
| [org-hierarchy-guide-additional_detail.md](org-hierarchy-guide-additional_detail.md) | Deep dive into the "everything is an org" mental model, worked scenarios, common agent mistakes |
| [auth-service-organization-guide.md](auth-service-organization-guide.md) | Enterprise features: OAuth, super-admin, delegation details, Zanzibar advanced |
| [implementation-details.md](implementation-details.md) | TenantConfig in code, check callbacks, type aliases |
| [registration.md](registration.md) | Registration script, API key creation |
| [auth-service-api.md](auth-service-api.md) | Full endpoint reference |
| [FAQ.md](FAQ.md) | Common questions (Section 6: Multi-Tenancy) |
