# Organization Architecture: The "Everything Is an Org" Deep Dive

**Why this file exists:** Agents and developers consistently get confused about how orgs, teams, users, and service accounts relate to each other. The root cause is that our auth system uses a **single universal primitive — the org** — for concepts that other systems represent as separate entity types. This file explains the mental model deeply, with concrete examples and decision frameworks.

---

## Table of Contents

1. [The Core Mental Model](#1-the-core-mental-model)
2. [The Org as Universal Primitive](#2-the-org-as-universal-primitive)
3. [Org Types in Practice](#3-org-types-in-practice)
4. [Personal Workspaces](#4-personal-workspaces)
5. [Service Orgs (Service Accounts)](#5-service-orgs-service-accounts)
6. [Customer Orgs](#6-customer-orgs)
7. [Nested Orgs (Departments, Sub-Customers)](#7-nested-orgs-departments-sub-customers)
8. [Teams-as-Orgs vs Traditional Teams](#8-teams-as-orgs-vs-traditional-teams)
9. [The Registration Flow Dissected](#9-the-registration-flow-dissected)
10. [Permission Scoping and the Org Boundary](#10-permission-scoping-and-the-org-boundary)
11. [User Membership and Multi-Org Access](#11-user-membership-and-multi-org-access)
12. [Delegation and Act-As Patterns](#12-delegation-and-act-as-patterns)
13. [Cross-Org Mesh Access](#13-cross-org-mesh-access)
14. [The Zanzibar Layer](#14-the-zanzibar-layer)
15. [Architecture Decision Framework](#15-architecture-decision-framework)
16. [Real-World Scenarios (Worked End-to-End)](#16-real-world-scenarios-worked-end-to-end)
17. [What Agents Get Wrong (and Why)](#17-what-agents-get-wrong-and-why)

---

## 1. The Core Mental Model

### Forget Everything You Know About "Organizations"

In most auth systems:
- An **org** is a company
- A **team** is a department within a company
- A **user** is a person
- A **service account** is a machine identity

These are separate entity types with separate tables, separate APIs, and separate mental models.

**Our system is different. There is only one primitive: the org.**

```
Traditional System:              Our System:
┌──────────┐                     ┌──────────────────────┐
│  User    │                     │                      │
├──────────┤                     │        Org           │
│  Team    │                     │                      │
├──────────┤         →           │  (everything is one) │
│  Org     │                     │                      │
├──────────┤                     │                      │
│  Service │                     └──────────────────────┘
│  Account │                       ↑ type determines behavior
└──────────┘
```

An org is a **workspace** — an isolated namespace where permissions exist, resources live, and identities operate. What makes one org different from another isn't its entity type — it's its **configuration**:

| Traditional Concept | In Our System | Org Settings |
|---|---|---|
| Customer company | Org with `type: "customer"` | `is_personal: false`, has users, teams |
| Department | Child org with `parent_id` | Nested under company org |
| Team | Org or team-within-org | `parent_team_id` for nesting |
| User workspace | Org with `is_personal: true` | One owner, personal resources |
| Microservice | Org with `type: "platform_service"` | API keys, no human users |
| Service account | API key within a service org | Permissions on the key |

### Why This Design?

**Uniformity.** Every isolation boundary works the same way:
- Same permission model
- Same API endpoints (`/organizations/`, `/organizations/{id}/users`, etc.)
- Same nesting mechanism (`parent_id`)
- Same access control (Phase 1 + Phase 2 + `get_user_filter()`)
- Same Zanzibar relationships

You don't need to learn separate APIs for "team permissions" vs "org permissions" vs "service account permissions." It's all just org permissions.

**Flexibility.** The system doesn't constrain you into a fixed hierarchy:
- A startup might have 1 org with 3 users and no teams
- An enterprise might have 50 nested orgs with 200 teams
- A platform might have 9 service orgs, 500 customer orgs, and cross-org mesh access
- A user might have a personal workspace org plus membership in 3 company orgs

All of these use the exact same primitives.

---

## 2. The Org as Universal Primitive

### What an Org Actually Contains

```
┌────────────────────────────────────────────────────┐
│  Organization (Org)                                │
│                                                    │
│  Identity:                                         │
│    id:         "020caf72-d9cd-48b1-..."           │
│    name:       "Resource Service"                  │
│    slug:       "resource-service"                  │
│    domain:     "resource.service.ab0t.com"         │
│    status:     "active" | "suspended" | "trial"    │
│                                                    │
│  Hierarchy:                                        │
│    parent_id:  null | "parent-org-uuid"            │
│    billing_type: "prepaid" | "postpaid" | "enterprise" │
│                                                    │
│  Configuration:                                    │
│    settings:   { type, hierarchical, ... }         │
│    metadata:   { description, capabilities, ... }  │
│    timezone:   "UTC"                               │
│                                                    │
│  Contains:                                         │
│    ├── Users (members with roles)                  │
│    ├── Teams (groupings within the org)            │
│    ├── API Keys (machine identities)               │
│    ├── Permissions (registered for this org)        │
│    ├── Resources (data scoped to this org)          │
│    └── Child Orgs (nested under parent_id)         │
│                                                    │
│  Security:                                         │
│    - JWKS keys (per-org key sets possible)         │
│    - Sessions (active user sessions)               │
│    - Invitations (pending invites)                 │
└────────────────────────────────────────────────────┘
```

### The `UserOrganizationInfo` Object

When you call `GET /users/me/organizations`, you get back a list of orgs the user belongs to. Each one has:

```json
{
  "id": "020caf72-...",
  "name": "Resource Service",
  "type": "platform_service",
  "role": "admin",
  "is_personal": false,
  "is_default": true,
  "joined_at": "2026-01-15T10:00:00Z",
  "permissions": ["resource.admin", "resource.read", "..."]
}
```

Key fields:
- **`type`** — what kind of org this is. Not an enum in the schema, but convention drives it: `"platform_service"`, `"customer"`, `"personal"`, etc.
- **`is_personal`** — this is a personal workspace for one user (like a GitHub personal account)
- **`is_default`** — the org context used when the user logs in without specifying `org_id`
- **`role`** — the user's role in this org
- **`permissions`** — the user's effective permissions in this org

This object is the proof that "everything is an org" — it returns the same shape whether the org represents a company, a service, or a personal workspace.

### The Org Lifecycle

```
Create ──→ Active ──→ Suspended ──→ Active (reactivated)
                  └──→ Trial ──→ Active (converted)
                  └──→ (deleted, if supported)

Status enum: "active" | "suspended" | "trial"
Billing enum: "prepaid" | "postpaid" | "enterprise"
```

Orgs can be suspended (all access blocked), put on trial (limited features/quotas), or kept active. The status applies to the org as a whole — if an org is suspended, all users in it lose access to that org's resources.

---

## 3. Org Types in Practice

The `settings.type` field on an org determines its purpose. This is a convention, not a hard enum — you can set any string. But the platform recognizes these patterns:

### Type: `platform_service`

**What it represents:** A microservice in the platform infrastructure.

**Characteristics:**
- Created by the registration script
- Has an admin account (usually `mike+{service}@ab0t.com`)
- Has API keys for inter-service communication
- Typically no human users besides the admin
- Permissions are registered here (e.g., `resource.read`, `resource.create.allocations`)
- `billing_type: "enterprise"` (platform services don't pay per usage)
- `hierarchical: false` (services don't nest under each other)

**Example:** The Resource Service org (`020caf72-...`)
```json
{
  "name": "Resource Service",
  "slug": "resource-service",
  "settings": {
    "type": "platform_service",
    "service": "resource",
    "hierarchical": false,
    "internal_service": false,
    "resource_features": {
      "quota_management": true,
      "allocation_tracking": true,
      "usage_metering": true,
      "auto_scaling": true
    }
  }
}
```

### Type: `customer` (or similar)

**What it represents:** A paying customer/tenant on the platform.

**Characteristics:**
- Created when a customer signs up or is onboarded
- Has human users who log in via browser/API
- Has teams for internal grouping
- May have child orgs for departments
- May have API keys for their own automation/CI
- `billing_type: "prepaid"` or `"postpaid"`
- Resources (allocations, sandboxes, etc.) belong to this org

**Example:**
```json
{
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "domain": "acme.com",
  "billing_type": "postpaid",
  "industry": "technology",
  "size": "enterprise",
  "settings": {
    "type": "customer",
    "hierarchical": true
  }
}
```

### Type: Personal Workspace

**What it represents:** A single user's personal space (like a GitHub personal account).

**Characteristics:**
- `is_personal: true` on the `UserOrganizationInfo`
- One owner
- No teams (just the owner)
- Personal resources (experiments, dev sandboxes)
- Often the `is_default: true` org for new users

**Example:** When a user first signs up, they might get a personal org automatically:
```json
{
  "name": "alice's workspace",
  "is_personal": true,
  "is_default": true,
  "settings": {
    "type": "personal"
  }
}
```

### Type: Department / Business Unit

**What it represents:** A sub-division of a customer org.

**Characteristics:**
- Has `parent_id` pointing to the parent customer org
- Users belong to the department org, not the parent
- Has its own budget/quotas (separate from siblings)
- Parent org admin can see into it (`allow_ancestor_access`)
- Cannot see sibling departments or parent internals

**Example:**
```json
{
  "name": "Acme Engineering",
  "slug": "acme-engineering",
  "parent_id": "acme-corp-uuid",
  "billing_type": "enterprise",
  "settings": {
    "type": "department",
    "hierarchical": false
  }
}
```

---

## 4. Personal Workspaces

### The Mental Model

Think of GitHub: every user has a personal account AND can belong to organizations. Your personal repos live under your account. Org repos live under the org.

Our system works the same way. A user can have:
- A **personal org** (their own workspace, `is_personal: true`)
- Membership in **multiple customer/team orgs** (companies they work for)

### How It Works

```
User: Alice
├── alice's workspace (personal org, is_personal: true, is_default: true)
│   └── Alice's personal resources (experiments, dev work)
│
├── Acme Corporation (customer org, role: "member")
│   └── Acme's shared resources (production allocations)
│
└── StartupX (customer org, role: "admin")
    └── StartupX's resources
```

When Alice logs in without specifying an `org_id`, she lands in her default org (personal workspace). To access Acme's resources, she switches:

```bash
# Switch to Acme Corporation context
curl -X POST "$AUTH_URL/auth/switch-organization" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"org_id": "acme-corp-uuid"}'
# Returns a new token scoped to Acme Corporation
```

### Why Personal Workspaces Matter

Without personal workspaces, every user must belong to an org before they can do anything. This creates friction:
- User signs up → "Which org?" → They don't have one yet → Dead end
- User leaves a company → Loses access to everything → Can't even use the platform

With personal workspaces:
- User signs up → Gets personal workspace immediately → Can experiment
- User joins a company → Gets added to company org → Can access shared resources
- User leaves company → Removed from company org → Still has personal workspace

### When to Use Personal Workspaces

| Scenario | Personal Workspace? |
|---|---|
| SaaS with individual users (like GitHub) | Yes |
| Enterprise-only (users always belong to a company) | Optional |
| B2B with strict company-only access | No — users only exist in company orgs |
| Platform with free tier for individuals | Yes — free tier = personal workspace |
| Developer platform with sandbox/playground | Yes — personal workspace IS the sandbox |

---

## 5. Service Orgs (Service Accounts)

### Why Services Are Orgs

A microservice needs an identity on the platform. It needs to:
- Register its permissions (`resource.read`, `resource.create.allocations`)
- Create API keys for other services to call it
- Have a namespace that isolates its permissions from other services

In our system, the service's **org IS its identity**. The registration script (step 2) creates an org for the service:

```bash
# From register-service-permissions.sh, step 2:
curl -s -X POST "$AUTH_SERVICE_URL/organizations/" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Resource Service",
    "slug": "resource-service",
    "domain": "resource-service.service.ab0t.com",
    "billing_type": "enterprise",
    "settings": {
      "type": "platform_service",
      "service": "resource",
      "hierarchical": false,
      "internal_service": false
    },
    "metadata": {
      "description": "Multi-cloud compute resource allocation and management service",
      "service_type": "resource_management",
      "data_classification": "standard"
    }
  }'
```

This org then becomes the container for:
- The service's registered permissions (step 4)
- The service's API keys (step 5)
- The service's admin user account

### The Service Org Contains No Customer Data

This is a critical distinction. The Resource Service org (`020caf72-...`) contains:
- Permission definitions (what `resource.read` means)
- API keys (credentials for other services to call Resource Service)
- An admin account (`mike+resource@ab0t.com`)

It does **NOT** contain:
- Customer allocations (those belong to customer orgs)
- Customer users (those belong to customer orgs)
- Customer billing data

Customer resources are tagged with the **customer's** org_id, not the service's org_id. When Sandbox Platform creates an allocation, the allocation's `org_id` is the Sandbox Platform's org (or the end customer's org), not the Resource Service's org.

### Service Accounts: Two Approaches

**Option 1: API Key (recommended, simpler)** — Create an API key via `POST /api-keys/` within a service org. The key IS the machine identity. This is what registration scripts use and covers most inter-service communication.

**Option 2: Dedicated Service Account** — Create via `POST /admin/users/create-service-account`. Creates a user entity with `account_type: "service"` (exempt from password rotation, `svc_` prefixed ID) and auto-generates an API key. Use when enterprise compliance requires named machine identities.

```
Service Org: "Resource Service" (020caf72-...)
├── Admin User: mike+resource@ab0t.com (manages the org)
├── API Key: "resource-internal" (all permissions, used by the service itself)
├── API Key: "sandbox-to-resource" (limited permissions, given to Sandbox Platform)
└── API Key: "billing-to-resource" (read-only, given to Billing Service)
```

For most cases, the API key approach is sufficient. The calling service stores the key in its config and sends it via `X-API-Key` header.

### How the Registration Script Creates This

Walking through `register-service-permissions.sh`:

```
Step 1: Create admin user (mike+resource@ab0t.com)
        └── This is a real user account, used to manage the service org

Step 2: Create service org ("Resource Service")
        └── settings.type = "platform_service"
        └── This is the service's identity in the auth system

Step 3: Login with org context
        └── Gets a token scoped to the service org
        └── Subsequent API calls are "as admin of Resource Service org"

Step 4: Register permissions
        └── POST /permissions/registry/register
        └── Registers actions × resources → generates permission strings
        └── These permissions only exist within this org's namespace

Step 4b: Grant admin implied permissions
        └── resource.admin implies [resource.read, resource.write, ...]
        └── Grants all implied permissions to the admin user

Step 5: Create API key
        └── POST /api-keys/ (within the org context)
        └── Key has all permissions from .permissions.json
        └── This key IS the service account

Step 6: Register with proxy controller (optional)
        └── Makes the service reachable at https://resource.service.ab0t.com
```

---

## 6. Customer Orgs

### How Customers Map to Orgs

When a customer signs up:
1. A new org is created for them
2. The signing-up user becomes the org admin
3. They can invite other users
4. They can create teams
5. They can create child orgs (departments)

### Customer Org Setup

```bash
# 1. Customer signs up and creates their org
curl -X POST "$AUTH_URL/organizations/" \
  -H "Authorization: Bearer $CUSTOMER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corporation",
    "slug": "acme-corp",
    "domain": "acme.com",
    "billing_type": "postpaid",
    "industry": "technology",
    "size": "enterprise",
    "settings": {"type": "customer", "hierarchical": true},
    "metadata": {"plan": "enterprise", "seats": 500}
  }'

# 2. Admin invites team members
curl -X POST "$AUTH_URL/organizations/$ORG_ID/invite" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "bob@acme.com",
    "role": "resource-user",
    "permissions": ["resource.read", "resource.create.allocations"],
    "message": "Welcome to Acme on the platform!"
  }'

# 3. Admin creates teams
curl -X POST "$AUTH_URL/organizations/$ORG_ID/teams" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Backend Engineering",
    "permissions": ["resource.create.allocations", "resource.execute.instances"],
    "settings": {"department": "engineering"}
  }'

# 4. Admin creates a department (child org)
curl -X POST "$AUTH_URL/organizations/" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Research Lab",
    "slug": "acme-research",
    "parent_id": "'"$ORG_ID"'",
    "billing_type": "enterprise",
    "settings": {"type": "department"}
  }'
```

### The Customer Org Contains Customer Data

Unlike service orgs, customer orgs contain the actual resources:

```
Acme Corporation (customer org: acme-123)
├── Users: alice (admin), bob, carol, dave
├── Teams: Backend, Frontend, DevOps
├── Resources:
│   ├── Allocation: alloc-001 (org_id: acme-123, user_id: bob)
│   ├── Allocation: alloc-002 (org_id: acme-123, user_id: carol)
│   └── Allocation: alloc-003 (org_id: acme-123, user_id: dave)
├── API Keys:
│   └── "acme-ci-runner" (for Acme's CI/CD pipeline)
└── Child Orgs:
    └── Acme Research Lab (org_id: acme-research-456, parent_id: acme-123)
        ├── Users: eve, frank
        └── Resources:
            └── Allocation: alloc-004 (org_id: acme-research-456, user_id: eve)
```

When `get_user_filter(bob)` runs:
- Returns `{"user_id": "bob", "org_id": "acme-123"}` — Bob sees only his own allocations
- If Bob has `resource.admin`, returns `{"org_id": "acme-123"}` — Bob sees all of Acme's allocations
- If Bob has `resource.cross_tenant`, returns `{}` — Bob sees everything (but Bob should never have this)

---

## 7. Nested Orgs (Departments, Sub-Customers)

### The Nesting Mechanism

Any org can be nested under another by setting `parent_id` at creation time:

```bash
curl -X POST "$AUTH_URL/organizations/" \
  -d '{"name": "Child Org", "parent_id": "parent-org-uuid", ...}'
```

The hierarchy is stored in the org itself and queryable:

```bash
# View full hierarchy tree from parent
curl -s "$AUTH_URL/organizations/$PARENT_ID/hierarchy" \
  -H "Authorization: Bearer $TOKEN"

# Set up hierarchy in Zanzibar (for relationship-based access)
curl -X POST "$AUTH_URL/zanzibar/hierarchy/setup" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"org_id": "child-uuid", "parent_org_id": "parent-uuid"}'
```

### What Nesting Gives You

1. **Billing rollup** — parent org is the billing entity. Child usage rolls up.
2. **Admin delegation** — parent admin can manage child orgs (with `allow_ancestor_access: true`).
3. **Data isolation** — children can't see each other (sibling isolation).
4. **Independent teams/users** — each child org has its own users and teams.
5. **Independent quotas** — each child org can have its own resource limits.

### What Nesting Does NOT Give You

1. **Shared users** — a user in the parent org is NOT automatically in the child org. They must be explicitly added.
2. **Shared permissions** — `resource.admin` in the parent org doesn't automatically grant admin in the child org. The TenantConfig controls this.
3. **Shared resources** — resources belong to exactly one org. They don't "inherit" from the parent.

### Nesting Depth: How Deep Can You Go?

The system supports arbitrary nesting depth. The `max_depth` parameter on hierarchy visualization defaults to 5 but can be increased.

**Practical recommendation:** 2-3 levels is typical:
```
Level 0: Platform root (if applicable)
Level 1: Customer company
Level 2: Department or business unit
Level 3: Sub-team or project (rare)
```

Going deeper than 3 levels usually means you should use teams within an org instead of more nesting.

### Deeply Nested Example: Global Enterprise

```
GlobalCorp (parent org, level 0)
├── GlobalCorp Americas (child org, level 1)
│   ├── GC Americas Engineering (child org, level 2)
│   │   ├── Backend Team (team within the org)
│   │   └── Frontend Team (team within the org)
│   └── GC Americas Sales (child org, level 2)
├── GlobalCorp EMEA (child org, level 1)
│   ├── GC EMEA Engineering (child org, level 2)
│   └── GC EMEA Operations (child org, level 2)
└── GlobalCorp APAC (child org, level 1)
    └── GC APAC All (child org, level 2)
```

**Access rules with TenantConfig:**
- GlobalCorp CTO → sees all regions (ancestor access)
- Americas VP → sees all Americas departments, NOT EMEA or APAC
- Americas Engineering lead → sees Backend + Frontend teams, NOT Americas Sales
- Backend Team member → sees only their own resources within that team/org

---

## 8. Teams-as-Orgs vs Traditional Teams

### Two Ways to Group Users

Our system offers two grouping mechanisms:

**1. Teams (within an org):** Created via `POST /organizations/{org_id}/teams`. Live inside a single org. Users can be in multiple teams. Teams can nest (`parent_team_id`). Teams inherit permissions from parent teams.

**2. Child orgs:** Created via `POST /organizations/` with `parent_id`. Full isolation boundary. Users belong to exactly one org per context. Separate billing, quotas, and admin.

### When the "Everything Is an Org" Model Matters

Because everything is an org, you **can** model a team as a child org. But should you?

**Model a team as a traditional team when:**
- Members need to be in multiple teams simultaneously
- You want permission inheritance (child team inherits parent team's permissions)
- There's no need for separate billing or hard data isolation
- The team is a "soft" grouping — access control, not data boundary

**Model a team as a child org when:**
- The team needs its own budget/quotas
- Hard data isolation is required (compliance, regulatory)
- The "team" is really a department or business unit
- The team needs its own admin who shouldn't see other teams
- The team will have its own sub-teams that also need isolation

### Comparison Table

| Capability | Team (within org) | Child Org |
|---|---|---|
| Multiple membership | Yes (user in many teams) | No (one org per login context) |
| Permission inheritance | Yes (from parent team) | No (separate permission space) |
| Hard data isolation | No (shared org boundary) | Yes (separate org boundary) |
| Separate billing | No | Yes |
| Separate quotas | No | Yes |
| Own admin | Team leaders (limited) | Full org admin |
| Nesting depth | Unlimited | Unlimited |
| API endpoint | `POST /organizations/{id}/teams` | `POST /organizations/` with `parent_id` |
| Zanzibar integration | `POST /zanzibar/teams/membership` | `POST /zanzibar/hierarchy/setup` |

### The Hybrid Pattern

Most real deployments use both:

```
Acme Corporation (org)
├── [CHILD ORG] Acme Engineering (hard boundary, separate budget)
│   ├── [TEAM] Backend (soft grouping, permission inheritance)
│   ├── [TEAM] Frontend (soft grouping)
│   └── [TEAM] DevOps (soft grouping, extra permissions like SSH)
├── [CHILD ORG] Acme Finance (hard boundary, regulatory isolation)
│   └── [TEAM] Accounting (soft grouping)
└── [TEAM] All-Hands (org-wide team, everyone is a member)
```

The child orgs provide hard isolation between Engineering and Finance. Teams within each child org provide soft grouping for access control and permission inheritance.

---

## 9. The Registration Flow Dissected

### What Actually Happens When a Service Registers

Let's trace `register-service-permissions.sh` step by step, explaining **what changes in the auth system** at each step.

**Step 1: Create Admin Account**
```
POST /auth/register
  email: "mike+resource@ab0t.com"
  password: "ResourceServiceAdmin2024!Secure"

Auth system state after:
  Users table:
    + user_id: "abc-123"
      email: "mike+resource@ab0t.com"
      (no org membership yet — user exists but is "homeless")
```

**Step 2: Create Service Org**
```
POST /organizations/
  Authorization: Bearer <token from step 1>
  name: "Resource Service"
  slug: "resource-service"
  settings: { type: "platform_service", service: "resource" }

Auth system state after:
  Organizations table:
    + org_id: "020caf72-..."
      name: "Resource Service"
      type: "platform_service"
      parent_id: null

  Membership table:
    + user_id: "abc-123" IN org: "020caf72-..."
      role: "owner" (creator becomes owner)
```

**Step 3: Login with Org Context**
```
POST /auth/login
  email: "mike+resource@ab0t.com"
  password: "..."
  org_id: "020caf72-..."

Result:
  New JWT with claims:
    sub: "abc-123"
    org_id: "020caf72-..."   ← Token is now scoped to this org
    aud: "LOCAL:020caf72-..."
```

**Step 4: Register Permissions**
```
POST /permissions/registry/register
  Authorization: Bearer <org-scoped token>
  service: "resource"
  actions: ["read", "write", "create", "delete", "scale", ...]
  resources: ["allocations", "instances", "deployments", ...]

Auth system state after:
  Permission Registry:
    + service: "resource"
      org_id: "020caf72-..."
      valid_permissions: [
        "resource.read.allocations",
        "resource.read.instances",
        "resource.write.allocations",
        ...
        (actions × resources = all valid combinations)
      ]
```

**Step 4b: Grant Admin Implied Permissions**
```
POST /permissions/grant?user_id=abc-123&org_id=020caf72-...&permission=resource.admin
POST /permissions/grant?...&permission=resource.read
POST /permissions/grant?...&permission=resource.write
... (all implied permissions)

Auth system state after:
  User Permissions:
    + user "abc-123" in org "020caf72-..." has:
      resource.admin
      resource.read
      resource.write
      resource.scale
      resource.delete
      ... (all implied by resource.admin)
```

**Step 5: Create API Key**
```
POST /api-keys/
  Authorization: Bearer <org-scoped token>
  name: "resource-internal"
  permissions: [all permissions from .permissions.json]

Auth system state after:
  API Keys:
    + key_id: "key-456"
      key: "ab0t_sk_live_..."
      org_id: "020caf72-..."
      permissions: ["resource.read", "resource.write", ..., "resource.cross_tenant"]
```

### The End State

After registration, the auth system has:

```
Organization: "Resource Service" (020caf72-...)
  │
  ├── Owner: mike+resource@ab0t.com
  │   └── Permissions: resource.admin + all implied
  │
  ├── API Key: "resource-internal" (ab0t_sk_live_...)
  │   └── Permissions: all 22 from .permissions.json
  │
  └── Permission Registry: service "resource"
      └── Valid permissions: actions × resources
```

Other services (Sandbox Platform, Billing) will later create their OWN API keys in this org to call the Resource Service.

---

## 10. Permission Scoping and the Org Boundary

### Permissions Are Org-Scoped

This is the most misunderstood concept. `resource.read` in org A is **the same permission string** as `resource.read` in org B, but they are **independently granted**.

```
Org: "Resource Service" (020caf72-...)
  Registered permissions: resource.read, resource.write, ...
  Users with resource.read:
    - mike+resource@ab0t.com (admin)
  API keys with resource.read:
    - resource-internal (the service's own key)
    - sandbox-to-resource (Sandbox Platform's key)

Org: "Acme Corporation" (acme-123)
  Users with resource.read:
    - alice@acme.com (granted via resource-user role)
    - bob@acme.com (granted directly)
  API keys with resource.read:
    - acme-ci-runner (Acme's CI key)
```

Alice has `resource.read` in Acme's org. This means she can read Acme's resources. She does NOT have `resource.read` in the Resource Service's org (and doesn't need it — that org contains config, not customer data).

### How the Auth Service Validates

When Alice sends a request to the Resource Service:

1. Her JWT contains `org_id: "acme-123"` and `permissions: ["resource.read", ...]`
2. The Resource Service's `AuthGuard` validates the JWT:
   - Signature valid? (JWKS check)
   - Audience matches? (`AB0T_AUTH_AUDIENCE = "LOCAL:020caf72-..."`)
   - Wait — Alice's token has `aud: "LOCAL:acme-123"`, not `"LOCAL:020caf72-..."`

**This is where audience configuration matters.** If the Resource Service only accepts tokens for its own org, customer tokens would be rejected. In practice:
- `AB0T_AUTH_AUDIENCE_SKIP=true` during transition (accepts any org's tokens)
- Or the audience is configured to accept customer org tokens
- Or the service uses server-mode permission checks (validates against auth service)

### The Permission Check Flow

```
Customer Alice → Resource Service

1. Extract token → org_id: "acme-123", permissions: ["resource.read"]
2. Phase 1 (dependency):
   - Has permission "resource.read"? ✅
   - Check callback: belongs_to_org(alice, request)?
     - request has org_id from path/query
     - alice.org_id == request.org_id? → depends on what she's accessing
3. Phase 2 (route handler):
   - Fetch allocation from DB
   - allocation.org_id == alice.org_id? → "acme-123" == "acme-123" ✅
   - Or allocation.user_id == alice.user_id? ✅
4. Return resource
```

---

## 11. User Membership and Multi-Org Access

### Users Can Belong to Multiple Orgs

A user can be a member of several orgs simultaneously:

```bash
# List all orgs the current user belongs to
curl -s "$AUTH_URL/users/me/organizations" \
  -H "Authorization: Bearer $TOKEN"

# Response:
# [
#   {
#     "id": "personal-workspace-uuid",
#     "name": "alice's workspace",
#     "type": "personal",
#     "role": "owner",
#     "is_personal": true,
#     "is_default": true,
#     "permissions": ["resource.read", "resource.create.allocations"]
#   },
#   {
#     "id": "acme-uuid",
#     "name": "Acme Corporation",
#     "type": "customer",
#     "role": "member",
#     "is_personal": false,
#     "is_default": false,
#     "permissions": ["resource.read", "resource.write"]
#   },
#   {
#     "id": "startupx-uuid",
#     "name": "StartupX",
#     "type": "customer",
#     "role": "admin",
#     "is_personal": false,
#     "is_default": false,
#     "permissions": ["resource.admin", "resource.read", "..."]
#   }
# ]
```

### Switching Between Orgs

A JWT is scoped to one org at a time. To access a different org's resources:

```bash
# Switch to Acme's context
curl -X POST "$AUTH_URL/auth/switch-organization" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"org_id": "acme-uuid"}'

# Returns new token with:
#   org_id: "acme-uuid"
#   permissions: ["resource.read", "resource.write"]  ← Alice's perms IN Acme
```

The permissions change because Alice might be admin in one org and viewer in another.

### Login with Org Context

You can also specify the org at login time:

```bash
curl -X POST "$AUTH_URL/auth/login" \
  -d '{
    "email": "alice@example.com",
    "password": "...",
    "org_id": "acme-uuid"
  }'
# Token is immediately scoped to Acme
```

If no `org_id` is provided at login, the token is scoped to the user's `is_default: true` org.

---

## 12. Delegation and Act-As Patterns

### Delegation in the "Everything Is an Org" Model

Delegation lets User A act as User B. In our model, this means:
- The delegated token has `sub: User B` (actions appear as B)
- But `act: User A` (audit trail records who's really acting)
- The delegation is scoped to specific permissions and time-limited

### Delegation Scenarios

**Scenario 1: Executive Assistant**
```
Alice (CEO of Acme) grants Bob (assistant) delegation:
  Scope: ["calendar.read", "calendar.write"]
  Duration: 720 hours (30 days)

Bob creates delegated token:
  POST /auth/delegate {"target_user_id": "alice-id"}

Bob uses the token:
  → Requests appear as Alice
  → Audit: "Bob acting as Alice"
  → Only calendar.read and calendar.write work
  → resource.admin (which Alice has) does NOT work (not in scope)
```

**Scenario 2: Platform Support**
```
Support agent needs to see what a customer sees:
  Customer alice grants delegation to support-agent:
    Scope: ["resource.read", "resource.logs"]
    Duration: 4 hours

Support agent can now:
  → See Alice's allocations exactly as Alice sees them
  → Read Alice's logs
  → CANNOT modify, delete, or create (not in scope)
```

**Scenario 3: Automated Systems**
```
A cron job needs to run as a specific user:
  Admin grants delegation to service-account:
    Scope: ["resource.scale"]
    Duration: 8760 hours (1 year)

Cron job creates delegated token → scales resources "as" the user
Audit trail: "service-account acting as admin scaled allocation-123"
```

### Delegation vs Other Access Patterns

```
"I need to access another user's resources"
│
├── Same org, I'm admin → Use resource.admin (no delegation needed)
│   └── Phase 2 verify_allocation_access() allows admin in same org
│
├── Same org, I'm not admin → Use delegation (user must grant)
│   └── Scoped, time-limited, audited
│
├── Different org, I'm platform staff → Use cross_tenant permission
│   └── Bypasses org boundary entirely
│
├── Different org, not platform staff → Delegation OR invitation
│   └── Delegation: temporary, act-as
│   └── Invitation: permanent, own identity
│
└── I'm a service, not a human → Use API key
    └── Created in the target org with specific permissions
```

---

## 13. Cross-Org Mesh Access

### The Problem

9 microservices. Each is an org. Some need to call each other. How do the permissions work across org boundaries?

### The Solution: API Keys in the Target Org

```
┌─────────────────────────┐          ┌─────────────────────────┐
│ Sandbox Platform        │          │ Resource Service         │
│ (org: sandbox-255...)   │          │ (org: resource-020...)   │
│                         │          │                         │
│ Config:                 │  calls   │ Contains:               │
│  RESOURCE_API_KEY=      │ ──────→  │  API Key:               │
│  "ab0t_sk_live_xyz..."  │          │   name: "sandbox-to-res"│
│                         │          │   perms: [resource.read, │
│ (key was created in     │          │    resource.create.*]    │
│  Resource Service's org)│          │   org: resource-020...   │
└─────────────────────────┘          └─────────────────────────┘
```

The key insight: the API key `ab0t_sk_live_xyz...` was created inside the Resource Service's org by the Resource Service admin. It lives in the Resource Service's org context and has permissions defined in that org's permission namespace.

When Sandbox Platform sends `X-API-Key: ab0t_sk_live_xyz...`:
1. Resource Service receives the request
2. AuthGuard calls `POST /auth/validate-api-key` with the key
3. Auth service looks up the key → finds it in org `resource-020...`
4. Returns: `{valid: true, permissions: ["resource.read", "resource.create.allocations"], org_id: "resource-020..."}`
5. The request is processed with those permissions

### The Mesh Map

For a platform with 9 services, document every cross-org key:

```
From → To                  | Key Name              | Permissions
========================== | ===================== | ================================
Sandbox → Resource          | sandbox-to-resource   | resource.create.*, resource.read,
                           |                       | resource.delete, resource.scale
Sandbox → Billing           | sandbox-to-billing    | billing.create.charges,
                           |                       | billing.read.invoices
Resource → Billing          | resource-to-billing   | billing.create.charges,
                           |                       | billing.read.costs
API Gateway → Resource      | gateway-to-resource   | resource.read
API Gateway → Billing       | gateway-to-billing    | billing.read
Audit → Resource            | audit-to-resource     | resource.read
Audit → Billing             | audit-to-billing      | billing.read
```

### Setting Up a Cross-Org Key

```bash
# Admin of Resource Service org logs in
TOKEN=$(curl -s -X POST "$AUTH_URL/auth/login" \
  -d '{"email": "mike+resource@ab0t.com", "password": "...", "org_id": "020caf72-..."}' \
  | jq -r '.access_token')

# Create a key for Sandbox Platform to use
curl -s -X POST "$AUTH_URL/api-keys/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "sandbox-to-resource",
    "permissions": [
      "resource.create.allocations",
      "resource.create.deployments",
      "resource.read",
      "resource.delete",
      "resource.scale"
    ],
    "metadata": {
      "purpose": "Sandbox Platform calling Resource Service",
      "created_by": "platform-team",
      "caller_service": "sandbox-platform",
      "target_service": "resource-service"
    }
  }'

# Give the returned key to the Sandbox Platform team
# They put it in their .env as RESOURCE_SERVICE_API_KEY=ab0t_sk_live_...
```

---

## 14. The Zanzibar Layer

### How Zanzibar Relates to the Org Model

The org model handles **infrastructure-level** access control:
- Who can call which service?
- Who belongs to which org?
- What permissions does a user have in an org?

Zanzibar handles **application-level** access control:
- Who can edit this specific document?
- Who can view this specific project?
- Can team Backend deploy to production?

### Zanzibar + Orgs Together

```
Org-Level (handled by AuthGuard + TenantConfig):
  "Alice is in Acme Corp with resource.read permission"

Zanzibar-Level (handled by relationship checks):
  "Alice is an editor of document:doc-123"
  "Team Backend is a viewer of project:proj-456"
```

Your route handler might use both:

```python
@router.get("/documents/{doc_id}")
async def get_document(doc_id: str, user: ResourceReader):
    # Phase 1 already verified: user has resource.read + belongs_to_org

    # Phase 2a: Check Zanzibar relationship
    allowed = await zanzibar_check(
        subject=f"user:{user.user_id}",
        permission="read",
        object=f"document:{doc_id}"
    )
    if not allowed:
        raise PermissionDeniedError("Access denied to this document")

    return await db.get_document(doc_id)
```

### When to Use Zanzibar vs Org-Level Permissions

| Access Pattern | Use Org-Level | Use Zanzibar |
|---|---|---|
| "Can this user create allocations?" | ✅ `resource.create.allocations` | |
| "Can this user edit THIS document?" | | ✅ `doc:123#editor@user:alice` |
| "Is this user in this org?" | ✅ `belongs_to_org` check | |
| "Can Team X deploy to Project Y?" | | ✅ `project:Y#deployer@team:X` |
| "Is this user an admin?" | ✅ `resource.admin` | |
| "Who can see this invoice?" | | ✅ `invoice:I#viewer@user:*` |
| "Is this user suspended?" | ✅ `is_not_suspended` | |

**Rule of thumb:** If the question is about a **type** of action (can they create allocations?), use org-level permissions. If the question is about a **specific resource** (can they edit THIS document?), use Zanzibar.

---

## 15. Architecture Decision Framework

### Step 1: How Many Isolation Boundaries?

```
Q: How many truly separate data boundaries do you need?

1 boundary (single-tenant)
  → 1 org, teams for grouping
  → Example: Internal company tool

N boundaries (multi-tenant)
  → N orgs, one per customer
  → Example: SaaS product

N×M boundaries (multi-tenant with departments)
  → N parent orgs with M child orgs each
  → Example: Enterprise SaaS with department isolation
```

### Step 2: How Deep Does the Nesting Go?

```
Q: Do customers need sub-divisions with separate data?

No → Flat orgs (1 level)
  → Use teams for grouping within the org
  → Simplest model

Yes, 1 level (departments) → Parent + child orgs (2 levels)
  → Common for enterprise customers
  → parent_id on child org creation

Yes, 2+ levels (regions → departments → teams) → Deep nesting (3+ levels)
  → Rare, but supported
  → Consider: do you really need hard isolation at every level?
  → Maybe: region orgs (hard boundary) + team structure within (soft boundary)
```

### Step 3: How Do Services Communicate?

```
Q: How many services call each other?

1-2 services → Manual API key creation
  → Create keys by hand, store in config

3+ services → Registration script + mesh documentation
  → register-service-permissions.sh for each service
  → Document the mesh map (who calls who, with what permissions)

9+ services → Consider service mesh tooling
  → Automate key rotation
  → Monitor key usage
  → Alert on unused or over-permissioned keys
```

### Step 4: Do Users Need Personal Workspaces?

```
Q: Can users exist independently of a company?

No (enterprise-only) → No personal workspaces
  → Users must be invited to a company org first

Yes (individual + company) → Personal workspaces
  → Users get a personal org on signup
  → They can join company orgs later
  → is_personal: true, is_default: true
```

### Step 5: TenantConfig Settings

```python
# Start here and adjust:
tenant_config = TenantConfig(
    # Almost always True for multi-tenant
    enforce_tenant_isolation=True,
    enforce_org_isolation=True,

    # True if you have platform support staff
    allow_cross_tenant_admin=True,
    cross_tenant_permission="myservice.cross_tenant",

    # Only True if you use parent/child orgs
    enable_org_hierarchy=<True if nested orgs>,

    # True if parent admin needs to see child resources
    allow_ancestor_access=<True if parent manages children>,

    # Almost always False (children shouldn't see parent data)
    allow_descendant_access=False,
)
```

---

## 16. Real-World Scenarios (Worked End-to-End)

### Scenario A: Developer Platform (Like Vercel/Render)

**Users:** Individual developers + company teams
**Need:** Personal projects + team projects + billing separation

```
Platform Structure:
├── Personal Workspaces (auto-created on signup)
│   ├── alice's workspace (personal org)
│   │   └── alice's hobby project (allocation)
│   └── bob's workspace (personal org)
│       └── bob's side project (allocation)
│
├── Company Orgs (created when companies sign up)
│   ├── TechStartup Inc (customer org)
│   │   ├── Team: Frontend → permissions: [resource.create.*, resource.read]
│   │   ├── Team: Backend → permissions: [resource.create.*, resource.execute.*]
│   │   └── Team: Ops → permissions: [resource.admin]
│   │   └── Members: alice (frontend+backend), carol (ops)
│   │
│   └── BigCorp Ltd (customer org)
│       ├── [CHILD ORG] BigCorp Dev (department)
│       │   └── Team: Developers
│       └── [CHILD ORG] BigCorp Staging (department)
│           └── Team: QA
│
└── Service Orgs (infrastructure)
    ├── Resource Service (org: 020caf72-...)
    ├── Billing Service (org: billing-uuid)
    └── Sandbox Platform (org: 255089eb-...)
```

**Alice's org memberships:**
```json
[
  {"name": "alice's workspace", "is_personal": true, "is_default": true, "role": "owner"},
  {"name": "TechStartup Inc", "is_personal": false, "role": "member"}
]
```

Alice can switch between her personal workspace (free-tier experiments) and TechStartup (company resources, team-shared, company billing).

---

### Scenario B: MSP / Managed Service Provider

**Users:** MSP staff manages multiple client environments
**Need:** Each client isolated, MSP staff has cross-client access

```
Platform Structure:
├── MSP Operations (parent org)
│   ├── MSP Staff (users with cross_tenant or admin + ancestor access)
│   │   ├── support-agent-1
│   │   ├── support-agent-2
│   │   └── msp-admin
│   │
│   ├── [CHILD ORG] Client: Hospital System (isolated)
│   │   ├── Hospital IT staff (users)
│   │   └── Hospital's resources
│   │
│   ├── [CHILD ORG] Client: Law Firm (isolated)
│   │   ├── Law firm IT staff (users)
│   │   └── Law firm's resources
│   │
│   └── [CHILD ORG] Client: School District (isolated)
│       ├── School IT staff (users)
│       └── School's resources
```

**TenantConfig:**
```python
TenantConfig(
    enforce_tenant_isolation=True,
    enforce_org_isolation=True,
    enable_org_hierarchy=True,
    allow_ancestor_access=True,      # MSP staff sees all clients
    allow_descendant_access=False,   # Clients can't see MSP internals or each other
)
```

**MSP admin access:** The admin is in the parent org (MSP Operations). With `allow_ancestor_access=True`, they can see resources in all child orgs (Hospital, Law Firm, School). But Hospital's staff CANNOT see Law Firm's data (sibling isolation).

**Alternative without hierarchy:** Use flat orgs for each client + `cross_tenant` permission for MSP staff. This works but is less structured — `cross_tenant` gives access to ALL orgs, not just the MSP's clients.

---

### Scenario C: Multi-Region Compliance

**Users:** Financial services company with regulatory requirements
**Need:** EU data stays in EU, US data stays in US, but global admin exists

```
Platform Structure:
├── GlobalFinance Corp (parent org)
│   ├── [CHILD ORG] GF-US (US region, SOC2 compliance)
│   │   ├── [CHILD ORG] GF-US-Trading (PCI-DSS)
│   │   │   └── Trading team (users, resources)
│   │   └── [CHILD ORG] GF-US-Banking (SOX compliance)
│   │       └── Banking team (users, resources)
│   │
│   ├── [CHILD ORG] GF-EU (EU region, GDPR compliance)
│   │   ├── [CHILD ORG] GF-EU-Trading
│   │   └── [CHILD ORG] GF-EU-Wealth
│   │
│   └── [CHILD ORG] GF-APAC (APAC region)
│       └── [CHILD ORG] GF-APAC-Operations
```

**TenantConfig:**
```python
TenantConfig(
    enforce_tenant_isolation=True,
    enforce_org_isolation=True,
    enable_org_hierarchy=True,
    allow_ancestor_access=True,      # Global admin sees all regions
    allow_descendant_access=False,   # Regions can't see each other
)
```

**Why 3 levels?**
- Level 0 (GlobalFinance): Global CTO, compliance officer
- Level 1 (Regions): Regional compliance, can see all departments in their region
- Level 2 (Departments): Actual business units, hardest isolation

**The US Trading team** is isolated from US Banking (sibling isolation at level 2). GF-US admin can see both (ancestor access from level 1). GlobalFinance admin can see everything (ancestor access from level 0). EU teams cannot see US data at all.

---

## 17. What Agents Get Wrong (and Why)

### Mistake 1: "I need to create a separate Team entity"

**Wrong thinking:** "Users need to be grouped, so I need the Team API."

**Right thinking:** First ask: "Do these users need hard data isolation?" If yes, create a child org. If no, create a team within the existing org. Teams are a convenience feature for soft grouping — the org is the real security boundary.

### Mistake 2: "I must use the service account endpoint for everything"

**Wrong thinking:** "Every machine identity needs `POST /admin/users/create-service-account`."

**Right thinking:** For most cases, just create an API key (`POST /api-keys/`) in the target service's org — it's simpler and sufficient. The dedicated service account endpoint (`POST /admin/users/create-service-account`) creates a named user entity with `account_type: "service"` — use it when enterprise compliance requires tracked machine identities. Start with API keys; upgrade to service accounts only if you need the audit trail of a named user.

### Mistake 3: "cross_tenant is like admin but for all orgs"

**Wrong thinking:** "Admin manages one org, cross_tenant manages all orgs. They're on the same spectrum."

**Right thinking:** They're fundamentally different. `admin` is an org-scoped role — it gives power within one org's boundary. `cross_tenant` removes the boundary entirely. They should never imply each other. `cross_tenant` is for platform infrastructure (support staff, monitoring systems), not for customer admins.

### Mistake 4: "Each team needs its own permissions registered"

**Wrong thinking:** "The Backend team and Frontend team need different permission registrations."

**Right thinking:** Permissions are registered once, per service. `resource.read`, `resource.create.allocations`, etc. exist in the service's org. Teams/users are GRANTED these permissions — the permissions themselves don't change per team. Teams can have default permissions that are inherited by members, but those are grants, not registrations.

### Mistake 5: "I'll use nested orgs for everything"

**Wrong thinking:** "My company has 20 teams → 20 child orgs."

**Right thinking:** 20 child orgs means 20 separate data boundaries, 20 separate admin accounts, users can't easily share resources across teams, and the admin overhead is enormous. Use teams within a single org for 90% of cases. Only use child orgs when you need hard isolation (separate billing, compliance, or truly independent business units).

### Mistake 6: "Users belong to one org"

**Wrong thinking:** "A user is created in an org and that's where they live."

**Right thinking:** Users exist independently of orgs. They can join multiple orgs, switch between them, and have different permissions in each. The JWT is scoped to one org at a time (`org_id` in claims), but the user's identity is global. This is why `POST /auth/switch-organization` and `GET /users/me/organizations` exist.

### Mistake 7: "The service org and the customer org are the same thing"

**Wrong thinking:** "The Resource Service org (020caf72-...) is where customer resources live."

**Right thinking:** The Resource Service org contains the service's identity (permissions, API keys, admin account). Customer resources belong to customer orgs. When Alice creates an allocation, it gets `org_id: alice's-company-org`, NOT `org_id: resource-service-org`. The service org is infrastructure; customer orgs hold customer data.

---

## Summary: The Complete Mental Model

```
┌──────────────────────────────────────────────────────────────┐
│                    EVERYTHING IS AN ORG                       │
│                                                              │
│  An org is a workspace. A namespace. An isolation boundary.  │
│  What makes orgs different is their TYPE and CONFIGURATION.  │
│                                                              │
│  Types:                                                      │
│  ├── platform_service → a microservice's identity            │
│  ├── customer → a paying customer/tenant                     │
│  ├── personal → a user's personal workspace                  │
│  ├── department → a division within a company (child org)    │
│  └── (any custom type you define in settings)                │
│                                                              │
│  Nesting:                                                    │
│  └── parent_id links orgs into a tree                        │
│      └── Ancestor access: parent sees children               │
│      └── Sibling isolation: children can't see each other    │
│                                                              │
│  Within an org:                                              │
│  ├── Users (human identities, can be in multiple orgs)       │
│  ├── Teams (soft grouping, permission inheritance)           │
│  ├── API Keys (machine identities / service accounts)        │
│  ├── Permissions (registered, granted, checked)              │
│  └── Resources (data scoped to this org via org_id)          │
│                                                              │
│  Across orgs:                                                │
│  ├── API Keys created in target org (cross-org access)       │
│  ├── cross_tenant permission (platform staff, bypasses all)  │
│  ├── Delegation (act-as-user, scoped and time-limited)       │
│  └── Super-admin (emergency access, requires justification)  │
│                                                              │
│  The auth service is the single source of truth for:         │
│  ├── Who exists (users, orgs, keys)                          │
│  ├── Who can do what (permissions, roles)                    │
│  ├── Who is in what (membership, teams, hierarchy)           │
│  └── Who is related to what (Zanzibar relationships)         │
└──────────────────────────────────────────────────────────────┘
```
