# AB0T-AUTH Complete Integration Guide

**Version:** 3.1
**Last Updated:** 2026-02-04
**Author:** Platform Team
**Skill Reference:** See your organization's auth skill file (typically `auth_system_skill_ab0t.txt`)

---

## Quick Start (TL;DR)

For experienced engineers who just need the essentials:

```bash
# 1. Install the library
echo "git+https://github.com/ab0t-com/auth_wrapper.git" >> requirements.txt

# 2. Create .permissions.json in your service root (see Section 6)

# 3. Create app/auth.py using the template (see Section 8.2)

# 4. Update app/main.py to integrate auth lifespan (see Section 8.3)

# 5. Register your service
./register-service-permissions.sh

# 6. Run security tests
./tests/security/auth_bypass_tests.sh http://localhost:YOUR_PORT apikey
```

**Files you will create/modify:**
- [ ] `requirements.txt` - Add ab0t-auth dependency
- [ ] `.permissions.json` - Define your permissions (service root)
- [ ] `app/config.py` - Add AB0T_AUTH_* settings
- [ ] `app/auth.py` - New file: auth module
- [ ] `app/main.py` - Add lifespan and exception handlers
- [ ] `register-service-permissions.sh` - Registration script
- [ ] `credentials/{service}.json` - Generated credentials (gitignored)
- [ ] `tests/test_auth_security.py` - Unit tests
- [ ] `tests/security/auth_bypass_tests.sh` - Integration tests

---

## Prerequisites & Assumptions

Before starting, verify the following:

### 1. Auth Service Accessibility

```bash
# Verify the auth service is reachable
curl -s https://YOUR_AUTH_SERVICE_URL/health | jq

# Expected: {"status": "healthy", ...}

# If using a custom/local auth service, set the URL:
export AB0T_AUTH_URL=http://localhost:8001
```

### 2. Library Installation Verification

```bash
# After adding to requirements.txt and rebuilding:
pip show ab0t-auth

# Verify imports work:
python -c "from ab0t_auth import AuthGuard; print('OK')"
```

### 3. Service Configuration

You need to know:
- **Your service ID** - A unique lowercase identifier (e.g., `myservice`, `billing`, `inventory`)
- **Your service port** - The port your FastAPI service runs on
- **Auth service URL** - Provided by your platform team (e.g., `https://auth.service.example.com`)

### 4. Creating Test API Keys

To run security tests, you need test API keys with different permission levels:

```bash
# After registration, create additional test keys:
# 1. Login as your service admin
TOKEN=$(curl -s -X POST "$AB0T_AUTH_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@yourservice.com", "password": "your_password"}' | jq -r '.access_token')

# 2. Create API key with specific permissions
curl -X POST "$AB0T_AUTH_URL/api-keys/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User A",
    "permissions": "myservice.read,myservice.create"
  }'

# 3. Create API key with NO permissions (for testing denials)
curl -X POST "$AB0T_AUTH_URL/api-keys/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "No Permissions User",
    "permissions": ""
  }'

# 4. Save the returned keys for use in tests
```

### 5. Placeholder Replacement

Throughout this guide, replace these placeholders with your values:

| Placeholder | Replace With | Example |
|-------------|--------------|---------|
| `myservice` | Your service ID | `billing`, `inventory` |
| `YOUR_AUTH_SERVICE_URL` | Your auth service URL | `https://auth.example.com` |
| `YOUR_PORT` | Your service port | `8007`, `8080` |
| `your_password` | Your admin password | - |
| `admin@yourservice.com` | Your admin email | - |

---

## Preface: What This Guide Is For

This guide is written for an AI agent or engineer who needs to integrate authentication and authorization into a FastAPI service. It assumes no prior knowledge of our systems. Every concept is explained from first principles, with reasoning for why decisions are made the way they are.

If you are reading this, your goal is likely one of:
1. Adding authentication to a new service
2. Understanding how our auth system works
3. Fixing or debugging auth issues
4. Extending auth capabilities

This guide will help with all of these.

---

## Table of Contents

**Getting Started**
- [Quick Start (TL;DR)](#quick-start-tldr)
- [Prerequisites & Assumptions](#prerequisites--assumptions)

**Part I: Foundation**
1. [Understanding the Problem](#1-understanding-the-problem)
2. [Core Concepts Explained](#2-core-concepts-explained)
3. [The ab0t-auth Library](#3-the-ab0t-auth-library)

**Part II: Planning**
4. [Identifying Your Service](#4-identifying-your-service)
5. [Designing Your Permissions](#5-designing-your-permissions)
6. [The .permissions.json Schema](#6-the-permissionsjson-schema)

**Part III: Implementation**
7. [Installation and Setup](#7-installation-and-setup)
8. [The Auth Module Pattern](#8-the-auth-module-pattern)
9. [Check Callbacks Deep Dive](#9-check-callbacks-deep-dive)
10. [Two-Phase Verification](#10-two-phase-verification)
11. [Multi-Tenant Isolation](#11-multi-tenant-isolation)

**Part IV: Registration and Verification**
12. [Registering with the Auth Service](#12-registering-with-the-auth-service)
13. [Verifying Your Setup](#13-verifying-your-setup)

**Part V: Testing**
14. [Security Testing Philosophy](#14-security-testing-philosophy)
15. [Writing Security Tests](#15-writing-security-tests)

**Part VI: Operations**
16. [Ticket Workflow](#16-ticket-workflow)
17. [File Reference](#17-file-reference)
18. [Troubleshooting](#18-troubleshooting)

**Part VII: Advanced Topics**
19. [Advanced: Permission Hierarchies](#19-advanced-permission-hierarchies)
20. [Advanced: Custom Auth Flows](#20-advanced-custom-auth-flows)
21. [Advanced: Performance Optimization](#21-advanced-performance-optimization)
22. [Advanced: Audit Logging](#22-advanced-audit-logging)
23. [Advanced: Token Introspection](#23-advanced-token-introspection)

---

# Part I: Foundation

## 1. Understanding the Problem

### 1.1 Why Authentication Matters

When you build a web service, anyone on the internet can send requests to it. Without authentication, you have no way to know who is making a request. This creates several problems:

1. **No accountability** - You cannot track who did what
2. **No access control** - Everyone can access everything
3. **No billing** - You cannot charge users for usage
4. **No security** - Attackers can freely access your system

Authentication solves the "who are you?" question. When a user makes a request, they include a token (like a password or key) that proves their identity.

### 1.2 Why Authorization Matters

Knowing who someone is (authentication) is not enough. You also need to know what they are allowed to do (authorization). Consider these scenarios:

- A regular user should not delete other users' data
- An admin should be able to see all data in their organization
- A platform admin should be able to access any organization (for support)
- A suspended user should not be able to create new resources

Authorization answers the "what can you do?" question. It checks whether a specific user has permission to perform a specific action.

### 1.3 Why Multi-Tenancy Matters

Our platform serves many organizations (companies, teams). Each organization is a "tenant" - they share the same software but their data must be completely isolated. This creates a critical security requirement:

**Users from Organization A must NEVER be able to access data from Organization B.**

This sounds simple but has subtle implications. Consider:

- An admin in Org A has `admin` permission
- They try to access a resource in Org B
- If we only check "does user have admin permission?" - they would be allowed!
- We must ALSO check "is the resource in the same org as the user?"

This is why we use "two-phase verification" - checking both permission AND ownership.

### 1.4 The Security Model

Our security model has three levels:

1. **Authentication** - Verify the user is who they claim to be (JWT or API key)
2. **Authorization** - Verify the user has the required permission
3. **Ownership** - Verify the user can access THIS specific resource

All three must pass for access to be granted.

---

## 2. Core Concepts Explained

### 2.1 Tokens

A token is a string that proves identity. We support two types:

**JWT (JSON Web Token)**
- Format: Three base64-encoded parts separated by dots: `header.payload.signature`
- Used by: Web applications, user sessions
- Sent in: `Authorization: Bearer <token>` header
- Expires: Yes, typically in 15-60 minutes
- Contains: User ID, email, permissions, org ID, expiration time

**API Key**
- Format: `ab0t_sk_live_` followed by random characters
- Used by: Scripts, service-to-service calls, testing
- Sent in: `X-API-Key: <key>` header
- Expires: No (but can be revoked)
- Contains: Linked to a user account with specific permissions

### 2.2 Permissions

A permission is a string that represents the ability to do something. We use a hierarchical format:

```
{service}.{action}.{resource}
```

Examples:
- `resource.read.allocations` - Can read allocation data
- `sandbox.create.sandboxes` - Can create sandboxes
- `billing.admin.costs` - Can administer cost settings

The format has meaning:
- **service** - Which microservice this applies to (e.g., `resource`, `sandbox`, `billing`)
- **action** - What operation (e.g., `read`, `write`, `create`, `delete`, `admin`)
- **resource** - What type of thing (e.g., `allocations`, `users`, `costs`)

### 2.3 Organizations

An organization (org) is a group of users who share resources. Every user belongs to exactly one organization. Every resource belongs to exactly one organization.

The `org_id` field is critical - it's how we enforce tenant isolation.

### 2.4 The AuthGuard

The `AuthGuard` is the central class that handles all authentication. It:
- Fetches JWKS (JSON Web Key Set) for validating JWT signatures
- Caches tokens to avoid repeated validation
- Provides dependency functions for route protection
- Manages its own lifecycle (initialization, shutdown)

### 2.5 The TenantConfig

The `TenantConfig` is a configuration object that defines how multi-tenant isolation works. It specifies:
- Whether org isolation is enforced
- What permission allows cross-org access
- Whether org hierarchy (parent/child orgs) is supported

---

## 3. The ab0t-auth Library

### 3.1 What It Is

`ab0t-auth` is our internal Python library for FastAPI authentication. It wraps the complexity of JWT validation, permission checking, and multi-tenant isolation into a simple, reusable package.

The library is documented in detail in the skill file:
```
sandbox-platform/auth_system_skill_ab0t.txt
```

This file contains the complete API reference, including all function signatures, types, and usage patterns. When you need to look up a specific function or understand available options, consult the skill file.

### 3.2 Key Imports

```python
# Core authentication
from ab0t_auth import (
    AuthGuard,              # Main coordinator class
    AuthenticatedUser,      # User object returned after auth
    require_auth,           # Require any authenticated user
    require_permission,     # Require specific permission
    require_any_permission, # Require any of several permissions
    optional_auth,          # Auth optional, returns None if not present
)

# Middleware and handlers
from ab0t_auth.middleware import (
    register_auth_exception_handlers,  # Proper 401/403 responses
)

# Errors
from ab0t_auth.errors import (
    PermissionDeniedError,  # Raised when permission check fails
    TokenNotFoundError,     # Raised when no token provided
    TokenExpiredError,      # Raised when JWT is expired
)

# Multi-tenancy
from ab0t_auth.tenant import (
    TenantConfig,           # Configuration for tenant isolation
)
```

### 3.3 The AuthenticatedUser Object

When authentication succeeds, you receive an `AuthenticatedUser` object:

```python
@dataclass
class AuthenticatedUser:
    user_id: str                    # Unique user identifier
    email: str | None               # User's email
    org_id: str | None              # User's organization
    permissions: tuple[str, ...]    # All granted permissions
    roles: tuple[str, ...]          # All assigned roles
    auth_method: AuthMethod         # JWT, API_KEY, or BYPASS
    metadata: dict[str, Any]        # Additional claims

    # Methods
    def has_permission(self, permission: str) -> bool
    def has_any_permission(self, *permissions: str) -> bool
    def has_all_permissions(self, *permissions: str) -> bool
    def has_role(self, role: str) -> bool
```

This object is your gateway to user information. You use it to:
- Get the user's ID for ownership checks
- Get the user's org_id for tenant isolation
- Check for specific permissions in your code

---

# Part II: Planning

## 4. Identifying Your Service

### 4.1 What Is a Service?

In our architecture, a "service" is an independently deployable unit that:
- Has its own codebase
- Runs on its own port
- Has its own database tables
- Exposes its own API endpoints
- Has its own permission namespace

Examples of services:
- `resource` - Resource Service (port 8007) - Manages compute resources
- `sandbox` - Sandbox Platform (port 8020) - Manages sandbox environments
- `billing` - Billing Service (port 8002) - Handles payments and invoices
- `auth` - Auth Service (port 8001) - Manages users and authentication

### 4.2 Choosing Your Service ID

Your service ID is a critical decision. It:
- Becomes the prefix for all your permissions (e.g., `myservice.read.*`)
- Must be unique across all services in the platform
- Cannot be changed without migrating all permissions
- Should be short, lowercase, and descriptive

**Good service IDs:**
- `resource` - Clear, describes what it does
- `sandbox` - Clear, describes what it manages
- `billing` - Clear, relates to billing functionality

**Bad service IDs:**
- `my-service` - Contains hyphen (use underscores if needed)
- `resourceManagementService` - Too long, mixed case
- `svc1` - Not descriptive
- `access` - Too generic, could conflict

### 4.3 Checking If Your Service ID Is Available

Before using a service ID, verify it's not already registered:

```bash
# List all registered services
curl -s https://auth.service.ab0t.com/permissions/registry/services | jq '.services[].service'

# Check for a specific service
curl -s https://auth.service.ab0t.com/permissions/registry/services | \
  jq '.services[] | select(.service == "myservice")'
```

If the service exists, you either need to:
1. Use the existing registration (if it's your service)
2. Choose a different name (if it's someone else's)

### 4.4 Understanding Service Boundaries

Ask yourself these questions to determine if you need a new service:

1. **Does this functionality have its own database?** If yes, likely a separate service.
2. **Could this be deployed independently?** If yes, likely a separate service.
3. **Does this have different permission requirements?** If yes, might need a separate service.
4. **Is this logically part of an existing service?** If yes, extend that service instead.

---

## 5. Designing Your Permissions

### 5.1 The Philosophy of Permissions

Permissions should be designed with these principles:

1. **Principle of Least Privilege** - Users should have only the permissions they need
2. **Granularity** - Permissions should be specific enough to be useful
3. **Composability** - Complex access can be built from simple permissions
4. **Clarity** - Permission names should be self-documenting

### 5.2 Identifying Actions

Actions are the verbs in your permission model. Common actions:

| Action | Intent | Risk Level |
|--------|--------|------------|
| `read` | View data | Low |
| `write` | Modify data | Medium |
| `create` | Create new records | Medium |
| `delete` | Remove records | High |
| `execute` | Run code/commands | High |
| `admin` | Full control | Critical |
| `cross_tenant` | Access other orgs | Critical |

Ask: "What can users DO in my service?"

### 5.3 Identifying Resources

Resources are the nouns in your permission model. They represent things users interact with:

For a Resource Service:
- `allocations` - Resource allocation records
- `instances` - Compute instances
- `deployments` - Deployment configurations
- `costs` - Cost/billing data
- `quotas` - Usage quotas

For a Sandbox Platform:
- `sandboxes` - Sandbox environments
- `containers` - Docker containers
- `files` - File storage
- `executions` - Command executions

Ask: "What THINGS exist in my service?"

### 5.4 Creating the Permission Matrix

Combine actions and resources to create permissions:

| Resource | read | write | create | delete | execute | admin |
|----------|------|-------|--------|--------|---------|-------|
| allocations | resource.read.allocations | resource.write.allocations | resource.create.allocations | resource.delete.allocations | - | resource.admin.allocations |
| instances | resource.read.instances | resource.write.instances | - | - | resource.execute.instances | - |
| costs | resource.read.costs | - | - | - | - | resource.admin.costs |

Not every combination makes sense. You don't "execute" a cost record. Design for your actual needs.

### 5.5 Deciding Default Grants

For each permission, decide:
- Should new users get this by default? (`default_grant: true`)
- Is this a privileged operation? (`default_grant: false`)

Guidance:
- `read` permissions are usually granted by default
- `create` and `write` are usually granted by default for user's own resources
- `delete` depends on reversibility (soft delete = grant, hard delete = maybe not)
- `admin` and `cross_tenant` are NEVER granted by default

---

## 6. The .permissions.json Schema

### 6.1 Purpose of This File

The `.permissions.json` file serves three purposes:

1. **Documentation** - Describes all permissions in your service
2. **Registration** - Tells the auth service what to register
3. **Reference** - Other developers can understand your permission model

### 6.2 Complete Schema Reference

```json
{
  "$schema": "https://auth.service.ab0t.com/schemas/permissions/v2",

  "service": {
    "id": "myservice",
    "name": "My Service",
    "description": "What this service does",
    "version": "1.0.0",
    "audience": "my-service",
    "maintainer": "team@company.com"
  },

  "registration": {
    "service": "myservice",
    "actions": ["read", "write", "create", "delete", "admin"],
    "resources": ["items", "users", "config"]
  },

  "permissions": [
    {
      "id": "myservice.read.items",
      "name": "Read Items",
      "description": "Allows user to view items",
      "intent": "Users need this to see their items in the dashboard. Low risk, grants read-only access.",
      "risk_level": "low",
      "cost_impact": false,
      "default_grant": true
    },
    {
      "id": "myservice.admin",
      "name": "Administrator",
      "description": "Full administrative access to all items in the organization",
      "intent": "Org-level admin. Can view, modify, delete ANY item in the org. Should only be granted to team leads.",
      "risk_level": "critical",
      "cost_impact": true,
      "default_grant": false,
      "security_notes": "Admins can access all org resources but cannot cross org boundaries."
    },
    {
      "id": "myservice.cross_tenant",
      "name": "Cross-Tenant Access",
      "description": "Allows access to items across organization boundaries",
      "intent": "Emergency support permission. Grants access to ANY organization. Only for senior support staff.",
      "risk_level": "critical",
      "cost_impact": false,
      "default_grant": false,
      "security_notes": "All cross-tenant access is logged and audited."
    }
  ],

  "roles": [
    {
      "id": "myservice-user",
      "name": "Standard User",
      "description": "Default role for regular users",
      "permissions": [
        "myservice.read.items",
        "myservice.create.items",
        "myservice.write.items",
        "myservice.delete.items"
      ],
      "default": true
    },
    {
      "id": "myservice-admin",
      "name": "Administrator",
      "description": "Organization administrator",
      "permissions": ["myservice.admin"],
      "default": false
    }
  ],

  "multi_tenancy": {
    "isolation_model": "organization",
    "tenant_field": "org_id",
    "enforcement": "strict",
    "cross_tenant_permission": "myservice.cross_tenant",
    "notes": "Users can only access items within their own organization."
  }
}
```

### 6.3 Field-by-Field Explanation

#### service block

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique service identifier. Must match registration.service |
| `name` | Yes | Human-readable name |
| `description` | Yes | What the service does |
| `version` | Yes | Schema version of your permissions |
| `audience` | Yes | JWT audience claim expected (usually `{service-id}`) |
| `maintainer` | No | Contact for questions |

#### registration block

This is what gets sent to the auth service during registration.

| Field | Required | Description |
|-------|----------|-------------|
| `service` | Yes | The service namespace. MUST match service.id |
| `actions` | Yes | List of action verbs (read, write, create, etc.) |
| `resources` | Yes | List of resource nouns (items, users, etc.) |

The auth service generates all valid permissions from: `{service}.{action}.{resource}` and `{service}.{action}` (without resource).

#### permissions block

Each permission entry documents a specific permission:

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | The permission string (e.g., `myservice.read.items`) |
| `name` | Yes | Human-readable name |
| `description` | Yes | What this permission allows |
| `intent` | Yes | WHY someone would need this permission. Explains the use case. |
| `risk_level` | Yes | One of: `low`, `medium`, `high`, `critical` |
| `cost_impact` | No | Does this permission affect billing/costs? |
| `default_grant` | Yes | Should new users get this automatically? |
| `security_notes` | No | Additional security considerations |
| `implies` | No | Other permissions this one includes |

**The `intent` field is critical.** It explains the reasoning behind the permission. Examples:

> "Users need this permission to provision new compute resources. Each allocation consumes cloud resources and incurs costs."

> "Enables permanent removal of compute resources. Termination is irreversible."

> "Org-level billing admin. View all user costs, set budgets, access org-wide reports."

#### roles block

Roles are bundles of permissions:

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Role identifier |
| `name` | Yes | Human-readable name |
| `description` | Yes | What this role is for |
| `permissions` | Yes | List of permission IDs |
| `default` | No | Is this the default role for new users? |

#### multi_tenancy block

Configures tenant isolation:

| Field | Required | Description |
|-------|----------|-------------|
| `isolation_model` | Yes | Usually `organization` |
| `tenant_field` | Yes | The field name for tenant ID (usually `org_id`) |
| `enforcement` | Yes | `strict` or `permissive` |
| `cross_tenant_permission` | Yes | Permission that bypasses isolation |
| `notes` | No | Additional documentation |

---

# Part III: Implementation

## 7. Installation and Setup

### 7.1 Adding the Dependency

In your `requirements.txt`:

```
# Authentication
git+https://github.com/ab0t-com/auth_wrapper.git
```

This installs the `ab0t-auth` library from our GitHub repository.

### 7.2 Environment Variables

Add to your `.env` file:

```bash
# Required: Auth service URL
AB0T_AUTH_URL=https://auth.service.ab0t.com

# Required: Your service's audience (from .permissions.json)
AB0T_AUTH_AUDIENCE=my-service

# Optional: Enable debug logging
AB0T_AUTH_DEBUG=false

# Optional: For testing only - bypasses auth entirely
# BOTH must be true for bypass to work (defense in depth)
# AB0T_AUTH_DEBUG=true
# AB0T_AUTH_BYPASS=true

# Recommended: Enable server-side permission checking
# Calls /permissions/check for real-time, authoritative verification
# Supports instant permission revocation without waiting for JWT expiry
AB0T_AUTH_PERMISSION_CHECK_MODE=server
```

Add to your `app/config.py`:

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # ... other settings ...

    # ab0t-auth Configuration
    AB0T_AUTH_URL: str = "https://auth.service.ab0t.com"
    AB0T_AUTH_AUDIENCE: str = "my-service"
    AB0T_AUTH_DEBUG: bool = False
    AB0T_AUTH_PERMISSION_CHECK_MODE: str = "server"  # Recommended for production

settings = Settings()
```

### 7.3 Verifying Installation

After rebuilding your container:

```bash
# Verify the library is installed
docker compose exec my-service pip show ab0t-auth

# Verify imports work
docker compose exec my-service python -c "
from ab0t_auth import AuthGuard, require_auth, require_permission
from ab0t_auth.tenant import TenantConfig
print('All imports successful!')
"
```

---

## 8. The Auth Module Pattern

### 8.1 Why a Separate Auth Module?

We create a dedicated `app/auth.py` file because:

1. **Single source of truth** - All auth configuration in one place
2. **Reusable type aliases** - Define once, use everywhere
3. **Consistent patterns** - All routes use the same approach
4. **Easy testing** - Mock one module, not scattered code

### 8.2 The Complete Auth Module Template

```python
"""
Authentication & Authorization Module for {Service Name}.

This module provides:
- AuthGuard configuration for JWT/API key validation
- TenantConfig for multi-tenant isolation
- Type aliases for route dependencies
- Check callbacks for additional validation
- Verification functions for Phase 2 ownership checks

Security Model:
- Users can only access resources in their own organization
- {service}.admin grants org-wide access (same org only)
- {service}.cross_tenant grants platform-wide access (platform staff only)

Two-Phase Verification:
- Phase 1 (dependency): Verify permission + basic tenant check
- Phase 2 (in-route): Verify access to THIS specific resource

Reference: sandbox-platform/auth_system_skill_ab0t.txt
"""
from typing import Annotated
from fastapi import Depends, Request

from ab0t_auth import (
    AuthGuard,
    AuthenticatedUser,
    require_auth,
    require_permission,
    require_any_permission,
    optional_auth,
)
from ab0t_auth.middleware import register_auth_exception_handlers
from ab0t_auth.errors import PermissionDeniedError
from ab0t_auth.tenant import TenantConfig

from .config import settings


# =============================================================================
# Global Configuration
# =============================================================================
# These are instantiated once when the module loads and shared across all requests.

auth = AuthGuard(
    auth_url=settings.AB0T_AUTH_URL,
    audience=settings.AB0T_AUTH_AUDIENCE,
    debug=settings.AB0T_AUTH_DEBUG,
    permission_check_mode=settings.AB0T_AUTH_PERMISSION_CHECK_MODE,  # "server" recommended
)

# TenantConfig defines how multi-tenant isolation works.
# This is critical for security - it ensures users cannot access other orgs.
tenant_config = TenantConfig(
    # Core isolation settings
    enforce_tenant_isolation=True,   # Users can only access their own tenant
    enforce_org_isolation=True,      # Strict org boundaries (recommended)

    # Admin access settings
    allow_cross_tenant_admin=True,   # Platform admins can cross org boundaries
    cross_tenant_permission="myservice.cross_tenant",  # Permission required

    # Organization hierarchy (if you have parent/child orgs)
    enable_org_hierarchy=False,      # Set True if you support nested orgs
    allow_ancestor_access=False,     # Can parent org see child resources?
    allow_descendant_access=False,   # Can child org see parent resources?
)


# =============================================================================
# Check Callbacks
# =============================================================================
# Check callbacks are functions that perform additional validation beyond
# just checking permissions. They receive the user and request, and return
# True (allow) or False (deny).
#
# Signature: (user: AuthenticatedUser, request: Request) -> bool
#
# When a check returns False, a PermissionDeniedError is raised automatically.

def belongs_to_org(user: AuthenticatedUser, request: Request) -> bool:
    """
    Verify user belongs to the organization specified in the request.

    This check enforces multi-tenant isolation at the request level.
    It looks for org_id in both path parameters and query parameters.

    Cross-tenant admins (with cross_tenant permission) bypass this check.

    Args:
        user: The authenticated user making the request
        request: The FastAPI request object

    Returns:
        True if access should be allowed, False otherwise
    """
    # Look for org_id in path params first, then query params
    org_id = request.path_params.get("org_id") or request.query_params.get("org_id")

    # If no org_id in request, no org constraint to check
    if not org_id:
        return True

    # User is in the same org - allowed
    if user.org_id == org_id:
        return True

    # User has cross-tenant permission - allowed (for platform admins)
    if user.has_permission(tenant_config.cross_tenant_permission):
        return True

    # Different org and no cross-tenant permission - denied
    return False


def can_access_user_resource(user: AuthenticatedUser, request: Request) -> bool:
    """
    Phase 1 check for accessing another user's resource.

    SECURITY WARNING: This is only Phase 1 verification!
    Routes using this callback MUST also call verify_user_org_access()
    in Phase 2 to prevent cross-org attacks.

    The reason we need Phase 2: An admin from Org A could pass this check
    (they have admin permission) but should not access Org B resources.
    Phase 2 checks the actual resource's org_id.

    Args:
        user: The authenticated user
        request: The FastAPI request

    Returns:
        True if Phase 1 passes (route must still do Phase 2)
    """
    # Get target user ID from path
    target_user_id = request.path_params.get("user_id")

    # No user_id in path - no user-specific constraint
    if not target_user_id:
        return True

    # Accessing own resources - always allowed
    if user.user_id == target_user_id:
        return True

    # Cross-tenant admin - allowed (can access any org)
    if user.has_permission(tenant_config.cross_tenant_permission):
        return True

    # Org admin - allowed in Phase 1, but MUST verify org in Phase 2
    if user.has_permission("myservice.admin"):
        return True

    # Regular user trying to access another user - denied
    return False


def is_not_suspended(user: AuthenticatedUser, request: Request) -> bool:
    """
    Verify user account is not suspended.

    Suspended users should not be able to create, modify, or delete resources.
    The suspended flag is stored in user metadata (from JWT claims).

    Returns:
        True if user is not suspended, False if suspended
    """
    return not user.metadata.get("suspended", False)


def is_within_quota(user: AuthenticatedUser, request: Request) -> bool:
    """
    Preliminary quota check based on user metadata.

    This is a quick check using token claims. For accurate quota
    enforcement, you should also check the database in your route.

    Returns:
        True if user appears to be within quota
    """
    return not user.metadata.get("quota_exceeded", False)


# =============================================================================
# Type Aliases - Basic Authentication
# =============================================================================
# Type aliases make route signatures cleaner and self-documenting.
# Instead of: async def route(user: AuthenticatedUser = Depends(require_auth(auth)))
# You write:  async def route(user: CurrentUser)

# Any authenticated user (JWT or API key)
CurrentUser = Annotated[AuthenticatedUser, Depends(require_auth(auth))]

# Optional authentication - returns None if not authenticated
# Useful for routes that work differently for logged-in vs anonymous users
OptionalUser = Annotated[AuthenticatedUser | None, Depends(optional_auth(auth))]


# =============================================================================
# Type Aliases - Permission-Based with Checks
# =============================================================================
# These combine permission requirements with check callbacks.
# The check callback runs AFTER permission is verified.

# Read operations - user must be in same org
Reader = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "myservice.read", check=belongs_to_org)
)]

# Create operations - user must be in org, not suspended, within quota
# Uses require_any_permission for multiple valid permissions
Creator = Annotated[AuthenticatedUser, Depends(
    require_any_permission(
        auth,
        "myservice.create.items",
        "myservice.create.other",
        checks=[belongs_to_org, is_not_suspended, is_within_quota],
        check_mode="all",  # All checks must pass
    )
)]

# Write/update operations - org isolation enforced
Writer = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "myservice.write", check=belongs_to_org)
)]

# Delete operations - org isolation enforced
Deleter = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "myservice.delete", check=belongs_to_org)
)]

# Admin operations - org-level access (still respects org boundaries)
Admin = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "myservice.admin", check=belongs_to_org)
)]

# Platform admin - cross-tenant access (no org restriction)
PlatformAdmin = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "myservice.admin.config")
)]


# =============================================================================
# Phase 2 Verification Functions
# =============================================================================
# These functions are called IN routes after fetching the resource from
# the database. They verify the user can access THIS specific resource.
#
# Phase 1 (dependency) = Does user have permission? Basic org check?
# Phase 2 (these functions) = Can user access THIS resource specifically?

def verify_resource_access(resource, user: AuthenticatedUser) -> None:
    """
    Verify user can access this specific resource.

    This is Phase 2 verification. Call this after fetching a resource
    from the database, before returning it to the user.

    Access rules (in order of precedence):
    1. Owner - user_id matches resource.user_id
    2. Org Admin - user has admin permission AND same org_id
    3. Cross-Tenant - user has cross_tenant permission

    Args:
        resource: The resource object (must have user_id and org_id attributes)
        user: The authenticated user

    Raises:
        PermissionDeniedError: If user cannot access this resource
    """
    # Rule 1: Owner can always access their own resource
    if resource.user_id == user.user_id:
        return

    # Rule 2: Org admin can access resources in their org
    if user.has_permission("myservice.admin") and resource.org_id == user.org_id:
        return

    # Rule 3: Cross-tenant admin can access any resource
    if user.has_permission(tenant_config.cross_tenant_permission):
        return

    # No rule matched - access denied
    raise PermissionDeniedError(
        "Access denied to this resource",
        required_permission="myservice.admin",
    )


def verify_user_org_access(target_org_id: str, user: AuthenticatedUser) -> None:
    """
    Verify user can access resources from the target organization.

    This is the critical Phase 2 check that prevents cross-org attacks.
    Call this when accessing another user's resources to ensure the
    target user is in the same organization.

    Without this check:
    - Admin from Org A has "admin" permission
    - Admin requests /users/user_in_org_b/items
    - Phase 1 passes (admin permission exists)
    - Admin gets Org B's data! (SECURITY BREACH)

    With this check:
    - Phase 2 verifies target_org_id == user.org_id
    - Request is denied because orgs don't match

    Args:
        target_org_id: The org_id of the resource being accessed
        user: The authenticated user

    Raises:
        PermissionDeniedError: If user cannot access this org
    """
    # Same org - allowed
    if user.org_id == target_org_id:
        return

    # Cross-tenant permission - allowed
    if user.has_permission(tenant_config.cross_tenant_permission):
        return

    # Different org, no cross-tenant - denied
    raise PermissionDeniedError(
        "Access denied - user belongs to different organization",
        required_permission=tenant_config.cross_tenant_permission,
    )


def verify_same_org(resource_org_id: str, user: AuthenticatedUser) -> None:
    """
    Simple org check - verify user and resource are in same org.

    Args:
        resource_org_id: The org_id of the resource
        user: The authenticated user

    Raises:
        PermissionDeniedError: If not in same org (and no cross_tenant)
    """
    if user.org_id != resource_org_id:
        if not user.has_permission(tenant_config.cross_tenant_permission):
            raise PermissionDeniedError(
                "Access denied - resource belongs to different organization",
                required_permission=tenant_config.cross_tenant_permission,
            )


# =============================================================================
# Utility Functions
# =============================================================================

def get_user_filter(user: AuthenticatedUser) -> dict:
    """
    Get database filter for listing resources user can access.

    This returns a filter dict that can be passed to database queries
    to automatically scope results to what the user can see.

    Access levels:
    - Cross-tenant: {} (no filter - see everything)
    - Admin: {"org_id": user.org_id} (see all in org)
    - User: {"user_id": user.user_id, "org_id": user.org_id} (see own only)

    Usage:
        filter = get_user_filter(user)
        items = await db.list_items(**filter)

    Returns:
        Dict of filter parameters
    """
    # Cross-tenant admins can see everything
    if user.has_permission(tenant_config.cross_tenant_permission):
        return {}

    # Org admins can see everything in their org
    if user.has_permission("myservice.admin"):
        return {"org_id": user.org_id}

    # Regular users can only see their own resources
    return {"user_id": user.user_id, "org_id": user.org_id}


# =============================================================================
# Exports
# =============================================================================
# List all public symbols for `from app.auth import *`

__all__ = [
    # Core
    "auth",
    "tenant_config",
    "register_auth_exception_handlers",
    # Types
    "AuthenticatedUser",
    "PermissionDeniedError",
    # Basic auth
    "CurrentUser",
    "OptionalUser",
    # Permission-based
    "Reader",
    "Creator",
    "Writer",
    "Deleter",
    "Admin",
    "PlatformAdmin",
    # Verification (Phase 2)
    "verify_resource_access",
    "verify_user_org_access",
    "verify_same_org",
    # Utilities
    "get_user_filter",
    # Check callbacks
    "belongs_to_org",
    "can_access_user_resource",
    "is_not_suspended",
    "is_within_quota",
]
```

### 8.3 Integrating with main.py

```python
# app/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI

from .auth import auth, register_auth_exception_handlers


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.

    The auth.lifespan() context manager:
    - Fetches JWKS keys from the auth service
    - Sets up token caching
    - Cleans up resources on shutdown
    """
    async with auth.lifespan():
        # Your other startup code here
        yield
        # Your shutdown code here


app = FastAPI(
    title="My Service",
    lifespan=lifespan,
)

# Register exception handlers BEFORE including routers.
# This ensures auth errors return proper JSON responses:
# - 401 for authentication failures
# - 403 for permission denied
register_auth_exception_handlers(app)

# Now include your routers
from .api import router
app.include_router(router, prefix="/api")
```

---

## 9. Check Callbacks Deep Dive

### 9.1 The Purpose of Check Callbacks

Check callbacks extend permission checks with additional logic. While permissions answer "does this user have access to this type of operation?", callbacks answer "can this user perform this operation right now, in this context?"

Examples of what callbacks can verify:
- Is the user in the right organization?
- Is the user's account suspended?
- Is the user within their quota?
- Is this resource in a valid state for this operation?
- Is the request coming from an allowed IP range?

### 9.2 Callback Signature

```python
def my_callback(user: AuthenticatedUser, request: Request) -> bool:
    """
    A check callback function.

    Args:
        user: The authenticated user object with all claims
        request: The FastAPI Request object

    Returns:
        True: Allow the request to proceed
        False: Deny the request (raises PermissionDeniedError)
    """
    # Your logic here
    return True  # or False
```

### 9.3 Accessing Request Data

You can access various parts of the request:

```python
def my_callback(user: AuthenticatedUser, request: Request) -> bool:
    # Path parameters (from URL path)
    # URL: /items/{item_id}/details/{detail_id}
    item_id = request.path_params.get("item_id")
    detail_id = request.path_params.get("detail_id")

    # Query parameters (from URL query string)
    # URL: /items?org_id=123&status=active
    org_id = request.query_params.get("org_id")
    status = request.query_params.get("status")

    # Headers
    custom_header = request.headers.get("X-Custom-Header")

    # User data
    user_org = user.org_id
    user_perms = user.permissions
    user_meta = user.metadata

    return True
```

### 9.4 Single vs Multiple Callbacks

**Single callback:**
```python
Reader = Annotated[AuthenticatedUser, Depends(
    require_permission(auth, "myservice.read", check=belongs_to_org)
)]
```

**Multiple callbacks - ALL must pass (default):**
```python
Creator = Annotated[AuthenticatedUser, Depends(
    require_permission(
        auth,
        "myservice.create",
        checks=[belongs_to_org, is_not_suspended, is_within_quota],
        check_mode="all",  # Default: all must return True
    )
)]
```

**Multiple callbacks - ANY can pass:**
```python
Accessor = Annotated[AuthenticatedUser, Depends(
    require_permission(
        auth,
        "myservice.read",
        checks=[is_owner, is_org_admin, is_platform_admin],
        check_mode="any",  # Any one returning True is enough
    )
)]
```

---

## 10. Two-Phase Verification

### 10.1 Why Two Phases?

The two-phase pattern exists to solve a subtle but critical security problem.

**The Problem:**

Consider a route that lets admins view any user's data:

```python
# DANGEROUS: Only Phase 1
@router.get("/users/{user_id}/items")
async def get_user_items(user_id: str, user: Admin):
    return await db.get_items(user_id=user_id)
```

An admin from Org A could:
1. Call `/users/user_in_org_b/items`
2. Pass the Admin dependency (they have admin permission)
3. Get items belonging to a user in Org B!

This is a cross-org data breach.

**The Solution:**

Add Phase 2 to verify the target resource's organization:

```python
# SECURE: Phase 1 + Phase 2
@router.get("/users/{user_id}/items")
async def get_user_items(
    user_id: str,
    user: Admin,
    db: Database = Depends(get_db)
):
    # Phase 1 passed (Admin dependency checked permission + belongs_to_org)

    # Phase 2: Verify org boundary
    if user_id != user.user_id:  # Only if accessing another user
        target_user = await db.get_user(user_id)
        if target_user:
            verify_user_org_access(target_user.org_id, user)

    return await db.get_items(user_id=user_id)
```

### 10.2 When to Use Each Phase

**Phase 1 only (dependency):**
- Listing user's own resources
- Creating new resources (will be owned by user)
- Public endpoints with auth

**Phase 1 + Phase 2:**
- Accessing a specific resource by ID
- Accessing another user's resources
- Any operation where org_id comes from the database

### 10.3 The Pattern

```python
@router.get("/items/{item_id}")
async def get_item(
    item_id: str,
    user: Reader,  # Phase 1: permission + belongs_to_org
    db: Database = Depends(get_db)
):
    # Fetch the resource
    item = await db.get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    # Phase 2: verify access to THIS specific resource
    verify_resource_access(item, user)

    return item
```

---

## 11. Multi-Tenant Isolation

### 11.1 What Is a Tenant?

In our system, a "tenant" is an organization. Each organization:
- Has a unique `org_id`
- Has its own users
- Has its own resources
- Should be completely isolated from other organizations

### 11.2 TenantConfig Explained

```python
tenant_config = TenantConfig(
    # Should we enforce that users can only see their tenant's data?
    enforce_tenant_isolation=True,

    # Should we strictly verify org_id matches?
    enforce_org_isolation=True,

    # Can platform admins bypass isolation?
    allow_cross_tenant_admin=True,

    # What permission grants cross-tenant access?
    cross_tenant_permission="myservice.cross_tenant",

    # Do you have parent/child organizations?
    enable_org_hierarchy=False,

    # If hierarchy enabled, can parent see child resources?
    allow_ancestor_access=False,

    # If hierarchy enabled, can child see parent resources?
    allow_descendant_access=False,
)
```

### 11.3 Database Query Filtering

Always filter database queries by org_id:

```python
@router.get("/items")
async def list_items(user: Reader, db: Database = Depends(get_db)):
    # Use get_user_filter for automatic scoping
    filter = get_user_filter(user)

    # This returns:
    # - {} for cross_tenant admins (see all)
    # - {"org_id": "..."} for org admins (see org)
    # - {"user_id": "...", "org_id": "..."} for users (see own)

    return await db.list_items(**filter)
```

### 11.4 Common Isolation Patterns

**Pattern 1: User's own resources only**
```python
@router.get("/my/items")
async def list_my_items(user: CurrentUser, db: Database = Depends(get_db)):
    return await db.list_items(user_id=user.user_id, org_id=user.org_id)
```

**Pattern 2: Org-wide with admin check**
```python
@router.get("/org/items")
async def list_org_items(user: Admin, db: Database = Depends(get_db)):
    return await db.list_items(org_id=user.org_id)
```

**Pattern 3: Specific resource with ownership check**
```python
@router.get("/items/{item_id}")
async def get_item(item_id: str, user: Reader, db: Database = Depends(get_db)):
    item = await db.get_item(item_id)
    if not item:
        raise HTTPException(404)
    verify_resource_access(item, user)  # Checks owner/admin/cross_tenant
    return item
```

---

# Part IV: Registration and Verification

## 12. Registering with the Auth Service

### 12.1 The Registration Script

Create `register-service-permissions.sh` in your service root:

```bash
#!/bin/bash
#
# register-service-permissions.sh
# ================================
# Registers this service with the Auth Service.
#
# This script is IDEMPOTENT - safe to run multiple times.
# It will:
# 1. Create admin account (or login if exists)
# 2. Create organization (or find existing)
# 3. Register permissions
# 4. Create API key
# 5. Save credentials
#
# Usage:
#   ./register-service-permissions.sh
#   AUTH_SERVICE_URL=http://localhost:8001 ./register-service-permissions.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERMISSIONS_FILE="$SCRIPT_DIR/.permissions.json"
AUTH_SERVICE_URL="${AUTH_SERVICE_URL:-https://auth.service.ab0t.com}"

# Verify permissions file exists
if [ ! -f "$PERMISSIONS_FILE" ]; then
    echo "ERROR: .permissions.json not found at $PERMISSIONS_FILE"
    echo "Create this file before running registration."
    exit 1
fi

# Load service info
SERVICE_ID=$(jq -r '.service.id' "$PERMISSIONS_FILE")
SERVICE_NAME=$(jq -r '.service.name' "$PERMISSIONS_FILE")

echo "=== Registering $SERVICE_NAME ==="
echo "Service ID: $SERVICE_ID"
echo "Auth Service: $AUTH_SERVICE_URL"

# Create credentials directory
mkdir -p "$SCRIPT_DIR/credentials"
CREDS_FILE="$SCRIPT_DIR/credentials/${SERVICE_ID}.json"

# Check for existing credentials
if [ -f "$CREDS_FILE" ]; then
    echo "Found existing credentials - will update"
    ADMIN_EMAIL=$(jq -r '.admin.email' "$CREDS_FILE")
    ADMIN_PASSWORD=$(jq -r '.admin.password' "$CREDS_FILE")
else
    # Derive credentials from service ID
    ADMIN_EMAIL="admin+${SERVICE_ID}@company.com"
    ADMIN_PASSWORD="${SERVICE_ID}Admin2024!Secure"
fi

# Step 1: Create/login admin account
echo ""
echo "Step 1: Admin Account"
REGISTER_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
        "email": "'"$ADMIN_EMAIL"'",
        "password": "'"$ADMIN_PASSWORD"'",
        "name": "'"$SERVICE_NAME"' Admin"
    }')

if echo "$REGISTER_RESPONSE" | grep -q "access_token"; then
    echo "  Created new admin account"
    ACCESS_TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.access_token')
else
    echo "  Admin exists, logging in..."
    LOGIN_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"email": "'"$ADMIN_EMAIL"'", "password": "'"$ADMIN_PASSWORD"'"}')
    ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')

    if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
        echo "  ERROR: Login failed"
        echo "$LOGIN_RESPONSE"
        exit 1
    fi
fi

# Step 2: Create organization
echo ""
echo "Step 2: Organization"
ORG_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/organizations/" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "'"$SERVICE_NAME"'",
        "slug": "'"$SERVICE_ID"'"
    }')

if echo "$ORG_RESPONSE" | grep -q '"id"'; then
    ORG_ID=$(echo "$ORG_RESPONSE" | jq -r '.id // .organization.id')
    echo "  Organization ID: $ORG_ID"
else
    # Try to find existing org
    echo "  Finding existing organization..."
    ORG_ID=$(curl -s "$AUTH_SERVICE_URL/organizations/" \
        -H "Authorization: Bearer $ACCESS_TOKEN" | \
        jq -r '.organizations[] | select(.slug == "'"$SERVICE_ID"'") | .id')
fi

# Step 3: Login with org context
echo ""
echo "Step 3: Org-scoped login"
LOGIN_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
        "email": "'"$ADMIN_EMAIL"'",
        "password": "'"$ADMIN_PASSWORD"'",
        "org_id": "'"$ORG_ID"'"
    }')
ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')

# Step 4: Register permissions
echo ""
echo "Step 4: Registering permissions"
REGISTRATION_BLOCK=$(jq -c '.registration' "$PERMISSIONS_FILE")
REGISTER_RESULT=$(curl -s -X POST "$AUTH_SERVICE_URL/permissions/registry/register" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$REGISTRATION_BLOCK")
echo "  $REGISTER_RESULT"

# Step 5: Create API key
echo ""
echo "Step 5: Creating API key"
PERMISSIONS_LIST=$(jq -r '[.permissions[].id] | join(",")' "$PERMISSIONS_FILE")
API_KEY_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/api-keys/" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "'"$SERVICE_NAME"' API Key",
        "permissions": "'"$PERMISSIONS_LIST"'"
    }')
API_KEY=$(echo "$API_KEY_RESPONSE" | jq -r '.key')

if [ -n "$API_KEY" ] && [ "$API_KEY" != "null" ]; then
    echo "  API Key created: ${API_KEY:0:20}..."
else
    echo "  Using existing API key"
    API_KEY=$(jq -r '.api_key.key' "$CREDS_FILE" 2>/dev/null || echo "")
fi

# Step 6: Save credentials
echo ""
echo "Step 6: Saving credentials"
cat > "$CREDS_FILE" << EOF
{
  "admin": {
    "email": "$ADMIN_EMAIL",
    "password": "$ADMIN_PASSWORD"
  },
  "organization": {
    "id": "$ORG_ID",
    "name": "$SERVICE_NAME"
  },
  "api_key": {
    "key": "$API_KEY"
  },
  "registered_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
echo "  Saved to: $CREDS_FILE"

echo ""
echo "=== Registration Complete ==="
```

Make it executable:
```bash
chmod +x register-service-permissions.sh
```

### 12.2 Running Registration

```bash
# Production
./register-service-permissions.sh

# Local development
AUTH_SERVICE_URL=http://localhost:8001 ./register-service-permissions.sh
```

---

## 13. Verifying Your Setup

### 13.1 Check Service Is Registered

```bash
# List all services
curl -s https://auth.service.ab0t.com/permissions/registry/services | \
  jq '.services[].service'

# Find your service
curl -s https://auth.service.ab0t.com/permissions/registry/services | \
  jq '.services[] | select(.service == "myservice")'
```

### 13.2 Check Permissions Are Valid

```bash
# List valid permissions for your service
curl -s https://auth.service.ab0t.com/permissions/registry/valid-permissions | \
  jq '.permissions | map(select(startswith("myservice")))'
```

### 13.3 Test Authentication

```bash
# Load your API key
API_KEY=$(jq -r '.api_key.key' credentials/myservice.json)

# Test a protected endpoint
curl -H "X-API-Key: $API_KEY" http://localhost:8007/api/items

# Should return 200 with data, not 401/403
```

### 13.4 Test Service Health

```bash
# Check if your service is running
docker ps | grep myservice

# Check service logs
docker compose logs myservice | tail -50

# Test health endpoint (should work without auth)
curl http://localhost:YOUR_PORT/health
```

### 13.5 Complete Verification Checklist

Run through this checklist to verify your integration is complete:

```bash
# === Environment ===
# [ ] Auth service is reachable
curl -s $AB0T_AUTH_URL/health | jq '.status'
# Expected: "healthy"

# [ ] Your service is running
curl -s http://localhost:YOUR_PORT/health
# Expected: 200 OK

# === Registration ===
# [ ] Service is registered
curl -s $AB0T_AUTH_URL/permissions/registry/services | jq '.services[] | select(.service == "myservice")'
# Expected: Your service object

# [ ] Permissions are valid
curl -s $AB0T_AUTH_URL/permissions/registry/valid-permissions | jq '[.permissions[] | select(startswith("myservice"))]'
# Expected: List of your permissions

# === Authentication ===
# [ ] Protected endpoints reject no auth
curl -s -o /dev/null -w "%{http_code}" http://localhost:YOUR_PORT/api/items
# Expected: 401

# [ ] Valid API key is accepted
curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: $YOUR_API_KEY" http://localhost:YOUR_PORT/api/items
# Expected: 200 (or 403 if permission issue, not 401)

# === Authorization ===
# [ ] No-permission user is rejected
curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: $NO_PERMS_KEY" http://localhost:YOUR_PORT/api/items
# Expected: 403

# [ ] Admin endpoint rejects regular user
curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: $REGULAR_USER_KEY" http://localhost:YOUR_PORT/api/admin/items
# Expected: 403

# === Multi-Tenancy ===
# [ ] Cross-org access is blocked (if applicable)
# Test by having User A try to access User B's resource in different org
# Expected: 403
```

If all checks pass, your integration is complete.

---

# Part V: Testing

## 14. Security Testing Philosophy

### 14.1 Why Security Tests?

Security tests verify that your auth implementation actually protects resources. They are "negative tests" - they verify that attacks FAIL.

A good security test suite:
1. Attempts every type of attack an attacker might try
2. Verifies each attack is blocked
3. Documents what protections exist
4. Catches regressions when code changes

### 14.2 Attack Categories

| Category | What It Tests |
|----------|---------------|
| No Auth | Endpoints reject unauthenticated requests |
| Invalid Tokens | Malformed, expired, tampered tokens rejected |
| Permission Bypass | Users without permission are blocked |
| Cross-User | User A cannot access User B's resources |
| Cross-Org | Org A cannot access Org B's resources |
| Privilege Escalation | Regular users cannot access admin functions |
| Injection | SQL, path traversal, etc. don't bypass auth |
| Header Manipulation | Forged headers don't grant access |

### 14.3 Red Team vs Blue Team

**Red Team (Attack Perspective):**
- "How would I bypass this?"
- "What happens if I send a malformed token?"
- "Can I trick the system into trusting me?"

**Blue Team (Defense Perspective):**
- "Does every endpoint require auth?"
- "Are permissions checked correctly?"
- "Is org isolation enforced?"

Good security tests think like attackers.

---

## 15. Writing Security Tests

### 15.1 Unit Tests (Python)

```python
"""
Security tests for auth module.

These tests verify:
1. Org boundaries are enforced
2. Phase 2 verification blocks cross-org access
3. Cross-tenant permission works correctly

Run with: pytest tests/test_auth_security.py -v
"""
import pytest
from unittest.mock import Mock
from fastapi import Request

from app.auth import (
    tenant_config,
    belongs_to_org,
    can_access_user_resource,
    verify_resource_access,
    verify_user_org_access,
)
from ab0t_auth.errors import PermissionDeniedError


# =============================================================================
# Test Fixtures
# =============================================================================

def create_mock_user(user_id: str, org_id: str, permissions: list = None):
    """Create a mock user for testing."""
    user = Mock()
    user.user_id = user_id
    user.org_id = org_id
    user._permissions = permissions or []
    user.has_permission = lambda p: p in user._permissions
    user.metadata = {}
    return user


def create_mock_request(path_params: dict = None, query_params: dict = None):
    """Create a mock FastAPI request for testing."""
    request = Mock(spec=Request)
    request.path_params = path_params or {}
    request.query_params = query_params or {}
    return request


def create_mock_resource(resource_id: str, user_id: str, org_id: str):
    """Create a mock resource for testing."""
    resource = Mock()
    resource.id = resource_id
    resource.user_id = user_id
    resource.org_id = org_id
    return resource


# =============================================================================
# TenantConfig Tests
# =============================================================================

class TestTenantConfig:
    """Verify tenant configuration is correct."""

    def test_cross_tenant_permission_defined(self):
        """Cross-tenant permission must be configured."""
        assert tenant_config.cross_tenant_permission is not None
        assert len(tenant_config.cross_tenant_permission) > 0

    def test_org_isolation_enabled(self):
        """Org isolation should be enabled for security."""
        assert tenant_config.enforce_org_isolation is True

    def test_tenant_isolation_enabled(self):
        """Tenant isolation should be enabled for security."""
        assert tenant_config.enforce_tenant_isolation is True


# =============================================================================
# belongs_to_org Tests
# =============================================================================

class TestBelongsToOrg:
    """Test the belongs_to_org check callback."""

    def test_no_org_constraint_allows(self):
        """When no org_id in request, should allow."""
        user = create_mock_user("user1", "org1")
        request = create_mock_request()
        assert belongs_to_org(user, request) is True

    def test_same_org_allows(self):
        """User in same org should be allowed."""
        user = create_mock_user("user1", "org1")
        request = create_mock_request(path_params={"org_id": "org1"})
        assert belongs_to_org(user, request) is True

    def test_different_org_denies(self):
        """User in different org should be denied."""
        user = create_mock_user("user1", "org1")
        request = create_mock_request(path_params={"org_id": "org2"})
        assert belongs_to_org(user, request) is False

    def test_cross_tenant_bypasses(self):
        """Cross-tenant permission should bypass org check."""
        user = create_mock_user("user1", "org1", [tenant_config.cross_tenant_permission])
        request = create_mock_request(path_params={"org_id": "org2"})
        assert belongs_to_org(user, request) is True

    def test_checks_query_params(self):
        """Should also check org_id in query params."""
        user = create_mock_user("user1", "org1")
        request = create_mock_request(query_params={"org_id": "org2"})
        assert belongs_to_org(user, request) is False


# =============================================================================
# verify_user_org_access Tests (Phase 2)
# =============================================================================

class TestVerifyUserOrgAccess:
    """Test Phase 2 org verification."""

    def test_same_org_passes(self):
        """Same org should not raise."""
        user = create_mock_user("admin", "org1", ["myservice.admin"])
        verify_user_org_access("org1", user)  # Should not raise

    def test_different_org_raises(self):
        """Different org should raise PermissionDeniedError."""
        user = create_mock_user("admin", "org1", ["myservice.admin"])
        with pytest.raises(PermissionDeniedError):
            verify_user_org_access("org2", user)

    def test_cross_tenant_bypasses(self):
        """Cross-tenant permission should allow different org."""
        user = create_mock_user("superadmin", "org1", [tenant_config.cross_tenant_permission])
        verify_user_org_access("org2", user)  # Should not raise


# =============================================================================
# verify_resource_access Tests (Phase 2)
# =============================================================================

class TestVerifyResourceAccess:
    """Test Phase 2 resource verification."""

    def test_owner_allowed(self):
        """Resource owner should have access."""
        user = create_mock_user("user1", "org1")
        resource = create_mock_resource("res1", "user1", "org1")
        verify_resource_access(resource, user)  # Should not raise

    def test_admin_same_org_allowed(self):
        """Admin in same org should have access."""
        user = create_mock_user("admin", "org1", ["myservice.admin"])
        resource = create_mock_resource("res1", "user1", "org1")
        verify_resource_access(resource, user)  # Should not raise

    def test_admin_different_org_denied(self):
        """Admin in different org should be denied."""
        user = create_mock_user("admin", "org1", ["myservice.admin"])
        resource = create_mock_resource("res1", "user2", "org2")
        with pytest.raises(PermissionDeniedError):
            verify_resource_access(resource, user)

    def test_cross_tenant_bypasses(self):
        """Cross-tenant should access any resource."""
        user = create_mock_user("superadmin", "org1", [tenant_config.cross_tenant_permission])
        resource = create_mock_resource("res1", "user2", "org2")
        verify_resource_access(resource, user)  # Should not raise

    def test_regular_user_other_resource_denied(self):
        """Regular user cannot access another user's resource."""
        user = create_mock_user("user1", "org1")
        resource = create_mock_resource("res1", "user2", "org1")
        with pytest.raises(PermissionDeniedError):
            verify_resource_access(resource, user)


# =============================================================================
# Attack Scenario Tests
# =============================================================================

class TestCrossOrgAttack:
    """
    Test the specific attack: Admin from Org A accessing Org B data.

    This is the attack that Phase 2 verification prevents.
    """

    def test_admin_cross_org_attack_blocked(self):
        """
        Scenario:
        - Admin from Org A has admin permission
        - Tries to access resource from Org B
        - Should be BLOCKED by verify_user_org_access
        """
        # Attacker: Admin from Org A
        attacker = create_mock_user("admin_a", "org_a", ["myservice.admin"])

        # Target: Resource in Org B
        target_org_id = "org_b"

        # Phase 1 would pass (admin has permission)
        # But Phase 2 should block
        with pytest.raises(PermissionDeniedError):
            verify_user_org_access(target_org_id, attacker)

    def test_legitimate_admin_access_allowed(self):
        """
        Scenario:
        - Admin from Org A has admin permission
        - Accesses resource from Org A
        - Should be ALLOWED
        """
        admin = create_mock_user("admin_a", "org_a", ["myservice.admin"])
        resource = create_mock_resource("res1", "user_a", "org_a")

        # Both phases should pass
        verify_resource_access(resource, admin)  # Should not raise
```

### 15.2 Integration Tests (Shell)

Create `tests/security/auth_bypass_tests.sh`:

```bash
#!/bin/bash
# =============================================================================
# Security Bypass Test Suite
# =============================================================================
# These tests attempt various attacks and verify they are all blocked.
# A passing test suite means security is working correctly.
#
# Usage: ./auth_bypass_tests.sh [BASE_URL] [AUTH_MODE]
# Example: ./auth_bypass_tests.sh http://localhost:8007 apikey
# =============================================================================

set -o pipefail

BASE_URL="${1:-http://localhost:8007}"
AUTH_MODE="${2:-apikey}"  # "apikey" or "bearer"

# Test tokens - configure for your environment
USER_A_TOKEN="${USER_A_TOKEN:-your_user_a_token}"
USER_B_TOKEN="${USER_B_TOKEN:-your_user_b_token}"
ADMIN_TOKEN="${ADMIN_TOKEN:-your_admin_token}"
NO_PERMS_TOKEN="${NO_PERMS_TOKEN:-your_no_perms_token}"

# Counters
TESTS_PASSED=0
TESTS_FAILED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# =============================================================================
# Helper Functions
# =============================================================================

run_test() {
    local name="$1"
    local expected="$2"
    local method="$3"
    local endpoint="$4"
    local token="$5"
    local body="$6"

    if [ "$AUTH_MODE" = "apikey" ]; then
        AUTH_HEADER="X-API-Key: $token"
    else
        AUTH_HEADER="Authorization: Bearer $token"
    fi

    if [ -n "$body" ]; then
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            -X "$method" "$BASE_URL$endpoint" \
            -H "$AUTH_HEADER" \
            -H "Content-Type: application/json" \
            -d "$body")
    elif [ -n "$token" ]; then
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            -X "$method" "$BASE_URL$endpoint" \
            -H "$AUTH_HEADER")
    else
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            -X "$method" "$BASE_URL$endpoint")
    fi

    if [ "$STATUS" = "$expected" ]; then
        echo -e "${GREEN}PASS${NC}: $name (got $STATUS)"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}FAIL${NC}: $name (expected $expected, got $STATUS)"
        ((TESTS_FAILED++))
    fi
}

# =============================================================================
# Test Suite
# =============================================================================

echo "========================================"
echo "Security Bypass Test Suite"
echo "Base URL: $BASE_URL"
echo "Auth Mode: $AUTH_MODE"
echo "========================================"
echo ""

# --- Section 1: No Authentication ---
echo -e "${YELLOW}=== Section 1: No Authentication ===${NC}"
run_test "Protected endpoint without token" "401" "GET" "/api/items" ""
run_test "Create without token" "401" "POST" "/api/items" "" '{"name":"test"}'
run_test "Admin endpoint without token" "401" "GET" "/api/admin/items" ""

# --- Section 2: Invalid Tokens ---
echo ""
echo -e "${YELLOW}=== Section 2: Invalid Tokens ===${NC}"
run_test "Invalid token string" "401" "GET" "/api/items" "invalid-token-123"
run_test "Malformed JWT" "401" "GET" "/api/items" "not.a.jwt"
run_test "Empty token" "401" "GET" "/api/items" ""

# --- Section 3: Permission Bypass ---
echo ""
echo -e "${YELLOW}=== Section 3: Permission Bypass ===${NC}"
run_test "No perms - create" "403" "POST" "/api/items" "$NO_PERMS_TOKEN" '{"name":"test"}'
run_test "No perms - admin" "403" "GET" "/api/admin/items" "$NO_PERMS_TOKEN"
run_test "No perms - delete" "403" "DELETE" "/api/items/item1" "$NO_PERMS_TOKEN"

# --- Section 4: Cross-User Access ---
echo ""
echo -e "${YELLOW}=== Section 4: Cross-User Access ===${NC}"
run_test "User A access User B's item" "403" "GET" "/api/users/user_b/items" "$USER_A_TOKEN"
run_test "User A delete User B's item" "403" "DELETE" "/api/items/user_b_item" "$USER_A_TOKEN"

# --- Section 5: Cross-Org Access (CRITICAL) ---
echo ""
echo -e "${YELLOW}=== Section 5: Cross-Org Access ===${NC}"
run_test "Admin Org A access Org B" "403" "GET" "/api/orgs/org_b/items" "$ADMIN_TOKEN"

# --- Section 6: Injection Attacks ---
echo ""
echo -e "${YELLOW}=== Section 6: Injection Attacks ===${NC}"
run_test "Path traversal" "404" "GET" "/api/items/../../../etc/passwd" "$USER_A_TOKEN"
run_test "SQL injection" "404" "GET" "/api/items/1'%20OR%20'1'='1" "$USER_A_TOKEN"
run_test "Null byte" "404" "GET" "/api/items/test%00.txt" "$USER_A_TOKEN"

# =============================================================================
# Summary
# =============================================================================

echo ""
echo "========================================"
echo "Results"
echo "========================================"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}ALL SECURITY TESTS PASSED${NC}"
    exit 0
else
    echo -e "${RED}SECURITY VULNERABILITIES DETECTED${NC}"
    exit 1
fi
```

---

# Part VI: Operations

## 16. Ticket Workflow

### 16.1 Creating a Ticket

When starting auth integration, create a ticket folder:

```
tickets/YYYYMMDD_ab0t_auth_integration/
├── TICKET.md              # Requirements, scope, acceptance criteria
├── IMPLEMENTATION_PLAN.md # Step-by-step tasks
├── CHECKLIST.md           # Verification checklist
├── work_log.md            # Daily progress log
├── SUMMARY.md             # Status and key decisions
└── tests/
    └── test_auth_security.py
```

### 16.2 Documentation Templates

See the existing tickets for templates:
- `resource/output/tickets/20260202_ab0t_auth_integration/`
- `sandbox-platform/tickets/20260203_secure_multi_tenant_auth_refactor/`

---

## 17. File Reference

| File | Purpose |
|------|---------|
| `app/auth.py` | Auth module with AuthGuard, type aliases, verification |
| `app/config.py` | Environment variable settings |
| `app/main.py` | Lifespan and exception handler integration |
| `.permissions.json` | Permission definitions and registration |
| `register-service-permissions.sh` | Registration script |
| `credentials/{service}.json` | Admin and API key credentials |
| `tests/test_auth_security.py` | Unit tests |
| `tests/security/auth_bypass_tests.sh` | Integration tests |

---

## 18. Troubleshooting

### 18.1 Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `AuthGuard not initialized` | Missing lifespan | Add `async with auth.lifespan()` |
| `401 Unauthorized` | No/invalid token | Check token format and expiration |
| `403 Permission denied` | Missing permission | Verify user has required permission |
| `JWKS fetch failed` | Network issue | Check AB0T_AUTH_URL is reachable |

### 18.2 Debugging

```python
# Enable debug logging
auth = AuthGuard(auth_url="...", debug=True)

# In route, inspect user
@router.get("/debug")
async def debug(user: CurrentUser):
    return {
        "user_id": user.user_id,
        "org_id": user.org_id,
        "permissions": user.permissions,
        "auth_method": str(user.auth_method),
    }
```

---

# Part VII: Advanced Topics

## 19. Advanced: Permission Hierarchies

### 19.1 Wildcard Permissions

The auth service supports wildcard permissions:

- `myservice.*` - All permissions in the service
- `myservice.read.*` - All read permissions
- `myservice.admin` - Typically implies many other permissions

### 19.2 Implied Permissions

In your `.permissions.json`, you can specify that one permission implies others:

```json
{
  "id": "myservice.admin",
  "implies": ["myservice.read", "myservice.write", "myservice.delete"]
}
```

### 19.3 Checking Hierarchies

```python
# Check if user has any permission starting with pattern
def has_permission_pattern(user: AuthenticatedUser, pattern: str) -> bool:
    import fnmatch
    return any(fnmatch.fnmatch(p, pattern) for p in user.permissions)

# Usage
if has_permission_pattern(user, "myservice.admin.*"):
    # User has some admin permission
    pass
```

---

## 20. Advanced: Custom Auth Flows

### 20.1 Webhook Authentication

For webhooks from external services, you might use HMAC signatures instead of JWT:

```python
import hmac
import hashlib

def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)

@router.post("/webhooks/external")
async def handle_webhook(request: Request):
    signature = request.headers.get("X-Hub-Signature-256", "")
    body = await request.body()

    if not verify_webhook_signature(body, signature, WEBHOOK_SECRET):
        raise HTTPException(401, "Invalid signature")

    # Process webhook...
```

### 20.2 Service-to-Service Authentication

For internal service calls, use service API keys:

```python
# In calling service
SERVICE_API_KEY = os.getenv("TARGET_SERVICE_API_KEY")

async with httpx.AsyncClient() as client:
    response = await client.get(
        "http://target-service:8000/api/data",
        headers={"X-API-Key": SERVICE_API_KEY}
    )
```

---

## 21. Advanced: Performance Optimization

### 21.1 Token Caching

The AuthGuard caches validated tokens automatically. Configure cache settings:

```python
auth = AuthGuard(
    auth_url="...",
    # These are defaults, adjust as needed
    # token_cache_ttl=60,      # Cache tokens for 60 seconds
    # jwks_cache_ttl=300,      # Cache JWKS for 5 minutes
)
```

### 21.2 Lazy Permission Loading

For complex permission checks, consider lazy loading:

```python
async def get_effective_permissions(user: AuthenticatedUser) -> set:
    """Expand permission hierarchies and wildcards."""
    base = set(user.permissions)

    # Expand admin to include all sub-permissions
    if "myservice.admin" in base:
        base.update(["myservice.read", "myservice.write", "myservice.delete"])

    return base
```

---

## 22. Advanced: Audit Logging

### 22.1 Logging Auth Events

Log all authentication and authorization decisions for security audits:

```python
import structlog

logger = structlog.get_logger()

def verify_resource_access(resource, user: AuthenticatedUser) -> None:
    access_granted = False
    reason = ""

    try:
        # ... verification logic ...
        access_granted = True
        reason = "owner" or "org_admin" or "cross_tenant"
    except PermissionDeniedError as e:
        reason = str(e)
        raise
    finally:
        logger.info(
            "resource_access_check",
            user_id=user.user_id,
            org_id=user.org_id,
            resource_id=resource.id,
            resource_org=resource.org_id,
            access_granted=access_granted,
            reason=reason,
        )
```

### 22.2 Audit Trail Requirements

For compliance, log:
- Who accessed what (user_id, resource_id)
- When (timestamp)
- From where (IP address, user agent)
- What happened (action, outcome)
- Why (permission used, denial reason)

---

## 23. Advanced: Token Introspection

### 23.1 When to Introspect

Token introspection means checking with the auth service whether a token is still valid (not revoked). Use it for:

- High-value operations
- After user reports compromise
- For long-lived tokens

### 23.2 Implementation

```python
from ab0t_auth.jwt import should_introspect

async def verify_with_introspection(token: str, user: AuthenticatedUser):
    """Verify token with optional server-side check."""
    claims = user.claims

    if should_introspect(claims, introspect_threshold=300):
        # Token is close to expiry or long-lived
        # Check with auth service for revocation
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{settings.AB0T_AUTH_URL}/oauth/introspect",
                data={"token": token}
            )
            if not response.json().get("active"):
                raise TokenInvalidError("Token has been revoked")
```

---

## Summary

This guide covered everything needed to integrate ab0t-auth:

0. **Quick Start** - Essential steps for experienced engineers
1. **Prerequisites** - What you need before starting
2. **Foundation** - Understanding the security model
3. **Planning** - Identifying services and designing permissions
4. **Implementation** - Building the auth module
5. **Registration** - Registering with the auth service
6. **Verification** - Confirming your setup works
7. **Testing** - Security test suites
8. **Operations** - Managing auth in production
9. **Advanced** - Optimization and extensions

### Key Takeaways

1. **Always use two-phase verification** for resource access (Phase 1: permission, Phase 2: ownership)
2. **Never trust org_id from request parameters alone** - always verify against the actual resource
3. **Test with multiple user types** - owner, admin same-org, admin different-org, no-perms user
4. **The cross-org attack is the critical one** - Admin from Org A accessing Org B data

### Getting Help

- **API Reference**: Consult your organization's auth skill file
- **Examples**: Look at existing service implementations in your codebase
- **Issues**: Contact your platform team or auth service maintainers

---

*Guide Version: 3.1*
*Last Updated: 2026-02-04*
