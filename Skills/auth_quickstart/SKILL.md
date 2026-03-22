---
name: auth-quickstart
description: Scaffold a new FastAPI microservice from zero with ab0t-auth already integrated. Use when creating a brand new service that doesn't exist yet, bootstrapping a project from scratch, or when the user says "new service", "start from scratch", "scaffold", "quickstart", "create a new API", or "bootstrap". Generates a complete project structure with auth guard, permission scheme, type aliases, example CRUD routes, config, Dockerfile, and registration-ready .permissions.json. NOT for adding auth to an existing service (use auth_fastapi_skill for that).
---

# Auth Quickstart: Zero to Running Service

Scaffold a complete FastAPI service with ab0t-auth baked in from the start.

## When to Use This vs auth_fastapi_skill

| Situation | Use |
|-----------|-----|
| No code exists yet | **This skill** |
| Existing service needs auth added | auth_fastapi_skill |
| Need to understand permission design in depth | auth_fastapi_skill |
| Need scenario walkthroughs by industry | auth_service_ab0t |

## Scaffold Workflow

### Step 1: Gather Requirements

Ask the user for:
1. **Service name** — human-readable (e.g., "Invoice Service")
2. **Service slug** — lowercase identifier (e.g., `invoices`). Used in permissions, audience, file names.
3. **Domain resources** — the nouns (e.g., invoices, payments, customers)
4. **Actions per resource** — the verbs (e.g., read, write, create, delete, send, approve)
5. **Maintainer email** — for `.permissions.json`

If the user is vague, suggest reasonable defaults and confirm.

### Step 2: Copy and Customize Template

The template lives in `assets/template/`. Copy the entire directory to the user's target path, then replace all placeholders:

| Placeholder | Replace with |
|-------------|-------------|
| `__SERVICE_NAME__` | Human-readable name |
| `__SERVICE_SLUG__` | Lowercase slug |
| `__SERVICE_DESCRIPTION__` | One-line description |
| `__MAINTAINER_EMAIL__` | Contact email |

**Files to customize:**

1. **`.permissions.json`** — Replace starter permissions with real ones derived from the user's resources and actions. Follow the `{slug}.{action}.{resource}` format. Set `admin.implies` to include all lower permissions. Never imply `cross_tenant`.

2. **`app/auth.py`** — Replace starter type aliases (`Reader`, `Writer`, `Admin`) with domain-specific aliases matching the permissions. Example for an invoice service:
   ```python
   InvoiceReader = Annotated[AuthenticatedUser, Depends(
       require_permission(auth, "invoices.read", check=belongs_to_org))]
   InvoiceSender = Annotated[AuthenticatedUser, Depends(
       require_permission(auth, "invoices.send", check=belongs_to_org))]
   ```

3. **`app/api/items.py`** — Rename to match the primary resource (e.g., `invoices.py`). Replace the example routes with real ones using the domain-specific type aliases. Keep the same auth patterns (list with filter, get with Phase 2, create without Phase 2, delete with Phase 2, admin-only).

4. **`app/main.py`** — Update the router import and prefix to match the renamed module.

5. **`app/config.py`** — Add any service-specific settings.

### Step 3: Verify Structure

After customization, the project should have:

```
my-service/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI app with auth lifespan
│   ├── config.py         # Pydantic settings
│   ├── auth.py           # AuthGuard, type aliases, Phase 2, check callbacks
│   └── api/
│       ├── __init__.py
│       ├── health.py     # Unauthenticated health check
│       └── {resource}.py # Auth-protected CRUD routes
├── .permissions.json     # Permission definitions for registration
├── .env.example          # Environment variable reference
├── .gitignore            # Excludes credentials/, .env, etc.
├── requirements.txt      # Dependencies including ab0t-auth
└── Dockerfile            # Production container
```

### Step 4: Run Locally

```bash
cd my-service
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # Edit values

# Development with auth bypass
AB0T_AUTH_DEBUG=true AB0T_AUTH_BYPASS=true uvicorn app.main:app --reload
```

Verify:
- `GET /health` returns `{"status": "ok"}` (no auth)
- `GET /items/` returns data with bypass user (auth bypassed)
- Routes return proper 401/403 JSON when bypass is off and no token is provided

### Step 5: Guide Next Steps

After the scaffold is running, point the user to [references/next-steps.md](references/next-steps.md) for:
- Adding more permissions and type aliases
- Adding check callbacks (suspension, quota)
- Wiring up Phase 2 ownership verification with a real database
- Registering with the auth service
- Multi-tenancy setup
- Middleware for blanket auth
- Production checklist

For deep dives, reference the **auth_fastapi_skill**:
- [permissions-design.md](../auth_fastapi_skill/references/permissions-design.md) — full schema and design principles
- [route-patterns.md](../auth_fastapi_skill/references/route-patterns.md) — all 7 route protection patterns
- [implementation-details.md](../auth_fastapi_skill/references/implementation-details.md) — all 19 type aliases, check callbacks
- [registration.md](../auth_fastapi_skill/references/registration.md) — auth service registration walkthrough

## Permission Design Quick Reference

**Format:** `{slug}.{action}` or `{slug}.{action}.{resource}`

| Action | Meaning | Risk |
|--------|---------|------|
| `read` | View without side effects | low |
| `write` | Modify existing records | medium |
| `create` | Create new records | medium |
| `delete` | Permanently remove | high |
| `execute` | Run user-provided code | high |
| `admin` | Full org-level access (implies lower perms) | critical |
| `cross_tenant` | Cross-org access (NEVER implied by admin) | critical |

## Common Mistakes

1. **Forgetting to rename placeholders** — grep for `__SERVICE` after scaffolding to catch any missed replacements
2. **Skipping Phase 2** — every route with `/{id}` in the path needs `verify_resource_access()` after the DB fetch
3. **Implying `cross_tenant` from `admin`** — never do this; it must be a conscious separate grant
4. **Unscoped list queries** — always use `get_user_filter(user)` for list/search routes
5. **404 after 403** — always check resource exists (404) before checking access (403)
