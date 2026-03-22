---
name: auth-quickstart-advanced
description: Scaffold a complete, production-shaped FastAPI microservice from zero with ab0t-auth, a pluggable database layer, and full auth feature coverage. Use when creating a new service from scratch and the user wants a realistic working example — not just boilerplate. Includes a project management API with projects, tasks, and comments demonstrating every auth pattern (optional_auth, require_permission, require_any_permission, check callbacks, Phase 2 ownership, nested resource access, scoped queries, public/private routes, moderation). Also use when the user says "advanced quickstart", "full example", "complete scaffold", or "realistic starter". For a simpler template with placeholders, use auth_quickstart instead.
---

# Auth Quickstart Advanced: Complete Working Service

A fully functional project management API demonstrating every ab0t-auth feature. Copy this template and adapt it — or study it to understand auth patterns before building your own.

**Quick download:** A ready-to-use zip is available at [assets/template.zip](assets/template.zip). Unzip, install deps, and run — no placeholders to replace.

## What's Included

| Component | File | Auth Features Demonstrated |
|-----------|------|---------------------------|
| Projects | `api/projects.py` | `require_permission`, `optional_auth`, Phase 2, scoped filters, archive check callback |
| Tasks | `api/tasks.py` | Nested resource access (verify parent project), inherited org_id, cascading delete |
| Comments | `api/comments.py` | `optional_auth` (public read), `require_any_permission` (moderation), self-delete |
| Auth module | `auth.py` | 11 type aliases, 2 check callbacks, Phase 2 helpers, scoped query filters |
| Permissions | `.permissions.json` | 13 permissions, 4 roles (viewer/contributor/manager/admin), `implies`, multi-tenancy |
| Database | `db.py` | Pluggable Repository pattern with SQLite default — swap for any backend |

## Auth Feature Coverage

| Feature | Where |
|---------|-------|
| `require_permission` | ProjectReader, TaskWriter, etc. |
| `require_any_permission` | CommentModerator (delete.comments OR admin) |
| `optional_auth` | OptionalUser — public project listing, public comment reading |
| Check callbacks (single) | `belongs_to_org` on all type aliases |
| Check callbacks (multiple, mode="all") | ProjectWriter, TaskCreator — belongs_to_org + is_not_archived_project |
| Phase 2 ownership | verify_resource_access on get/update/delete routes |
| Phase 2 public variant | verify_project_access — public projects readable by anyone |
| Scoped queries | get_user_filter() on all list routes |
| Nested resource | Tasks verify parent project access; comments verify task + project |
| Separate create/write/delete perms | pm.create.projects vs pm.write.projects vs pm.archive.projects |
| Admin implies | pm.admin implies all except cross_tenant |
| Cross-tenant isolation | pm.cross_tenant, never implied |
| 4 role tiers | viewer, contributor, manager, admin |
| Archived state callback | is_not_archived_project blocks writes to archived projects |

## When to Use This vs Other Skills

| Situation | Use |
|-----------|-----|
| Want a complete, runnable example from zero | **This skill** |
| Want a minimal template with placeholders to customize | auth_quickstart |
| Adding auth to an existing service | auth_fastapi_skill |
| Need scenario walkthroughs by industry | auth_service_ab0t |

## Scaffold Workflow

### Step 1: Copy Template

Copy `assets/template/` to the user's target directory. The template is a complete, runnable FastAPI service — no placeholders to replace.

### Step 2: Adapt to User's Domain

The template uses a project management domain (projects/tasks/comments). Adapt it:

1. **Identify the user's resources** — what are their nouns? (orders, tickets, documents)
2. **Map to the template** — projects → their primary resource, tasks → secondary, comments → tertiary
3. **Rename files and routes** — `projects.py` → `orders.py`, etc.
4. **Update `.permissions.json`** — change `pm` slug, rename permissions
5. **Update `auth.py`** — rename type aliases, adjust check callbacks
6. **Update `db.py`** — rename models and repository methods
7. **Update `main.py`** — fix router imports and prefixes
8. **Update `config.py`** — change service name, audience

### Step 3: Verify Structure

```
my-service/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI app with auth lifespan + nested routers
│   ├── config.py         # Pydantic settings with DB_PATH
│   ├── auth.py           # AuthGuard, 11 type aliases, callbacks, Phase 2
│   ├── db.py             # Repository pattern — SQLite default, swap for any backend
│   └── api/
│       ├── __init__.py
│       ├── health.py     # Unauthenticated health check
│       ├── projects.py   # Top-level resource with reports
│       ├── tasks.py      # Nested under projects
│       └── comments.py   # Nested under tasks, public/private
├── .permissions.json     # 13 permissions, 4 roles, multi-tenancy config
├── .env.example
├── .gitignore
├── requirements.txt
└── Dockerfile
```

### Step 4: Run Locally

```bash
cd my-service
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Development with auth bypass
AB0T_AUTH_DEBUG=true AB0T_AUTH_BYPASS=true uvicorn app.main:app --reload
```

Verify:
- `GET /health` → `{"status": "ok"}` (no auth)
- `POST /projects` → creates project with bypass user
- `GET /projects/public` → returns public projects (no auth needed)
- `GET /projects` → returns user's projects (auth required)
- `POST /projects/{id}/tasks` → creates task (nested resource)
- Routes return 401/403 JSON when bypass is off

### Step 5: Swap Database Backend

The Repository in `db.py` is a plain class with standard method signatures. To swap to Postgres, Mongo, etc.:

1. Keep the same method signatures (`create_project`, `list_projects`, `get_project`, etc.)
2. Keep the same model dataclasses (or map to/from your ORM)
3. Keep `_apply_filters()` compatible with `get_user_filter()` output
4. Replace the `repo = Repository()` singleton at the bottom

### Step 6: Guide Next Steps

Point to [references/next-steps.md](references/next-steps.md) for:
- Registering with the auth service
- Adding middleware for blanket auth
- Production checklist

For deep dives, reference the **auth_fastapi_skill**:
- [permissions-design.md](../auth_fastapi_skill/references/permissions-design.md) — full schema and design principles
- [route-patterns.md](../auth_fastapi_skill/references/route-patterns.md) — all 7 route protection patterns
- [implementation-details.md](../auth_fastapi_skill/references/implementation-details.md) — all 19 type aliases, check callbacks
- [registration.md](../auth_fastapi_skill/references/registration.md) — auth service registration walkthrough
