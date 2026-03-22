"""Centralized auth module — single source of truth for all auth config.

WHY ONE FILE: Auth config must be consistent across all routes. One file
means one import, one audit point, and one place to update when permissions
change. Never scatter AuthGuard instances across modules.

THREE LAYERS OF SECURITY:
  1. Authentication — "Who are you?" (JWT/API key validation)
  2. Authorization  — "Do you have permission?" (permission check via type alias)
  3. Ownership      — "Is this YOUR resource?" (Phase 2 verification in route body)

All three must pass. A valid user with the right permission can still be
denied if the resource belongs to someone else in a different org.

REQUEST LIFECYCLE — how a single request flows through all 3 layers:

  1. HTTP request arrives with Authorization: Bearer <jwt> or X-API-Key header
  2. Type alias (e.g., ProjectWriter) triggers require_permission()
     → ab0t-auth validates the token (authentication)
     → ab0t-auth checks the user has "pm.write.projects" (authorization)
     → Check callbacks run: belongs_to_org() + is_not_archived_project()
     → If all pass, route receives an AuthenticatedUser object
  3. Route body fetches resource from DB
  4. verify_resource_access(resource, user) checks ownership (Phase 2)
  5. Request proceeds or gets 401/403 JSON error

HOW .permissions.json CONNECTS TO THIS CODE:
  - .permissions.json defines which permissions EXIST and their metadata
  - This file defines which permissions routes CHECK via type aliases
  - They must match: if auth.py checks "pm.write.projects", it must be
    defined in .permissions.json, or the auth service won't recognize it
  - The registration script reads .permissions.json and tells the auth
    service about your permissions. Re-run it when you add new ones.

MULTI-TENANCY — WHY org_id MATTERS:
  Every resource has both user_id (owner) and org_id (tenant).
  - user_id alone isn't enough: org admins need to see all org resources
  - org_id alone isn't enough: regular users shouldn't see other users'
    resources within the same org
  - Together they enable 3 tiers: own resources → org resources → all resources
  - Without org_id on models, get_user_filter() can't scope queries,
    and verify_resource_access() can't check org admin access

PERMISSION SCHEME (see .permissions.json for full definitions):
  pm.read.projects          — view projects
  pm.create.projects        — create new projects
  pm.write.projects         — update project settings
  pm.archive.projects       — archive/soft-delete projects
  pm.read.tasks             — view tasks
  pm.create.tasks           — create tasks in a project
  pm.write.tasks            — update/assign tasks
  pm.delete.tasks           — permanently remove tasks
  pm.create.comments        — post comments on tasks
  pm.delete.comments        — remove comments (moderation)
  pm.read.reports           — view org-wide reports
  pm.admin                  — full org-level access (implies all above)
  pm.cross_tenant           — cross-org access (NEVER implied by admin)
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

from .config import settings

# --- Guard ---
# Single AuthGuard instance shared by all routes. Created once at import time.

auth = AuthGuard(
    auth_url=settings.AB0T_AUTH_URL,
    audience=settings.AB0T_AUTH_AUDIENCE,
    debug=settings.AB0T_AUTH_DEBUG,
    permission_check_mode=settings.AB0T_AUTH_PERMISSION_CHECK_MODE,
)

# --- Check callbacks ---
# Functions (user, request) -> bool that run AFTER permission check, BEFORE route handler.
# They answer: "Even with the right permission, should this user be allowed right now?"


def belongs_to_org(user: AuthenticatedUser, request: Request) -> bool:
    """Verify user belongs to the org referenced in the request.

    Extracts org_id from path params or X-Org-Id header. If neither is
    present, the route doesn't have org context so we skip the check.
    """
    org_id = request.path_params.get("org_id") or request.headers.get("X-Org-Id")
    if not org_id:
        return True  # No org context in this request — skip check
    return user.org_id == org_id


def is_not_archived_project(user: AuthenticatedUser, request: Request) -> bool:
    """Prevent modifications to archived projects.

    Only applies to routes with project_id in the path. Import here to avoid
    circular imports — check callbacks run at request time, not import time.
    """
    from .db import repo
    project_id = request.path_params.get("project_id")
    if not project_id:
        return True
    project = repo.get_project(project_id)
    if not project:
        return True  # Let the route handler return 404
    return not project.archived


# --- Type aliases ---
# These replace Depends(get_current_user) with self-documenting security.
# The permission + checks are encoded in the function signature itself.

# -- General --

# Authenticated — valid token, no specific permission. Use for profile, settings.
Authenticated = Annotated[AuthenticatedUser, Depends(require_auth(auth))]

# OptionalUser — returns None for anonymous requests. Use for public endpoints
# that show extra data to logged-in users.
OptionalUser = Annotated[
    AuthenticatedUser | None,
    Depends(optional_auth(auth)),
]

# -- Projects --

# Can view projects within their org
ProjectReader = Annotated[
    AuthenticatedUser,
    Depends(require_permission(auth, "pm.read.projects", check=belongs_to_org)),
]

# Can create new projects. Separate from write — creating incurs resource cost.
ProjectCreator = Annotated[
    AuthenticatedUser,
    Depends(require_permission(auth, "pm.create.projects", check=belongs_to_org)),
]

# Can update project settings (name, description, visibility).
# is_not_archived_project prevents edits to archived projects.
ProjectWriter = Annotated[
    AuthenticatedUser,
    Depends(require_permission(
        auth, "pm.write.projects",
        checks=[belongs_to_org, is_not_archived_project],
        check_mode="all",
    )),
]

# Can archive projects (soft delete). High-privilege, separate from write.
ProjectArchiver = Annotated[
    AuthenticatedUser,
    Depends(require_permission(auth, "pm.archive.projects", check=belongs_to_org)),
]

# -- Tasks --

# Can view tasks within a project
TaskReader = Annotated[
    AuthenticatedUser,
    Depends(require_permission(auth, "pm.read.tasks", check=belongs_to_org)),
]

# Can create tasks in a project. Checks project isn't archived.
TaskCreator = Annotated[
    AuthenticatedUser,
    Depends(require_permission(
        auth, "pm.create.tasks",
        checks=[belongs_to_org, is_not_archived_project],
        check_mode="all",
    )),
]

# Can update task status, title, assignee. Also checks project isn't archived.
TaskWriter = Annotated[
    AuthenticatedUser,
    Depends(require_permission(
        auth, "pm.write.tasks",
        checks=[belongs_to_org, is_not_archived_project],
        check_mode="all",
    )),
]

# Can permanently delete tasks. Separate from write — deletion is irreversible.
TaskDeleter = Annotated[
    AuthenticatedUser,
    Depends(require_permission(auth, "pm.delete.tasks", check=belongs_to_org)),
]

# -- Comments --

# Can post comments on tasks. Check project isn't archived.
Commenter = Annotated[
    AuthenticatedUser,
    Depends(require_permission(
        auth, "pm.create.comments",
        checks=[belongs_to_org, is_not_archived_project],
        check_mode="all",
    )),
]

# Can delete any comment (moderation). Org admin or dedicated moderator.
# require_any_permission — user needs EITHER pm.delete.comments OR pm.admin.
CommentModerator = Annotated[
    AuthenticatedUser,
    Depends(require_any_permission(
        auth, "pm.delete.comments", "pm.admin",
        check=belongs_to_org,
    )),
]

# -- Reports & Admin --

# Can view org-wide reports (burndown, velocity, etc.)
ReportViewer = Annotated[
    AuthenticatedUser,
    Depends(require_permission(auth, "pm.read.reports", check=belongs_to_org)),
]

# Full org-level admin. Implies all other permissions except cross_tenant.
OrgAdmin = Annotated[
    AuthenticatedUser,
    Depends(require_permission(auth, "pm.admin", check=belongs_to_org)),
]


# --- Phase 2: Resource ownership verification ---
# Phase 1 (type alias above) runs BEFORE your route — it doesn't know WHICH resource.
# Phase 2 runs AFTER you fetch the resource from DB, when you know its org_id and user_id.
# Required for any route with a resource ID in the path (e.g., /projects/{id}).
# NOT needed for: create (ownership assigned), list (scoped by get_user_filter).


def verify_resource_access(resource, user: AuthenticatedUser) -> None:
    """Verify the user can access this specific resource. Call after DB fetch.

    Checks in order: owner > org admin > platform admin.
    Raises PermissionDeniedError if none match.
    """
    if resource.user_id == user.user_id:
        return  # Owner — always allowed to access own resources
    if user.has_permission("pm.admin") and resource.org_id == user.org_id:
        return  # Org admin — can access any resource in their org
    if user.has_permission("pm.cross_tenant"):
        return  # Platform admin — can access resources across all orgs
    raise PermissionDeniedError(
        "Access denied", required_permission="pm.admin"
    )


def verify_project_access(project, user: AuthenticatedUser) -> None:
    """Verify access to a project. Public projects are readable by anyone."""
    if project.is_public:
        return  # Public project — anyone can read
    verify_resource_access(project, user)


def get_user_filter(user: AuthenticatedUser) -> dict:
    """Return DB query filter scoped to user's access level.

    Use this in every list/search route to prevent data leakage.
    The returned dict should be passed to Repository.list_*() methods.
    """
    if user.has_permission("pm.cross_tenant"):
        return {}  # Platform admin — no filter, sees everything
    if user.has_permission("pm.admin"):
        return {"org_id": user.org_id}  # Org admin — sees all org resources
    return {"user_id": user.user_id, "org_id": user.org_id}  # Regular user — own only
