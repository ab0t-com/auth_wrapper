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
# Common reasons to deny: wrong org, suspended account, over quota.


def belongs_to_org(user: AuthenticatedUser, request: Request) -> bool:
    """Verify user belongs to the org referenced in the request.

    Extracts org_id from path params or X-Org-Id header. If neither is
    present, the route doesn't have org context so we skip the check.
    """
    org_id = request.path_params.get("org_id") or request.headers.get("X-Org-Id")
    if not org_id:
        return True  # No org context in this request — skip check
    return user.org_id == org_id


# --- Type aliases ---
# These replace Depends(get_current_user) with self-documenting security.
# The permission + checks are encoded in the function signature itself.
# Customize these for your service's permission scheme.

# Authenticated — valid token required, no specific permission needed.
# Use for routes where any logged-in user should have access.
Authenticated = Annotated[AuthenticatedUser, Depends(require_auth(auth))]

# Reader — needs __SERVICE_SLUG__.read permission + org membership.
# Use for list/get routes that return data without side effects.
Reader = Annotated[
    AuthenticatedUser,
    Depends(require_permission(auth, "__SERVICE_SLUG__.read", check=belongs_to_org)),
]

# Writer — needs __SERVICE_SLUG__.write permission + org membership.
# Use for create/update/delete routes that modify data.
Writer = Annotated[
    AuthenticatedUser,
    Depends(require_permission(auth, "__SERVICE_SLUG__.write", check=belongs_to_org)),
]

# Admin — needs __SERVICE_SLUG__.admin permission + org membership.
# Admin implies read+write+delete (configured in .permissions.json).
# Use for org-wide operations like bulk import, config changes.
Admin = Annotated[
    AuthenticatedUser,
    Depends(require_permission(auth, "__SERVICE_SLUG__.admin", check=belongs_to_org)),
]


# --- Phase 2: Resource ownership verification ---
# Phase 1 (type alias above) runs BEFORE your route — it doesn't know WHICH resource.
# Phase 2 runs AFTER you fetch the resource from DB, when you know its org_id and user_id.
# Required for any route with a resource ID in the path (e.g., /items/{item_id}).
# NOT needed for: create (ownership assigned), list (scoped by get_user_filter).


def verify_resource_access(resource, user: AuthenticatedUser) -> None:
    """Verify the user can access this specific resource. Call after DB fetch.

    Checks in order: owner > org admin > platform admin.
    Raises PermissionDeniedError if none match.
    """
    if resource.user_id == user.user_id:
        return  # Owner — always allowed to access own resources
    if user.has_permission("__SERVICE_SLUG__.admin") and resource.org_id == user.org_id:
        return  # Org admin — can access any resource in their org
    if user.has_permission("__SERVICE_SLUG__.cross_tenant"):
        return  # Platform admin — can access resources across all orgs
    raise PermissionDeniedError(
        "Access denied", required_permission="__SERVICE_SLUG__.admin"
    )


def get_user_filter(user: AuthenticatedUser) -> dict:
    """Return DB query filter scoped to user's access level.

    Use this in every list/search route to prevent data leakage.
    The returned dict should be merged into your DB query conditions.
    """
    if user.has_permission("__SERVICE_SLUG__.cross_tenant"):
        return {}  # Platform admin — no filter, sees everything
    if user.has_permission("__SERVICE_SLUG__.admin"):
        return {"org_id": user.org_id}  # Org admin — sees all org resources
    return {"user_id": user.user_id, "org_id": user.org_id}  # Regular user — own only
