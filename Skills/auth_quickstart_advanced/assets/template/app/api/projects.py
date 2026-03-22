"""Project routes — top-level resource demonstrating all major auth patterns.

AUTH PATTERNS USED:
  List         — ProjectReader + get_user_filter() to scope query
  List public  — OptionalUser for mixed public/authenticated access
  Get by ID    — ProjectReader + Phase 2 verify_project_access()
  Create       — ProjectCreator, no Phase 2 (ownership assigned at creation)
  Update       — ProjectWriter + Phase 2 (also blocked on archived projects via check callback)
  Archive      — ProjectArchiver + Phase 2 (separate permission from write)
  Reports      — ReportViewer for org-wide data
  Admin        — OrgAdmin for org-wide admin operations
"""

from dataclasses import asdict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..auth import (
    ProjectReader, ProjectCreator, ProjectWriter, ProjectArchiver,
    ReportViewer, OrgAdmin, OptionalUser,
    verify_project_access, verify_resource_access, get_user_filter,
)
from ..db import repo, Project

router = APIRouter()


# --- Request models ---

class ProjectCreate(BaseModel):
    name: str
    description: str = ""
    is_public: bool = False


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    is_public: bool | None = None


# --- Routes ---


# Pattern: List with scoped filter
# get_user_filter() returns different filters based on the user's role:
#   - Regular user: only their own projects
#   - Org admin: all projects in their org
#   - Platform admin: everything
@router.get("/")
async def list_projects(user: ProjectReader):
    filters = get_user_filter(user)
    projects = repo.list_projects(filters)
    return {"projects": [asdict(p) for p in projects]}


# Pattern: Optional auth — public content with enhanced view for logged-in users
# OptionalUser returns None for anonymous requests, AuthenticatedUser for valid tokens.
# This lets you show public projects to anyone, plus private projects to logged-in users.
@router.get("/public")
async def list_public_projects(user: OptionalUser):
    projects = repo.list_public_projects()
    result = [asdict(p) for p in projects]

    # If the user is logged in, also include their private projects
    if user:
        filters = get_user_filter(user)
        private = repo.list_projects(filters)
        for p in private:
            if not p.is_public:  # Avoid duplicates
                result.append(asdict(p))

    return {"projects": result, "authenticated": user is not None}


# Pattern: Get by ID with Phase 2 ownership check
# Always 404 before 403 — check resource exists before checking access.
# verify_project_access() allows public projects to be read by anyone.
@router.get("/{project_id}")
async def get_project(project_id: str, user: ProjectReader):
    project = repo.get_project(project_id)
    if not project:
        raise HTTPException(404, "Project not found")  # 404 first
    verify_project_access(project, user)                # Then 403 if not authorized
    return asdict(project)


# Pattern: Create — no Phase 2 needed
# Ownership is assigned at creation time (user.user_id, user.org_id),
# so there's no existing resource to verify access against.
@router.post("/", status_code=201)
async def create_project(body: ProjectCreate, user: ProjectCreator):
    project = Project(
        name=body.name,
        description=body.description,
        is_public=body.is_public,
        user_id=user.user_id,   # Set owner
        org_id=user.org_id,     # Set tenant
    )
    repo.create_project(project)
    return asdict(project)


# Pattern: Update with Phase 2 + archived check
# The ProjectWriter type alias includes is_not_archived_project check callback,
# so archived projects are rejected before we even reach the route body.
@router.patch("/{project_id}")
async def update_project(project_id: str, body: ProjectUpdate, user: ProjectWriter):
    project = repo.get_project(project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    verify_resource_access(project, user)  # Phase 2: ownership check

    updates = body.model_dump(exclude_none=True)
    updated = repo.update_project(project_id, updates)
    return asdict(updated)


# Pattern: Destructive action with separate permission
# Archive is separate from write — it's a higher-privilege operation that
# prevents all future modifications to the project.
@router.post("/{project_id}/archive", status_code=200)
async def archive_project(project_id: str, user: ProjectArchiver):
    project = repo.get_project(project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    verify_resource_access(project, user)  # Phase 2

    repo.archive_project(project_id)
    return {"archived": True, "project_id": project_id}


# Pattern: Admin-only org-wide operation
# OrgAdmin alias requires pm.admin permission. Only org admins can see
# reports across all projects in their org.
@router.get("/reports/summary")
async def org_report(user: ReportViewer):
    # org-scoped — only sees projects in user's org
    filters = {"org_id": user.org_id}
    projects = repo.list_projects(filters)
    return {
        "org_id": user.org_id,
        "total_projects": len(projects),
        "archived": sum(1 for p in projects if p.archived),
        "public": sum(1 for p in projects if p.is_public),
    }
