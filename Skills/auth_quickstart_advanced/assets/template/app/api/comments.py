"""Comment routes — demonstrating optional_auth and moderation patterns.

Comments are nested under tasks, which are nested under projects.
Access checks cascade: project → task → comment.

AUTH PATTERNS USED:
  List         — OptionalUser: public projects show comments to anyone,
                 private projects require authentication
  Create       — Commenter: requires pm.create.comments + org membership
  Delete       — CommentModerator: require_any_permission (pm.delete.comments OR pm.admin)
"""

from dataclasses import asdict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..auth import (
    OptionalUser, Commenter, CommentModerator,
    verify_project_access, verify_resource_access,
)
from ..db import repo, Comment

router = APIRouter()


class CommentCreate(BaseModel):
    body: str


# --- Helpers ---


def _get_parent_chain_or_404(project_id: str, task_id: str, user):
    """Verify access to the full parent chain: project → task.

    For public projects, unauthenticated users (user=None) can read.
    For private projects, full auth verification is required.
    """
    project = repo.get_project(project_id)
    if not project:
        raise HTTPException(404, "Project not found")

    # For public projects, allow anonymous read access
    if project.is_public and user is None:
        pass  # Skip auth — public content
    elif user:
        verify_project_access(project, user)
    else:
        raise HTTPException(401, "Authentication required")

    task = repo.get_task(task_id)
    if not task or task.project_id != project_id:
        raise HTTPException(404, "Task not found")

    return project, task


# --- Routes ---


# Pattern: Optional auth — public comments visible to anyone, private require auth.
# OptionalUser returns None for anonymous, AuthenticatedUser for valid tokens.
# This single route handles both public and private project comments.
@router.get("/")
async def list_comments(project_id: str, task_id: str, user: OptionalUser):
    _get_parent_chain_or_404(project_id, task_id, user)
    comments = repo.list_comments(task_id)
    return {"comments": [asdict(c) for c in comments]}


# Pattern: Authenticated create on nested resource
# Commenter alias requires pm.create.comments + is_not_archived_project check.
# Comments inherit org_id from the parent project.
@router.post("/", status_code=201)
async def create_comment(
    project_id: str, task_id: str, body: CommentCreate, user: Commenter,
):
    project = repo.get_project(project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    verify_project_access(project, user)

    task = repo.get_task(task_id)
    if not task or task.project_id != project_id:
        raise HTTPException(404, "Task not found")

    comment = Comment(
        task_id=task_id,
        body=body.body,
        user_id=user.user_id,
        org_id=project.org_id,  # Inherit org from project
    )
    repo.create_comment(comment)
    return asdict(comment)


# Pattern: Moderation with require_any_permission
# CommentModerator uses require_any_permission — user needs EITHER
# pm.delete.comments (dedicated moderator) OR pm.admin (org admin).
# This avoids forcing admins to have every fine-grained permission.
@router.delete("/{comment_id}", status_code=204)
async def delete_comment(
    project_id: str, task_id: str, comment_id: str, user: CommentModerator,
):
    project = repo.get_project(project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    verify_resource_access(project, user)

    # Comment authors can delete their own; moderators can delete any
    comments = repo.list_comments(task_id)
    comment = next((c for c in comments if c.id == comment_id), None)
    if not comment:
        raise HTTPException(404, "Comment not found")

    # Allow self-delete OR moderator-delete
    if comment.user_id != user.user_id:
        verify_resource_access(comment, user)  # Phase 2 for non-owner

    repo.delete_comment(comment_id)
    return None
