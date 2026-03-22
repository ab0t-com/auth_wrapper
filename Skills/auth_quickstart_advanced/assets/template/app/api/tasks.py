"""Task routes — nested resource demonstrating parent access verification.

Tasks live under projects. Before accessing a task, verify the user can
access the parent project. This is the "nested resource" auth pattern.

AUTH PATTERNS USED:
  List         — TaskReader + parent project access + get_user_filter()
  Get by ID    — TaskReader + parent project access + Phase 2
  Create       — TaskCreator + parent project access (also blocked on archived via callback)
  Update       — TaskWriter + parent project access + Phase 2
  Delete       — TaskDeleter + parent project access + Phase 2
"""

from dataclasses import asdict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..auth import (
    TaskReader, TaskCreator, TaskWriter, TaskDeleter,
    verify_project_access, verify_resource_access, get_user_filter,
)
from ..db import repo, Task

router = APIRouter()


# --- Request models ---

class TaskCreate(BaseModel):
    title: str


class TaskUpdate(BaseModel):
    title: str | None = None
    status: str | None = None       # todo, in_progress, done
    assignee_id: str | None = None


# --- Helpers ---


def _get_project_or_404(project_id: str, user):
    """Fetch project and verify access. Reused across all task routes.

    WHY: Tasks are nested under projects. A user who can't access the
    parent project should never see its tasks, regardless of task-level
    permissions. Always verify parent access first.
    """
    project = repo.get_project(project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    verify_project_access(project, user)
    return project


# --- Routes ---


# Pattern: List nested resource with parent access check + scoped filter
@router.get("/")
async def list_tasks(project_id: str, user: TaskReader):
    _get_project_or_404(project_id, user)  # Verify parent project access first

    filters = get_user_filter(user)
    tasks = repo.list_tasks(project_id, filters)
    return {"tasks": [asdict(t) for t in tasks]}


# Pattern: Get nested resource by ID with parent check + Phase 2
@router.get("/{task_id}")
async def get_task(project_id: str, task_id: str, user: TaskReader):
    _get_project_or_404(project_id, user)  # Parent access

    task = repo.get_task(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    verify_resource_access(task, user)  # Phase 2: task ownership
    return asdict(task)


# Pattern: Create nested resource — ownership assigned, project access verified
# The TaskCreator alias includes is_not_archived_project check callback,
# so tasks can't be created in archived projects.
@router.post("/", status_code=201)
async def create_task(project_id: str, body: TaskCreate, user: TaskCreator):
    project = _get_project_or_404(project_id, user)

    task = Task(
        project_id=project_id,
        title=body.title,
        user_id=user.user_id,       # Task creator
        org_id=project.org_id,       # Inherit org from parent project
    )
    repo.create_task(task)
    return asdict(task)


# Pattern: Update nested resource with parent check + Phase 2
# TaskWriter also checks project isn't archived via callback.
@router.patch("/{task_id}")
async def update_task(project_id: str, task_id: str, body: TaskUpdate, user: TaskWriter):
    _get_project_or_404(project_id, user)

    task = repo.get_task(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    verify_resource_access(task, user)  # Phase 2

    updates = body.model_dump(exclude_none=True)
    updated = repo.update_task(task_id, updates)
    return asdict(updated)


# Pattern: Delete nested resource — separate permission, Phase 2
# TaskDeleter requires pm.delete.tasks, which is separate from pm.write.tasks.
# Delete is irreversible, so it has its own permission.
@router.delete("/{task_id}", status_code=204)
async def delete_task(project_id: str, task_id: str, user: TaskDeleter):
    _get_project_or_404(project_id, user)

    task = repo.get_task(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    verify_resource_access(task, user)  # Phase 2

    repo.delete_task(task_id)  # Also deletes child comments (cascade)
    return None
