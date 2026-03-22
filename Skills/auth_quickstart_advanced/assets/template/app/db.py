"""Database abstraction layer.

Provides a Repository interface backed by SQLite. Swap the implementation
for Postgres, Mongo, DynamoDB, etc. — routes and auth don't change.

WHY AN ABSTRACTION: Auth logic (get_user_filter, verify_resource_access)
produces plain dicts for query filters and expects objects with .user_id
and .org_id. Keeping the DB layer behind an interface means you can change
storage without touching auth code.

TABLES:
  projects  — top-level resource, owned by a user within an org
  tasks     — nested under a project, inherits project's org
  comments  — nested under a task, supports public (anonymous) viewing
"""

import sqlite3
import uuid
from datetime import datetime, timezone
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from typing import Optional


# --- Models ---
# These are plain dataclasses, not ORM models. They work with any DB backend.
# Auth checks rely on .user_id and .org_id — keep those fields on every model.
#
# WHY BOTH user_id AND org_id:
#   - user_id identifies the owner. verify_resource_access() checks this first.
#   - org_id identifies the tenant. get_user_filter() uses this to scope queries.
#   - Regular users see only their own resources (filter by user_id + org_id)
#   - Org admins see all resources in their org (filter by org_id only)
#   - Platform admins see everything (no filter)
#   If you omit org_id, org admins can't see their team's resources.
#   If you omit user_id, you can't distinguish owners from other org members.


@dataclass
class Project:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    user_id: str = ""       # Owner — used by verify_resource_access()
    org_id: str = ""        # Tenant — used by get_user_filter()
    is_public: bool = False  # Public projects visible via optional_auth
    archived: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Task:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str = ""    # Parent — verify project access before task access
    title: str = ""
    status: str = "todo"    # todo, in_progress, done
    assignee_id: Optional[str] = None
    user_id: str = ""       # Creator
    org_id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Comment:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str = ""
    body: str = ""
    user_id: str = ""       # Author — empty string for anonymous on public projects
    org_id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# --- Repository interface ---
# Routes call these methods. The implementation below uses SQLite.
# To swap backends, reimplement this class with the same method signatures.


class Repository:
    """Pluggable data access layer. Default implementation uses SQLite."""

    def __init__(self, db_path: str = "data.db"):
        self._db_path = db_path
        self._init_tables()

    @contextmanager
    def _conn(self):
        """Yield a connection with row_factory set to sqlite3.Row."""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # Better concurrent read performance
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_tables(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    user_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    is_public INTEGER DEFAULT 0,
                    archived INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(id),
                    title TEXT NOT NULL,
                    status TEXT DEFAULT 'todo',
                    assignee_id TEXT,
                    user_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS comments (
                    id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL REFERENCES tasks(id),
                    body TEXT NOT NULL,
                    user_id TEXT DEFAULT '',
                    org_id TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                );
            """)

    # --- Helpers ---

    def _row_to_model(self, row: sqlite3.Row, model_class):
        """Convert a sqlite3.Row to a dataclass instance."""
        return model_class(**{k: row[k] for k in row.keys()})

    def _apply_filters(self, base_query: str, filters: dict) -> tuple[str, list]:
        """Append WHERE clauses from a filter dict. Used with get_user_filter() output.

        SECURITY: This is the enforcement point for multi-tenant isolation.
        Without these filters, list queries would return ALL resources across
        all orgs — a data leakage vulnerability. Every list/search route MUST
        pass get_user_filter() output through this method.

        Example: {"org_id": "abc", "user_id": "xyz"} → "WHERE org_id = ? AND user_id = ?"
        """
        if not filters:
            return base_query, []
        clauses = [f"{k} = ?" for k in filters]
        return f"{base_query} WHERE {' AND '.join(clauses)}", list(filters.values())

    # --- Projects ---

    def create_project(self, project: Project) -> Project:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO projects (id, name, description, user_id, org_id, is_public, archived, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (project.id, project.name, project.description, project.user_id,
                 project.org_id, int(project.is_public), int(project.archived), project.created_at),
            )
        return project

    def get_project(self, project_id: str) -> Optional[Project]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if not row:
            return None
        p = self._row_to_model(row, Project)
        p.is_public = bool(p.is_public)
        p.archived = bool(p.archived)
        return p

    def list_projects(self, filters: dict) -> list[Project]:
        """List projects scoped by auth filters. Pass get_user_filter() output."""
        query, params = self._apply_filters("SELECT * FROM projects", filters)
        with self._conn() as conn:
            rows = conn.execute(f"{query} ORDER BY created_at DESC", params).fetchall()
        return [self._row_to_model(r, Project) for r in rows]

    def list_public_projects(self) -> list[Project]:
        """List projects marked as public. No auth filter needed."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM projects WHERE is_public = 1 ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_model(r, Project) for r in rows]

    def update_project(self, project_id: str, updates: dict) -> Optional[Project]:
        if not updates:
            return self.get_project(project_id)
        sets = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [project_id]
        with self._conn() as conn:
            conn.execute(f"UPDATE projects SET {sets} WHERE id = ?", vals)
        return self.get_project(project_id)

    def archive_project(self, project_id: str) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE projects SET archived = 1 WHERE id = ?", (project_id,))

    # --- Tasks ---

    def create_task(self, task: Task) -> Task:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO tasks (id, project_id, title, status, assignee_id, user_id, org_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (task.id, task.project_id, task.title, task.status,
                 task.assignee_id, task.user_id, task.org_id, task.created_at),
            )
        return task

    def get_task(self, task_id: str) -> Optional[Task]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return self._row_to_model(row, Task) if row else None

    def list_tasks(self, project_id: str, filters: dict) -> list[Task]:
        """List tasks within a project, scoped by auth filters."""
        filters_with_project = {**filters, "project_id": project_id}
        query, params = self._apply_filters("SELECT * FROM tasks", filters_with_project)
        with self._conn() as conn:
            rows = conn.execute(f"{query} ORDER BY created_at DESC", params).fetchall()
        return [self._row_to_model(r, Task) for r in rows]

    def update_task(self, task_id: str, updates: dict) -> Optional[Task]:
        if not updates:
            return self.get_task(task_id)
        sets = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [task_id]
        with self._conn() as conn:
            conn.execute(f"UPDATE tasks SET {sets} WHERE id = ?", vals)
        return self.get_task(task_id)

    def delete_task(self, task_id: str) -> None:
        # Cascade: delete child comments first, then the task.
        # Auth checks (Phase 2) happen in the route BEFORE calling this.
        with self._conn() as conn:
            conn.execute("DELETE FROM comments WHERE task_id = ?", (task_id,))
            conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))

    # --- Comments ---

    def create_comment(self, comment: Comment) -> Comment:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO comments (id, task_id, body, user_id, org_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (comment.id, comment.task_id, comment.body,
                 comment.user_id, comment.org_id, comment.created_at),
            )
        return comment

    def list_comments(self, task_id: str) -> list[Comment]:
        """List all comments on a task. Auth check happens at the task/project level."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM comments WHERE task_id = ? ORDER BY created_at ASC", (task_id,)
            ).fetchall()
        return [self._row_to_model(r, Comment) for r in rows]

    def delete_comment(self, comment_id: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM comments WHERE id = ?", (comment_id,))


# Singleton instance — import this in route modules.
# Replace with a different Repository implementation to swap backends.
repo = Repository()
