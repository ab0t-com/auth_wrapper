"""Example CRUD routes demonstrating all auth patterns.

Replace 'items' with your actual domain resource (e.g., invoices, projects,
tickets). Each route shows a different auth pattern — delete or adapt as needed.

AUTH PATTERNS USED:
  Pattern 1 (list)   — Reader alias + get_user_filter() to scope query
  Pattern 2 (get)    — Reader alias + Phase 2 verify_resource_access() after DB fetch
  Pattern 3 (create) — Writer alias, no Phase 2 (ownership assigned at creation)
  Pattern 4 (delete) — Writer alias + Phase 2 verify_resource_access() after DB fetch
  Pattern 5 (admin)  — Admin alias for org-wide operations
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..auth import Authenticated, Reader, Writer, Admin, get_user_filter

router = APIRouter()


class ItemCreate(BaseModel):
    name: str
    description: str = ""


# Pattern 1: List with scoped filter
# get_user_filter() returns different filters based on the user's role:
#   - Regular user: only their own items
#   - Org admin: all items in their org
#   - Platform admin: everything (no filter)
@router.get("/")
async def list_items(user: Reader):
    filters = get_user_filter(user)
    # TODO: pass filters to your DB query, e.g.:
    #   items = await db.find({"collection": "items", **filters})
    return {"items": [], "filters_applied": filters}


# Pattern 2: Get by ID with Phase 2 ownership check
# Always 404 before 403 — check resource exists before checking access.
# This prevents leaking information about whether a resource exists.
@router.get("/{item_id}")
async def get_item(item_id: str, user: Reader):
    # TODO: uncomment when DB is wired up:
    # item = await db.get(item_id)
    # if not item:
    #     raise HTTPException(404, "Item not found")  # 404 first
    # verify_resource_access(item, user)               # Then 403 if not authorized
    # return item
    return {"item_id": item_id, "user": user.user_id}


# Pattern 3: Create — no Phase 2 needed
# Ownership is assigned at creation time (user.user_id, user.org_id),
# so there's no existing resource to verify access against.
@router.post("/", status_code=201)
async def create_item(body: ItemCreate, user: Writer):
    # TODO: save to DB, always set owner fields:
    #   item = {"name": body.name, "user_id": user.user_id, "org_id": user.org_id}
    return {"created": body.name, "owner": user.user_id, "org": user.org_id}


# Pattern 4: Delete with Phase 2 ownership check
# Same as Pattern 2 — fetch first, verify access, then delete.
@router.delete("/{item_id}", status_code=204)
async def delete_item(item_id: str, user: Writer):
    # TODO: uncomment when DB is wired up:
    # item = await db.get(item_id)
    # if not item:
    #     raise HTTPException(404, "Item not found")
    # verify_resource_access(item, user)
    # await db.delete(item_id)
    return None


# Pattern 5: Admin-only operation
# Only users with the __SERVICE_SLUG__.admin permission can call this.
# Admin implies read+write+delete (configured in .permissions.json).
@router.post("/bulk-import")
async def bulk_import(user: Admin):
    # TODO: implement bulk import logic
    return {"status": "imported", "by": user.user_id}
