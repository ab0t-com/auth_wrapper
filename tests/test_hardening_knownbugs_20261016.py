"""Tests written 2026-10-16 that FAIL on ab0t-auth 0.1.4 because they expose a defect.

They were marked xfail(strict=True) while the defects existed. Fixed in 0.1.5 (P-1, P-2, P-3, T-1): the markers are
removed and every test here is now a regression gate that always runs. RED on 0.1.4 (observed 2026-10-16 with
--runxfail, all 5 FAIL); GREEN on 0.1.5.

Ticket: tickets/20261016_test_hardening_findings/TICKET.md (gitignored ticket area of this repo).
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import respx

from ab0t_auth import permissions as perms_mod
from ab0t_auth.cache import PermissionCache, resolve_cache_ttls
from ab0t_auth.core import AuthConfig, AuthenticatedUser, AuthMethod

AUTH_URL = "https://auth.example"
PERM_URL = f"{AUTH_URL}/permissions/check"
TICKET = "tickets/20261016_test_hardening_findings/TICKET.md"


def _pdp(decide):
    """A /permissions/check double that decides on the full request body."""

    def answer(req):
        body = json.loads(req.content)
        return httpx.Response(200, json={"allowed": bool(decide(body))})

    return answer


def _check(cache, **kw):
    cfg = AuthConfig(auth_url=AUTH_URL)
    user = AuthenticatedUser(user_id="u1", org_id="o1", auth_method=AuthMethod.JWT)

    async def run():
        async with httpx.AsyncClient() as client:
            return await perms_mod.verify_permission(client, cfg, "Bearer t", user, cache=cache, **kw)

    return asyncio.run(run())


# P-1 (fixed 0.1.5): resource_type is part of the permission cache key — a cached allow for one resource type is never
# served for another.
def test_permission_cache_key_includes_resource_type():
    cache = PermissionCache()
    with respx.mock:
        route = respx.post(PERM_URL).mock(side_effect=_pdp(lambda b: b.get("resource_type") == "doc"))
        a = _check(cache, permission="x.read", resource_id="42", resource_type="doc")
        b = _check(cache, permission="x.read", resource_id="42", resource_type="invoice")
    assert a.allowed is True
    assert route.call_count == 2, "the second, different question was answered from the cache"
    assert b.allowed is False, "the 'doc' allow was served for resource_type='invoice'"


# P-2 (fixed 0.1.5): the permission cache key is a fixed-length tuple, so colon permissions (the library's own examples
# use 'users:delete') never collide with permission + resource.
def test_permission_cache_key_is_injective_for_colon_permissions():
    cache = PermissionCache()
    with respx.mock:
        route = respx.post(PERM_URL).mock(
            side_effect=_pdp(lambda b: b["permission"] == "docs:read" and b.get("resource_id") == "x")
        )
        a = _check(cache, permission="docs:read", resource_id="x")  # allowed
        b = _check(cache, permission="docs:read:x")  # a different permission, no resource: denied by the PDP
    assert a.allowed is True
    assert route.call_count == 2, "permission 'docs:read:x' was answered from the cache of 'docs:read' on 'x'"
    assert b.allowed is False


# T-1 (fixed 0.1.5): MIGRATION.md A2 documents a 0–300 range for the AuthConfig fields; a value set in code outside it
# is no longer honoured — it is CLAMPED to 300 with a warning (lead decision 2026-10-16: a patch release must not stop a
# client's service from starting; a later minor release may refuse it, as the env var already does).
@pytest.mark.parametrize("field,attr", [("permission_cache_ttl", "permission"), ("api_key_cache_ttl", "api_key")])
def test_code_set_ttl_out_of_documented_range_is_not_honoured(field, attr, caplog):
    with caplog.at_level("WARNING", logger="ab0t_auth.cache"):
        ttls = resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL, **{field: 86_400}))
    assert getattr(ttls, attr) == 300, f"a day-long TTL was not clamped to 300: {ttls!r}"
    assert any(field in r.getMessage() and "300" in r.getMessage() for r in caplog.records), caplog.text


# P-3 (fixed 0.1.5): authentication accepts a lower-case 'bearer' scheme (RFC 7235), and the server-mode permission
# check now forwards it as 'Bearer <token>' (was 'Bearer bearer <token>', which the auth service rejected).
def test_server_mode_permission_check_forwards_lowercase_bearer_correctly():
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from ab0t_auth.dependencies import require_permission
    from ab0t_auth.guard import AuthGuard

    guard = AuthGuard(config=AuthConfig(auth_url=AUTH_URL, org_id="o1", permission_check_mode="server"))
    guard._initialized = True
    user = AuthenticatedUser(user_id="u1", org_id="o1", auth_method=AuthMethod.JWT)

    async def auth(authorization, api_key, **kwargs):  # the token itself is valid
        return user

    guard.authenticate_or_raise = auth  # type: ignore[method-assign]
    seen = []

    def answer(req):
        seen.append(req.headers.get("Authorization"))
        ok = req.headers.get("Authorization") == "Bearer tok"
        return httpx.Response(200 if ok else 401, json={"allowed": True} if ok else {"detail": "Invalid token"})

    app = FastAPI()

    @app.get("/r")
    async def r(u: AuthenticatedUser = Depends(require_permission(guard, "x.read"))):
        return {"ok": True}

    with respx.mock:
        respx.post(PERM_URL).mock(side_effect=answer)
        guard._http_client = httpx.AsyncClient()
        client = TestClient(app, raise_server_exceptions=False)
        assert client.get("/r", headers={"Authorization": "Bearer tok"}).status_code == 200
        guard.clear_caches()
        resp = client.get("/r", headers={"Authorization": "bearer tok"})
    assert seen[-1] == "Bearer tok", f"forwarded Authorization header: {seen[-1]!r}"
    assert resp.status_code == 200
