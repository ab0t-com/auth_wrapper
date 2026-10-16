"""Regression tests for the 0.1.5 fixes of the 2026-10-16 test-hardening findings (P-1, P-2, P-3, T-1).

The minimal reproductions live in test_hardening_knownbugs_20261016.py (RED on 0.1.4 with --runxfail, observed
2026-10-16). This file covers the rest of each fix's surface, so a partial fix cannot pass:

    P-1  resource_type is part of the permission-cache key            TestResourceTypeInKey
         (also through verify_any_permission / verify_all_permissions, and for denials)
    P-2  the key is injective (fixed-length tuple, no ':'-join)       TestKeyInjective
         invalidate_user() matches the user id exactly
    P-3  a case-insensitive 'Bearer' scheme is forwarded canonically  TestBearerSchemeForwarded
         on all three client call sites; key credential == forwarded credential
    T-1  a TTL set in code outside 0..300 is refused like an env one  TestCodeTtlRange
         (every field, every construction path, bounds inclusive)

Ticket: tickets/20261016_test_hardening_findings/TICKET.md (gitignored ticket area of this repo).
"""

from __future__ import annotations

import asyncio
import itertools
import json
import random

import httpx
import pytest
import respx

from ab0t_auth import permissions as perms_mod
from ab0t_auth.cache import (
    PermissionCache,
    bearer_credential,
    create_permission_cache_key,
    permission_credential_fingerprint,
    resolve_cache_ttls,
)
from ab0t_auth.client import check_permission, get_user_permissions, validate_token
from ab0t_auth.config import create_config
from ab0t_auth.core import AuthConfig, AuthenticatedUser, AuthMethod, PermissionCheckRequest

AUTH_URL = "https://auth.example"
PERM_URL = f"{AUTH_URL}/permissions/check"

TTL_FIELDS = {
    "permission_cache_ttl": "AB0T_AUTH_PERMISSION_CACHE_TTL",
    "permission_cache_negative_ttl": "AB0T_AUTH_PERMISSION_CACHE_NEGATIVE_TTL",
    "api_key_cache_ttl": "AB0T_AUTH_API_KEY_CACHE_TTL",
    "api_key_cache_negative_ttl": "AB0T_AUTH_API_KEY_CACHE_NEGATIVE_TTL",
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for env in TTL_FIELDS.values():
        monkeypatch.delenv(env, raising=False)


def _user(user_id="u1", org="o1"):
    return AuthenticatedUser(user_id=user_id, org_id=org, auth_method=AuthMethod.JWT)


def _pdp(decide, seen=None):
    """A /permissions/check double that decides on the full request body (and records it)."""

    def answer(req):
        body = json.loads(req.content)
        if seen is not None:
            seen.append(body)
        return httpx.Response(200, json={"allowed": bool(decide(body))})

    return answer


def _run(coro_fn):
    async def run():
        async with httpx.AsyncClient() as client:
            return await coro_fn(client)

    return asyncio.run(run())


def _verify(cache, permission, **kw):
    cfg = AuthConfig(auth_url=AUTH_URL)
    return _run(lambda c: perms_mod.verify_permission(c, cfg, "Bearer t", _user(), permission, cache=cache, **kw))


# =============================================================================
# P-1 — resource_type is part of the key (and of every entry point)
# =============================================================================


class TestResourceTypeInKey:
    def test_denial_for_one_type_is_not_served_for_another(self):
        cache = PermissionCache()
        with respx.mock:
            route = respx.post(PERM_URL).mock(side_effect=_pdp(lambda b: b.get("resource_type") == "doc"))
            assert _verify(cache, "x.read", resource_id="42", resource_type="invoice").allowed is False
            assert _verify(cache, "x.read", resource_id="42", resource_type="doc").allowed is True
        assert route.call_count == 2, "the cached 'invoice' denial answered the 'doc' question"

    def test_same_question_still_hits_the_cache(self):
        # non-vacuity: the fix must not simply turn the cache off
        cache = PermissionCache()
        with respx.mock:
            route = respx.post(PERM_URL).mock(side_effect=_pdp(lambda b: True))
            for _ in range(4):
                assert _verify(cache, "x.read", resource_id="42", resource_type="doc").allowed
        assert route.call_count == 1
        assert cache.hits == 3

    def test_typed_and_untyped_questions_are_separate(self):
        cache = PermissionCache()
        with respx.mock:
            route = respx.post(PERM_URL).mock(side_effect=_pdp(lambda b: "resource_type" not in b))
            assert _verify(cache, "x.read", resource_id="42").allowed is True
            assert _verify(cache, "x.read", resource_id="42", resource_type="doc").allowed is False
        assert route.call_count == 2

    def test_empty_type_and_id_mean_not_sent(self):
        # client.check_permission sends neither a falsy resource_type nor a falsy resource_id, so the key treats
        # "" like None — the same question shares one entry
        assert create_permission_cache_key("u", "p", "", "fp", "o", "") == create_permission_cache_key(
            "u", "p", None, "fp", "o", None
        )

    @pytest.mark.parametrize("fn_name", ["verify_any_permission", "verify_all_permissions"])
    def test_multi_permission_entry_points_send_and_key_on_resource_type(self, fn_name):
        fn = getattr(perms_mod, fn_name)
        cfg = AuthConfig(auth_url=AUTH_URL)
        cache = PermissionCache()
        seen: list[dict] = []
        with respx.mock:
            route = respx.post(PERM_URL).mock(
                side_effect=_pdp(lambda b: b.get("resource_type") == "doc", seen)
            )
            a = _run(lambda c: fn(c, cfg, "Bearer t", _user(), "x.read", resource_id="42", resource_type="doc",
                                   cache=cache))
            b = _run(lambda c: fn(c, cfg, "Bearer t", _user(), "x.read", resource_id="42", resource_type="invoice",
                                   cache=cache))
        assert a.allowed is True and b.allowed is False
        assert route.call_count == 2
        assert [s.get("resource_type") for s in seen] == ["doc", "invoice"], "resource_type was not sent"


# =============================================================================
# P-2 — the key is injective; invalidate_user is exact
# =============================================================================


class TestKeyInjective:
    @pytest.mark.parametrize(
        "a,b",
        [
            # (permission, resource_id) pairs that collided under the 0.1.4 ':'-join
            (("docs:read", "x", None), ("docs:read:x", None, None)),
            (("a", "b:c", None), ("a:b", "c", None)),
            (("p", "x", "t"), ("p", "t:x", None)),
            (("p", None, "doc"), ("p", "doc", None)),
        ],
    )
    def test_former_collisions_are_distinct(self, a, b):
        ka = create_permission_cache_key("u", a[0], a[1], "fp", "o", a[2])
        kb = create_permission_cache_key("u", b[0], b[1], "fp", "o", b[2])
        assert ka != kb

    def test_user_org_and_credential_slots_cannot_bleed(self):
        # user "u:cred=fp" with no credential vs user "u" with credential "fp" — and similar shapes
        keys = {
            create_permission_cache_key("u:cred=fp", "p", None),
            create_permission_cache_key("u", "p", None, "fp"),
            create_permission_cache_key("u", "p", None, "fp", ""),
            create_permission_cache_key("u", "org=o:p", None, "fp"),
            create_permission_cache_key("u", "p", None, "fp", "o"),
        }
        # ("u", "fp") with org None and org "" are the SAME question (org normalised to ""), so 4 distinct keys
        assert len(keys) == 4

    def test_property_random_questions_never_share_a_key(self):
        rnd = random.Random(20261016)
        alphabet = [":", "", "a", "b", "cred=", "org=", "=", "x:y", " ", "\x00"]

        def part():
            return "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 3)))

        def opt():
            v = part()
            return v or None  # falsy is normalised to None (not sent), so draw only canonical values

        seen: dict = {}
        questions = set()
        for _ in range(30000):
            q = (part(), part(), opt(), part(), opt(), opt())  # user, permission, resource_id, cred, org, type
            questions.add(q)
            key = create_permission_cache_key(q[0], q[1], q[2], q[3], q[4], q[5])
            canon = (q[0], q[1], q[2], q[3], q[4] or "", q[5])
            prev = seen.setdefault(key, canon)
            assert prev == canon, f"two different questions share key {key!r}: {prev!r} vs {canon!r}"
        assert len(questions) > 10000, "too few distinct questions drawn — the property would be vacuous"

    def test_invalidate_user_is_exact_match(self):
        cache = PermissionCache()
        cache.set("a", "p", True, credential="fp", org_id="o")
        cache.set("a", "q", True, "r1", credential="fp2", org_id="o2", resource_type="doc")
        cache.set("a:b", "p", True, credential="fp", org_id="o")
        cache.set("ab", "p", True, credential="fp", org_id="o")
        assert cache.invalidate_user("a") == 2
        assert cache.get("a:b", "p", credential="fp", org_id="o") is True, "another user's entry was dropped"
        assert cache.get("ab", "p", credential="fp", org_id="o") is True
        assert cache.get("a", "p", credential="fp", org_id="o") is None

    def test_legacy_positional_set_and_keyword_get_still_meet(self):
        # The pre-0.1.5 call shape (positional resource_id, no resource_type) keeps working: consumers seed the cache
        # this way in their tests (e.g. audit test_api_key_decided_on_own_scope_20260926).
        cache = PermissionCache()
        fp = permission_credential_fingerprint("Bearer t")
        cache.set("u1", "x.read", True, None, credential=fp, org_id="o1")
        assert cache.get("u1", "x.read", None, credential=fp, org_id="o1") is True
        assert _verify(cache, "x.read").allowed is True  # served from that entry, no HTTP double needed


# =============================================================================
# P-3 — case-insensitive 'Bearer' scheme forwarded canonically, everywhere
# =============================================================================

SCHEME_VARIANTS = ["Bearer tok", "bearer tok", "BEARER tok", "BeArEr tok", "Bearer   tok", " bearer tok ", "tok"]


class _Recorder:
    def __init__(self, json_body):
        self.headers: list[str] = []
        self.json_body = json_body

    def __call__(self, req):
        self.headers.append(req.headers.get("Authorization"))
        return httpx.Response(200, json=self.json_body)


class TestBearerSchemeForwarded:
    @pytest.mark.parametrize("value", SCHEME_VARIANTS)
    def test_check_permission(self, value):
        rec = _Recorder({"allowed": True})
        with respx.mock:
            respx.post(PERM_URL).mock(side_effect=rec)
            r = _run(lambda c: check_permission(c, AuthConfig(auth_url=AUTH_URL), value,
                                                PermissionCheckRequest(user_id="u", permission="p")))
        assert r.allowed is True
        assert rec.headers == ["Bearer tok"]

    @pytest.mark.parametrize("value", SCHEME_VARIANTS)
    def test_validate_token(self, value):
        rec = _Recorder({"valid": True, "user_id": "u"})
        with respx.mock:
            respx.post(f"{AUTH_URL}/auth/validate").mock(side_effect=rec)
            _run(lambda c: validate_token(c, AuthConfig(auth_url=AUTH_URL), value))
        assert rec.headers == ["Bearer tok"]

    @pytest.mark.parametrize("value", SCHEME_VARIANTS)
    def test_get_user_permissions(self, value):
        rec = _Recorder({"permissions": ["p"]})
        with respx.mock:
            respx.get(f"{AUTH_URL}/permissions/user/u").mock(side_effect=rec)
            _run(lambda c: get_user_permissions(c, AuthConfig(auth_url=AUTH_URL), value, "u"))
        assert rec.headers == ["Bearer tok"]

    def test_key_credential_is_the_forwarded_credential(self):
        # Same fingerprint <=> same forwarded Authorization value, over every variant pair: the cache can never answer
        # one credential with another's entry because of a header-normalisation mismatch.
        values = SCHEME_VARIANTS + ["Bearer other", "bearer other", "Bearer", "bearer", "Bearer  ", "x y"]
        for a, b in itertools.product(values, repeat=2):
            same_key = permission_credential_fingerprint(a) == permission_credential_fingerprint(b)
            same_sent = bearer_credential(a) == bearer_credential(b)
            assert same_key == same_sent, (a, b)

    def test_whitespace_bearer_falls_back_to_the_api_key_like_the_fingerprint(self):
        # The fingerprint of (token="   ", api_key=K) is K's; the request must therefore be asked with K too.
        rec = _Recorder({"allowed": True})
        with respx.mock:
            respx.post(PERM_URL).mock(side_effect=rec)
            _run(lambda c: check_permission(c, AuthConfig(auth_url=AUTH_URL), "   ",
                                            PermissionCheckRequest(user_id="u", permission="p"), api_key="ab0t_sk_k"))
        assert rec.headers == ["Bearer ab0t_sk_k"]
        assert permission_credential_fingerprint("   ", "ab0t_sk_k") == permission_credential_fingerprint("", "ab0t_sk_k")

    @pytest.mark.parametrize("dep_name", ["require_any_permission", "require_all_permissions"])
    def test_server_mode_dependencies_accept_lowercase_bearer_on_a_cold_cache(self, dep_name):
        from fastapi import Depends, FastAPI
        from fastapi.testclient import TestClient

        from ab0t_auth import dependencies as deps
        from ab0t_auth.guard import AuthGuard

        guard = AuthGuard(config=AuthConfig(auth_url=AUTH_URL, org_id="o1", permission_check_mode="server"))
        guard._initialized = True

        async def auth(authorization, api_key, **kwargs):  # the token itself is valid
            return _user()

        guard.authenticate_or_raise = auth  # type: ignore[method-assign]
        seen: list[str] = []

        def answer(req):
            seen.append(req.headers.get("Authorization"))
            ok = req.headers.get("Authorization") == "Bearer tok"
            return httpx.Response(200 if ok else 401, json={"allowed": True} if ok else {"detail": "Invalid token"})

        app = FastAPI()
        dep = getattr(deps, dep_name)(guard, "x.read", "x.list")

        @app.get("/r")
        async def r(u: AuthenticatedUser = Depends(dep)):
            return {"ok": True}

        with respx.mock:
            respx.post(PERM_URL).mock(side_effect=answer)
            guard._http_client = httpx.AsyncClient()
            resp = TestClient(app, raise_server_exceptions=False).get("/r", headers={"Authorization": "bearer tok"})
        assert seen and all(h == "Bearer tok" for h in seen), seen
        assert resp.status_code == 200


# =============================================================================
# T-1 — a TTL set in code outside 0..300 is not honoured: CLAMPED into range with a warning naming the field, on every
# construction path (lead decision 2026-10-16: a patch release must not stop a client's service from starting; the env
# var keeps refusing, as it did before; a later minor release may refuse code values too)
# =============================================================================

TTL_ATTR = {"permission_cache_ttl": "permission", "permission_cache_negative_ttl": "permission_negative",
            "api_key_cache_ttl": "api_key", "api_key_cache_negative_ttl": "api_key_negative"}


class TestCodeTtlRange:
    @pytest.mark.parametrize("field", list(TTL_FIELDS))
    @pytest.mark.parametrize("bad,want", [(-1, 0), (-300, 0), (301, 300), (86_400, 300)])
    def test_out_of_range_is_clamped_with_a_warning_naming_the_field(self, field, bad, want, caplog):
        with caplog.at_level("WARNING", logger="ab0t_auth.cache"):
            ttls = resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL, **{field: bad}))
        # a negative-result TTL is also capped at its positive TTL by design (_clamp_negative_ttl), so "≤ the clamp"
        got = getattr(ttls, TTL_ATTR[field])
        assert (got == 0) if want == 0 else (0 <= got <= want), f"{field}={bad} → {ttls!r}, want ≤ {want}"
        assert any(field in r.getMessage() for r in caplog.records), f"no warning naming {field}: {caplog.text!r}"

    @pytest.mark.parametrize("field", list(TTL_FIELDS))
    @pytest.mark.parametrize("ok", [0, 1, 300])
    def test_bounds_are_inclusive(self, field, ok):
        resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL, **{field: ok}))

    @pytest.mark.parametrize("field", list(TTL_FIELDS))
    def test_non_integer_raises_naming_the_field(self, field):
        with pytest.raises(ValueError) as ei:
            resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL, **{field: "abc"}))  # type: ignore[arg-type]
        assert field in str(ei.value)

    @pytest.mark.parametrize("field", list(TTL_FIELDS))
    def test_every_construction_path_starts_and_warns(self, field, caplog):
        # the point of clamping: a client that set 86400 in code in 0.1.4 still STARTS on 0.1.5 (and is told why)
        from flask import Flask

        from ab0t_auth.flask import Ab0tAuth
        from ab0t_auth.guard import AuthGuard

        with caplog.at_level("WARNING", logger="ab0t_auth.cache"):
            AuthGuard(config=AuthConfig(auth_url=AUTH_URL, **{field: 86_400}))
            AuthGuard(config=create_config(AUTH_URL, **{field: 86_400}))
            Ab0tAuth().init_app(Flask("t"), config=AuthConfig(auth_url=AUTH_URL, enable_jwt_auth=False,
                                                              **{field: 86_400}))
        assert sum(field in r.getMessage() for r in caplog.records) >= 3, caplog.text

    @pytest.mark.parametrize("field", list(TTL_FIELDS))
    def test_code_out_of_range_is_clamped_even_with_a_valid_env(self, monkeypatch, field):
        # code > env precedence: the code value is the one used, so it is the one clamped (the env value is ignored)
        monkeypatch.setenv(TTL_FIELDS[field], "10")
        got = getattr(resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL, **{field: 301})), TTL_ATTR[field])
        assert 0 <= got <= 300 and got != 10, f"{field}=301 with env 10 → {got} (want the clamped code value, ≤ 300)"

    def test_env_message_unchanged(self, monkeypatch):
        # the env path keeps its exact wording (clients may grep start-up logs for it)
        monkeypatch.setenv("AB0T_AUTH_API_KEY_CACHE_TTL", "301")
        with pytest.raises(ValueError, match=r"^AB0T_AUTH_API_KEY_CACHE_TTL must be between 0 and 300 seconds$"):
            resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL))
