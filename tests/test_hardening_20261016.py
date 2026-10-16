"""Adversarial hardening tests for ab0t-auth 0.1.4 (owner instruction 2026-10-16: "robust testing, no assumptions").

Black-box against the code as it is. Assertions are on what the auth double RECEIVED (respx call counts, request
bodies) or on what the caller got. Tests that expose a defect are in test_hardening_knownbugs_20261016.py.

    claim (CHANGELOG 0.1.4 / MIGRATION.md)                        tests
    TTL precedence code > env > derived; invalid env raises      TestTTLPrecedenceMatrix
    negative TTL never above the positive TTL                     TestNegativeNeverAbovePositive
    API-key cache keyed by SHA-256; raw key never stored          TestApiKeyCacheInternals
    errors / 429 / 5xx / network never cached (API key, perms)    TestErrorsNeverCachedEveryShape
    fresh=True bypasses on every documented dependency            TestFreshOnEveryDependency
    invalidate_api_key drops exactly one key                      TestInvalidateApiKey
    concurrent use (asyncio.gather): no cross-talk                TestConcurrencyNoCrossTalk
    token cache never served past exp (grid)                      TestTokenCacheExpGrid
    unknown-kid cooldown holds through a FAILED refetch           TestKidCooldownThroughFailure
"""

from __future__ import annotations

import asyncio
import gc
import hashlib
import json
import random

import httpx
import pytest
import respx
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from ab0t_auth import cache as cache_mod
from ab0t_auth import permissions as perms_mod
from ab0t_auth.cache import ApiKeyCache, PermissionCache, TokenCache, resolve_cache_ttls
from ab0t_auth.core import AuthConfig, AuthenticatedUser, AuthMethod, TokenClaims
from ab0t_auth.dependencies import (
    require_all_permissions,
    require_any_permission,
    require_auth_and_permission,
    require_permission,
)
from ab0t_auth.errors import AuthError
from ab0t_auth.guard import AuthGuard

AUTH_URL = "https://auth.example"
API_KEY_URL = f"{AUTH_URL}/auth/validate-api-key"
PERM_URL = f"{AUTH_URL}/permissions/check"

FIELDS = {
    "permission_cache_ttl": ("AB0T_AUTH_PERMISSION_CACHE_TTL", "permission"),
    "permission_cache_negative_ttl": ("AB0T_AUTH_PERMISSION_CACHE_NEGATIVE_TTL", "permission_negative"),
    "api_key_cache_ttl": ("AB0T_AUTH_API_KEY_CACHE_TTL", "api_key"),
    "api_key_cache_negative_ttl": ("AB0T_AUTH_API_KEY_CACHE_NEGATIVE_TTL", "api_key_negative"),
}
DERIVED = {"permission": 15, "permission_negative": 5, "api_key": 60, "api_key_negative": 10}


class _Clock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def advance(self, s: float) -> None:
        self.now += s


@pytest.fixture
def clock(monkeypatch) -> _Clock:
    c = _Clock()
    monkeypatch.setattr(cache_mod, "_monotonic", lambda: c.now)
    return c


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for env, _ in FIELDS.values():
        monkeypatch.delenv(env, raising=False)


# =============================================================================
# TTL precedence: code > env > derived, every field, every edge
# =============================================================================


class TestTTLPrecedenceMatrix:
    @pytest.mark.parametrize("field", list(FIELDS))
    @pytest.mark.parametrize(
        "code,env,want",
        [
            (7, "9", 7),  # code wins over env
            (0, "9", 0),  # an explicit 0 in code wins (and disables) even with env set
            (None, "9", 9),  # env is the fallback
            (None, " 9 ", 9),  # surrounding whitespace tolerated
            (None, "\t9\n", 9),
            (None, "0", 0),  # env 0 disables
            (None, "300", 300),  # upper bound inclusive (clamped below for negatives)
            (None, "", None),  # blank = unset → derived
            (None, "   ", None),  # whitespace-only = unset → derived
        ],
    )
    def test_precedence(self, monkeypatch, field, code, env, want):
        env_name, attr = FIELDS[field]
        monkeypatch.setenv(env_name, env)
        ttls = resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL, **{field: code}))
        got = getattr(ttls, attr)
        if want is None:
            want = DERIVED[attr]
        if attr.endswith("negative"):
            pos = getattr(ttls, attr.replace("_negative", ""))
            want = min(want, pos)
        assert got == want, f"{field} code={code!r} env={env!r}: effective {got}, want {want}"

    @pytest.mark.parametrize("field", list(FIELDS))
    @pytest.mark.parametrize(
        "bad", ["abc", "1.5", "0x10", "9s", "1e1", "nan", "-1", "301", "100000", "--5", "5 5", "true"]
    )
    def test_invalid_env_raises_naming_the_variable(self, monkeypatch, field, bad):
        env_name, _ = FIELDS[field]
        monkeypatch.setenv(env_name, bad)
        with pytest.raises(ValueError) as ei:
            resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL))
        assert env_name in str(ei.value), f"error {ei.value!r} does not name {env_name}"

    @pytest.mark.parametrize("field", list(FIELDS))
    def test_invalid_env_ignored_when_code_sets_the_value(self, monkeypatch, field):
        # Precedence is real: an explicit code value means the env var is not even read.
        env_name, attr = FIELDS[field]
        monkeypatch.setenv(env_name, "garbage")
        ttls = resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL, **{field: 3}))
        assert getattr(ttls, attr) == 3

    @pytest.mark.parametrize("field", list(FIELDS))
    def test_invalid_env_raises_on_every_construction_path(self, monkeypatch, field):
        env_name, _ = FIELDS[field]
        monkeypatch.setenv(env_name, "abc")
        with pytest.raises(Exception) as ei:
            AuthGuard(auth_url=AUTH_URL)
        assert env_name in str(ei.value) or field in str(ei.value)

    def test_token_ttl_zero_disables_all_unless_explicitly_overridden(self, monkeypatch):
        cfg = AuthConfig(auth_url=AUTH_URL, token_cache_ttl=0)
        t = resolve_cache_ttls(cfg)
        assert (t.permission, t.permission_negative, t.api_key, t.api_key_negative) == (0, 0, 0, 0)
        # documented precedence: an env value is NOT "unset", so it re-enables that one cache
        monkeypatch.setenv("AB0T_AUTH_API_KEY_CACHE_TTL", "30")
        t = resolve_cache_ttls(cfg)
        assert (t.permission, t.api_key, t.api_key_negative) == (0, 30, 10)

    def test_property_random_configs(self, monkeypatch):
        rnd = random.Random(20261016)
        for _ in range(3000):
            kw = {"token_cache_ttl": rnd.choice([0, 1, 2, 10, 29, 30, 31, 59, 60, 61, 120, 300])}
            for f in FIELDS:
                kw[f] = rnd.choice([None, None, 0, 1, 4, 5, 6, 10, 15, 30, 60, 300])
            t = resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL, **kw))
            assert 0 <= t.permission_negative <= t.permission, (kw, t)
            assert 0 <= t.api_key_negative <= t.api_key, (kw, t)
            if kw["permission_cache_ttl"] is None:
                assert t.permission == min(kw["token_cache_ttl"] // 2, 15), (kw, t)
            if kw["api_key_cache_ttl"] is None:
                assert t.api_key == min(kw["token_cache_ttl"], 60), (kw, t)
            for f, (_, attr) in FIELDS.items():
                if kw[f] is not None and not attr.endswith("negative"):
                    assert getattr(t, attr) == kw[f], (f, kw, t)


# =============================================================================
# Negative TTL never above positive — and the behaviour matches the number
# =============================================================================


class TestNegativeNeverAbovePositive:
    @pytest.mark.parametrize("cls,default_neg", [(PermissionCache, 5), (ApiKeyCache, 10)])
    @pytest.mark.parametrize("ttl", [-5, 0, 1, 3, 5, 10, 60])
    @pytest.mark.parametrize("neg", [None, -1, 0, 1, 4, 5, 9, 10, 11, 1000])
    def test_effective(self, cls, default_neg, ttl, neg):
        c = cls(ttl=ttl, negative_ttl=neg)
        want = max(0, min(default_neg if neg is None else neg, ttl))
        assert c.effective_negative_ttl == want
        assert c.effective_negative_ttl <= max(ttl, 0)

    @pytest.mark.parametrize("ttl,neg", [(3, 10), (10, 3), (5, None), (60, 0)])
    def test_denied_entry_lives_exactly_effective_negative(self, clock, ttl, neg):
        c = PermissionCache(ttl=ttl, negative_ttl=neg)
        eff = c.effective_negative_ttl
        c.set("u", "p", False, credential="fp", org_id="o")
        if eff == 0:
            assert c.get("u", "p", credential="fp", org_id="o") is None
            return
        clock.advance(eff - 0.001)
        assert c.get("u", "p", credential="fp", org_id="o") is False
        clock.advance(0.001)
        assert c.get("u", "p", credential="fp", org_id="o") is None, "denial outlived its negative TTL"


# =============================================================================
# API-key cache internals: SHA-256 key, raw key never stored anywhere
# =============================================================================


def _guard(**cfg) -> AuthGuard:
    return AuthGuard(config=AuthConfig(auth_url=AUTH_URL, enable_jwt_auth=False, **cfg))


class TestApiKeyCacheInternals:
    RAW = "ab0t_sk_live_SECRET_9f8e7d6c5b4a"

    def test_raw_key_absent_from_every_cache_structure(self):
        guard = _guard()
        with respx.mock:
            respx.post(API_KEY_URL).mock(
                return_value=httpx.Response(200, json={"valid": True, "user_id": "svc", "org_id": "o"})
            )
            assert asyncio.run(guard.authenticate(api_key=self.RAW)).success
        cache = guard._api_key_cache
        keys = list(cache._cache.keys())
        assert keys == [hashlib.sha256(self.RAW.encode()).hexdigest()], keys
        for k, v in cache._cache.items():
            assert self.RAW not in k and self.RAW not in repr(v)
        assert self.RAW not in repr(cache)
        assert self.RAW not in json.dumps(guard.cache_stats())
        assert guard._token_cache.size == 0, "an API key must not land in the JWT token cache"
        assert guard._permission_cache.size == 0
        # no object reachable from the cache holds the raw key
        for obj in gc.get_referents(cache._cache):
            assert self.RAW not in repr(obj)

    def test_distinct_keys_never_share_an_entry(self):
        c = ApiKeyCache()
        from ab0t_auth.core import ApiKeyValidationResponse as R

        keys = [self.RAW, self.RAW + " ", " " + self.RAW, self.RAW.upper(), self.RAW[:-1], self.RAW + "\x00", "é" + self.RAW]
        for i, k in enumerate(keys):
            c.set(k, R(valid=True, user_id=f"u{i}"))
        for i, k in enumerate(keys):
            got = c.get(k)
            assert got is not None and got.user_id == f"u{i}", f"key variant {i} served {got}"


# =============================================================================
# Errors never cached — every shape, API key and permission check
# =============================================================================


def _key_auth(guard: AuthGuard, key: str, n: int) -> list:
    async def run():
        return [await guard.authenticate(api_key=key) for _ in range(n)]

    return asyncio.run(run())


class TestErrorsNeverCachedEveryShape:
    SHAPES = [
        ("400", dict(return_value=httpx.Response(400, json={"detail": "bad"}))),
        ("404", dict(return_value=httpx.Response(404, json={"detail": "Not Found"}))),
        ("405", dict(return_value=httpx.Response(405))),
        ("409", dict(return_value=httpx.Response(409, json={}))),
        ("422", dict(return_value=httpx.Response(422, json={"detail": []}))),
        ("429", dict(return_value=httpx.Response(429, json={"detail": "slow"}))),
        ("500", dict(return_value=httpx.Response(500, text="boom"))),
        ("502", dict(return_value=httpx.Response(502))),
        ("503", dict(return_value=httpx.Response(503, json={"detail": "Service temporarily unavailable"}))),
        ("504", dict(return_value=httpx.Response(504))),
        ("200 non-JSON", dict(return_value=httpx.Response(200, text="<html>proxy</html>"))),
        ("200 truncated JSON", dict(return_value=httpx.Response(200, text='{"valid": tr'))),
        ("200 JSON array", dict(return_value=httpx.Response(200, json=[{"valid": True}]))),
        ("timeout", dict(side_effect=httpx.ReadTimeout("t"))),
        ("connect error", dict(side_effect=httpx.ConnectError("c"))),
        ("remote protocol error", dict(side_effect=httpx.RemoteProtocolError("r"))),
    ]

    @pytest.mark.parametrize("name,mock", SHAPES, ids=[s[0] for s in SHAPES])
    def test_api_key(self, name, mock):
        guard = _guard()
        with respx.mock:
            route = respx.post(API_KEY_URL).mock(**mock)
            results = _key_auth(guard, "ab0t_sk_err", 3)
        assert not any(r.success for r in results), f"{name}: an error authenticated the request"
        assert route.call_count == 3, f"{name}: {route.call_count} auth calls for 3 requests — an error was cached"
        assert guard._api_key_cache.size == 0

    @pytest.mark.parametrize("name,mock", SHAPES + [
        ("401", dict(return_value=httpx.Response(401, json={"detail": "x"}))),
    ], ids=[s[0] for s in SHAPES] + ["401"])
    def test_permission_check(self, name, mock):
        cfg = AuthConfig(auth_url=AUTH_URL)
        cache = PermissionCache()
        user = AuthenticatedUser(user_id="u1", org_id="o1", auth_method=AuthMethod.JWT)

        async def run():
            out = []
            async with httpx.AsyncClient() as client:
                for _ in range(3):
                    try:
                        out.append(
                            await perms_mod.verify_permission(client, cfg, "Bearer t", user, "a.write", cache=cache)
                        )
                    except AuthError as e:  # raised (not a fallback) — still a refusal
                        out.append(e)
                    except Exception as e:  # noqa: BLE001 — record, the test asserts "never allowed"
                        out.append(e)
            return out

        with respx.mock:
            route = respx.post(PERM_URL).mock(**mock)
            results = asyncio.run(run())
        assert not any(getattr(r, "allowed", False) for r in results), f"{name}: allowed on an error"
        assert route.call_count == 3, f"{name}: {route.call_count} calls for 3 checks — an error was cached"
        assert cache.size == 0


# =============================================================================
# fresh=True on every documented dependency (server mode, HTTP-level counts)
# =============================================================================


def _server_guard(user: AuthenticatedUser) -> AuthGuard:
    guard = AuthGuard(config=AuthConfig(auth_url=AUTH_URL, org_id="org_1", permission_check_mode="server"))
    guard._initialized = True

    async def auth(authorization, api_key, **kwargs):
        return user

    guard.authenticate_or_raise = auth  # type: ignore[method-assign]
    return guard


def _app(dep) -> FastAPI:
    app = FastAPI()

    @app.exception_handler(AuthError)
    async def _h(request: Request, exc: AuthError):
        return JSONResponse(status_code=exc.status_code, content={"code": exc.code})

    @app.get("/r")
    async def r(user: AuthenticatedUser = Depends(dep)):
        return {"user_id": user.user_id}

    return app


class TestFreshOnEveryDependency:
    FACTORIES = {
        "require_permission": lambda g, fresh: require_permission(g, "p.a", **({"fresh": True} if fresh else {})),
        "require_any_permission": lambda g, fresh: require_any_permission(
            g, "p.a", "p.b", **({"fresh": True} if fresh else {})
        ),
        "require_all_permissions": lambda g, fresh: require_all_permissions(
            g, "p.a", "p.b", **({"fresh": True} if fresh else {})
        ),
        "require_auth_and_permission": lambda g, fresh: require_auth_and_permission(
            g, "p.a", **({"fresh": True} if fresh else {})
        ),
    }

    @pytest.mark.parametrize("name", list(FACTORIES))
    @pytest.mark.parametrize("fresh", [False, True])
    def test_counts(self, name, fresh):
        user = AuthenticatedUser(user_id="u1", org_id="org_1", auth_method=AuthMethod.JWT)
        guard = _server_guard(user)
        with respx.mock:
            route = respx.post(PERM_URL).mock(return_value=httpx.Response(200, json={"allowed": True}))
            guard._http_client = httpx.AsyncClient()
            client = TestClient(_app(self.FACTORIES[name](guard, fresh)))
            for _ in range(4):
                r = client.get("/r", headers={"Authorization": "Bearer t"})
                assert r.status_code == 200, r.text
        per_request = 2 if name == "require_all_permissions" else 1
        if fresh:
            assert route.call_count == 4 * per_request, f"{name} fresh=True: {route.call_count} checks for 4 requests"
        else:
            assert route.call_count == per_request, f"{name} default: {route.call_count} checks (cache not used)"

    @pytest.mark.parametrize("name", list(FACTORIES))
    def test_fresh_answer_refreshes_shared_entry(self, name):
        # fresh skips the READ but STORES the answer: a revocation seen by a fresh route is seen by the
        # default route at once.
        user = AuthenticatedUser(user_id="u1", org_id="org_1", auth_method=AuthMethod.JWT)
        guard = _server_guard(user)
        with respx.mock:
            route = respx.post(PERM_URL).mock(return_value=httpx.Response(200, json={"allowed": True}))
            guard._http_client = httpx.AsyncClient()
            default = TestClient(_app(self.FACTORIES["require_permission"](guard, False)))
            fresh = TestClient(_app(self.FACTORIES["require_permission"](guard, True)))
            assert default.get("/r", headers={"Authorization": "Bearer t"}).status_code == 200
            route.mock(return_value=httpx.Response(200, json={"allowed": False}))  # revoked
            assert fresh.get("/r", headers={"Authorization": "Bearer t"}).status_code == 403
            assert default.get("/r", headers={"Authorization": "Bearer t"}).status_code == 403, (
                "the fresh denial did not replace the cached allow"
            )


# =============================================================================
# invalidate_api_key: exactly one key
# =============================================================================


class TestInvalidateApiKey:
    def test_isolation(self):
        guard = _guard()
        keys = ["ab0t_sk_A", "ab0t_sk_A2", "ab0t_sk_B", "ab0t_sk_A "]
        with respx.mock:
            route = respx.post(API_KEY_URL).mock(
                side_effect=lambda req: httpx.Response(
                    200, json={"valid": True, "user_id": "u-" + json.loads(req.content)["api_key"]}
                )
            )

            async def run():
                for k in keys:
                    assert (await guard.authenticate(api_key=k)).success
                assert route.call_count == len(keys)
                assert guard.invalidate_api_key("ab0t_sk_A") is True
                assert guard.invalidate_api_key("ab0t_sk_A") is False, "second invalidate reports a stale hit"
                assert guard.invalidate_api_key("ab0t_sk_never_seen") is False
                for k in keys:
                    r = await guard.authenticate(api_key=k)
                    assert r.user.user_id == "u-" + k
                return route.call_count

            calls = asyncio.run(run())
        assert calls == len(keys) + 1, f"{calls - len(keys)} re-validations after invalidating ONE key"


# =============================================================================
# Concurrency: asyncio.gather — no cross-talk between keys / credentials
# =============================================================================


class TestConcurrencyNoCrossTalk:
    def test_api_keys(self):
        guard = _guard()
        keys = [f"ab0t_sk_k{i:02d}" for i in range(15)]

        async def answer(req):
            await asyncio.sleep(0.005)
            k = json.loads(req.content)["api_key"]
            valid = int(k[-2:]) % 3 != 0
            return httpx.Response(200, json={"valid": valid, "user_id": "u-" + k, "permissions": ["p-" + k]})

        async def one(k):
            r = await guard.authenticate(api_key=k)
            return k, r

        async def run():
            jobs = [one(k) for k in keys for _ in range(8)]
            random.Random(1).shuffle(jobs)
            return await asyncio.gather(*jobs)

        with respx.mock:
            route = respx.post(API_KEY_URL).mock(side_effect=answer)
            results = asyncio.run(run())
            # a second wave is all cache
            before = route.call_count
            results2 = asyncio.run(run())
            after = route.call_count
        for k, r in results + results2:
            should = int(k[-2:]) % 3 != 0
            assert r.success == should, f"{k}: success={r.success}, want {should}"
            if should:
                assert r.user.user_id == "u-" + k and r.user.permissions == ("p-" + k,), f"{k} got {r.user}"
        assert len(keys) <= before <= len(keys) * 8
        assert after == before, f"{after - before} auth calls on a fully warm second wave"

    def test_permission_answers_per_credential(self):
        cfg = AuthConfig(auth_url=AUTH_URL)
        cache = PermissionCache()
        user = AuthenticatedUser(user_id="owner", org_id="o1", auth_method=AuthMethod.API_KEY)
        creds = [f"ab0t_sk_c{i}" for i in range(10)]

        async def answer(req):
            await asyncio.sleep(0.003)
            cred = req.headers["Authorization"].split(" ", 1)[1]
            return httpx.Response(200, json={"allowed": int(cred[-1]) % 2 == 0})

        async def one(client, cred):
            r = await perms_mod.verify_permission(client, cfg, "", user, "x.write", cache=cache, api_key=cred)
            return cred, r.allowed

        async def run():
            async with httpx.AsyncClient() as client:
                jobs = [one(client, c) for c in creds for _ in range(6)]
                random.Random(2).shuffle(jobs)
                return await asyncio.gather(*jobs)

        with respx.mock:
            respx.post(PERM_URL).mock(side_effect=answer)
            for cred, allowed in asyncio.run(run()) + asyncio.run(run()):
                assert allowed == (int(cred[-1]) % 2 == 0), f"{cred} got another credential's answer"


# =============================================================================
# Token cache: never served past exp — grid
# =============================================================================


class _WallClock:
    def __init__(self, t: float) -> None:
        self.t = t

    def time(self) -> float:
        return self.t


class TestTokenCacheExpGrid:
    @pytest.mark.parametrize("ttl", [1, 15, 60])
    @pytest.mark.parametrize("exp_off", [-10, -0.001, 0, 0.5, 1, 14.999, 30, 59, 61, 3600, None])
    def test_grid(self, monkeypatch, ttl, exp_off):
        wall = _WallClock(2_000_000_000.0)
        monkeypatch.setattr(cache_mod, "time", wall)
        tc = TokenCache(ttl=ttl)
        exp = None if exp_off is None else wall.t + exp_off
        user = AuthenticatedUser(user_id="u", auth_method=AuthMethod.JWT)
        tc.set("tok", user, TokenClaims(sub="u", exp=exp))
        limit = ttl if exp_off is None else min(ttl, exp_off)
        if limit <= 0:
            assert tc.get("tok") is None, "an already-expired token was stored"
            return
        wall.t += limit - 0.0005
        assert tc.get("tok") is not None, "entry dropped before min(ttl, exp)"
        wall.t += 0.0005
        assert tc.get("tok") is None, f"served at min(ttl={ttl}, exp=+{exp_off}) — past the token's exp/TTL"


# =============================================================================
# Unknown-kid cooldown holds through a FAILED refetch (a down JWKS is not hammered)
# =============================================================================


class TestKidCooldownThroughFailure:
    def test_failed_forced_refetch_still_starts_the_cooldown(self, monkeypatch):
        from jwt import PyJWKClientConnectionError, PyJWKClientError

        from ab0t_auth import jwt as jwt_mod
        from ab0t_auth.jwt import CooldownPyJWKClient

        t = {"now": 10_000.0}
        monkeypatch.setattr(jwt_mod.time, "monotonic", lambda: t["now"])
        client = CooldownPyJWKClient(f"{AUTH_URL}/.well-known/jwks.json")
        forced = []

        class _K:
            key_id = "known"

        def keys(refresh=False):
            if refresh:
                forced.append(t["now"])
                raise PyJWKClientConnectionError("jwks down")
            return [_K()]

        monkeypatch.setattr(client, "get_signing_keys", keys)
        monkeypatch.setattr(client, "match_kid", lambda ks, kid: next((k for k in ks if k.key_id == kid), None))

        with pytest.raises(PyJWKClientError):
            client.get_signing_key("new-kid")
        assert len(forced) == 1
        for _ in range(59):
            t["now"] += 1
            with pytest.raises(PyJWKClientError):
                client.get_signing_key("new-kid")
            assert client.get_signing_key("known").key_id == "known"
        assert len(forced) == 1, f"{len(forced)} forced refetches against a failing JWKS inside 60 s"
        t["now"] += 1  # 60 s after the failed attempt
        with pytest.raises(PyJWKClientError):
            client.get_signing_key("new-kid")
        assert len(forced) == 2
