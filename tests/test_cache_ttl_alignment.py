"""Decision-cache alignment with the Go SDK (0.1.4).

One test (or small group) per rule:
  - permission decisions: positive 15 s, negative 5 s (was a single 30 s)
  - API-key validation:   positive 60 s, negative 10 s (was not cached)
  - token cache:          never past the token's `exp`; failures never cached; fail closed after expiry
  - errors / 429 / 5xx / network failures are never cached, on every cache
  - every TTL is configurable and 0 disables that cache; token_cache_ttl=0 still disables everything
  - a per-call `fresh=True` bypass
  - unknown-`kid` JWKS refetch at most once per 60 s; JWKS TTL default unchanged (300 s)
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from ab0t_auth import cache as cache_mod
from ab0t_auth import permissions as perms_mod
from ab0t_auth.cache import (
    DEFAULT_API_KEY_CACHE_NEGATIVE_TTL,
    DEFAULT_API_KEY_CACHE_TTL,
    DEFAULT_PERMISSION_CACHE_NEGATIVE_TTL,
    DEFAULT_PERMISSION_CACHE_TTL,
    ApiKeyCache,
    PermissionCache,
    TokenCache,
    create_api_key_cache,
    create_caches,
    resolve_cache_ttls,
)
from ab0t_auth.config import AuthSettings, settings_to_config
from ab0t_auth.core import (
    ApiKeyValidationResponse,
    AuthConfig,
    AuthenticatedUser,
    AuthMethod,
    PermissionCheckResponse,
    TokenClaims,
)
from ab0t_auth.dependencies import require_auth, require_permission
from ab0t_auth.errors import AuthError, AuthServiceError, JWKSFetchError, TokenInvalidError
from ab0t_auth.guard import AuthGuard

AUTH_URL = "https://auth.example"
API_KEY_URL = f"{AUTH_URL}/auth/validate-api-key"
PERM_URL = f"{AUTH_URL}/permissions/check"
KEY = "ab0t_sk_live_example_key"


# =============================================================================
# Fixtures / helpers
# =============================================================================


class _Clock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch) -> _Clock:
    """Moves the decision caches' clock (ab0t_auth.cache._monotonic) without touching the global time module."""
    c = _Clock()
    monkeypatch.setattr(cache_mod, "_monotonic", lambda: c.now)
    return c


def _valid_key_json() -> dict:
    return {"valid": True, "user_id": "svc_1", "org_id": "org_1", "permissions": ["a.read"]}


def _guard(**cfg) -> AuthGuard:
    return AuthGuard(config=AuthConfig(auth_url=AUTH_URL, enable_jwt_auth=False, **cfg))


def _authenticate_key(guard: AuthGuard, n: int = 1, *, fresh: bool = False) -> list:
    """Run n API-key authentications on one event loop (respx must be active)."""

    async def run():
        out = []
        for _ in range(n):
            if fresh:
                out.append(await guard.authenticate(api_key=KEY, fresh=True))
            else:
                out.append(await guard.authenticate(api_key=KEY))
        return out

    return asyncio.run(run())


def _jwt_user(user_id: str = "user_1", org: str = "org_1") -> AuthenticatedUser:
    return AuthenticatedUser(user_id=user_id, org_id=org, auth_method=AuthMethod.JWT)


class _FakePermServer:
    """Stands in for client.check_permission (the /permissions/check call)."""

    def __init__(self, allowed: bool = True, exc: Exception | None = None) -> None:
        self.allowed = allowed
        self.exc = exc
        self.calls = 0

    async def __call__(self, client, config, token, request, *, api_key=None):
        self.calls += 1
        if self.exc is not None:
            raise self.exc
        return PermissionCheckResponse(
            allowed=self.allowed, permission=request.permission, user_id=request.user_id
        )


def _verify(cache, *, fresh: bool = False, token: str = "Bearer user.jwt"):
    cfg = AuthConfig(auth_url=AUTH_URL)
    kwargs = {"fresh": True} if fresh else {}
    return asyncio.run(
        perms_mod.verify_permission(
            None, cfg, token, _jwt_user(), "billing.write", cache=cache, **kwargs
        )
    )


# =============================================================================
# 1. Defaults match the approved targets (and the Go SDK)
# =============================================================================


class TestDefaults:
    def test_constants(self):
        assert DEFAULT_PERMISSION_CACHE_TTL == 15
        assert DEFAULT_PERMISSION_CACHE_NEGATIVE_TTL == 5
        assert DEFAULT_API_KEY_CACHE_TTL == 60
        assert DEFAULT_API_KEY_CACHE_NEGATIVE_TTL == 10

    def test_permission_cache_class_defaults(self):
        c = PermissionCache()
        assert c.ttl == 15, "permission cache positive TTL must be 15 s (was 30 s)"
        assert c.effective_negative_ttl == 5

    def test_api_key_cache_class_defaults(self):
        c = ApiKeyCache()
        assert c.ttl == 60
        assert c.effective_negative_ttl == 10
        assert c.max_size == 10_000

    def test_default_config_resolves_to_targets(self):
        ttls = resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL))
        assert (ttls.permission, ttls.permission_negative) == (15, 5)
        assert (ttls.api_key, ttls.api_key_negative) == (60, 10)

    def test_guard_builds_caches_with_targets(self):
        stats = AuthGuard(auth_url=AUTH_URL).cache_stats()
        assert stats["permission"]["ttl"] == 15 and stats["permission"]["negative_ttl"] == 5
        assert stats["api_key"]["ttl"] == 60 and stats["api_key"]["negative_ttl"] == 10

    def test_create_caches_return_shape_unchanged(self):
        out = create_caches(AuthConfig(auth_url=AUTH_URL))
        assert isinstance(out, tuple) and len(out) == 3, "create_caches must still return 3 caches"
        token_cache, perm_cache, _jwks = out
        assert token_cache.ttl == 60 and perm_cache.ttl == 15

    def test_token_and_jwks_defaults_unchanged(self):
        cfg = AuthConfig(auth_url=AUTH_URL)
        assert cfg.token_cache_ttl == 60
        assert cfg.jwks_cache_ttl == 300, "JWKS TTL default deliberately left at 300 s"
        settings = AuthSettings(_env_file=None)
        assert settings.token_cache_ttl == 60 and settings.jwks_cache_ttl == 300


# =============================================================================
# 2. Configuration: every TTL configurable, 0 disables, old derivation preserved
# =============================================================================


class TestConfiguration:
    def test_token_cache_ttl_zero_still_disables_every_cache(self):
        ttls = resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL, token_cache_ttl=0))
        assert ttls.permission == 0 and ttls.permission_negative == 0
        assert ttls.api_key == 0 and ttls.api_key_negative == 0

    def test_small_token_cache_ttl_derivation(self):
        # token_cache_ttl=20: permission = min(20 // 2, 15) = 10 (same as 0.1.3), api key = min(20, 60) = 20
        ttls = resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL, token_cache_ttl=20))
        assert (ttls.permission, ttls.permission_negative) == (10, 5)
        assert (ttls.api_key, ttls.api_key_negative) == (20, 10)

    def test_negative_ttl_clamped_to_positive(self):
        ttls = resolve_cache_ttls(AuthConfig(auth_url=AUTH_URL, token_cache_ttl=8))
        assert ttls.permission == 4 and ttls.permission_negative == 4
        assert ttls.api_key == 8 and ttls.api_key_negative == 8
        explicit = resolve_cache_ttls(
            AuthConfig(
                auth_url=AUTH_URL,
                permission_cache_ttl=3,
                permission_cache_negative_ttl=30,
                api_key_cache_ttl=4,
                api_key_cache_negative_ttl=40,
            )
        )
        assert explicit.permission_negative == 3 and explicit.api_key_negative == 4

    def test_explicit_values_win_and_old_30s_is_restorable(self):
        ttls = resolve_cache_ttls(
            AuthConfig(
                auth_url=AUTH_URL,
                permission_cache_ttl=30,
                permission_cache_negative_ttl=30,
                api_key_cache_ttl=0,
            )
        )
        assert (ttls.permission, ttls.permission_negative) == (30, 30)
        assert ttls.api_key == 0 and ttls.api_key_negative == 0

    def test_explicit_zero_disables_independently(self):
        ttls = resolve_cache_ttls(
            AuthConfig(auth_url=AUTH_URL, permission_cache_ttl=0, api_key_cache_negative_ttl=0)
        )
        assert ttls.permission == 0 and ttls.permission_negative == 0
        assert ttls.api_key == 60 and ttls.api_key_negative == 0

    def test_env_vars(self, monkeypatch):
        monkeypatch.setenv("AB0T_AUTH_PERMISSION_CACHE_TTL", "7")
        monkeypatch.setenv("AB0T_AUTH_PERMISSION_CACHE_NEGATIVE_TTL", "2")
        monkeypatch.setenv("AB0T_AUTH_API_KEY_CACHE_TTL", "0")
        monkeypatch.setenv("AB0T_AUTH_API_KEY_CACHE_NEGATIVE_TTL", "3")
        cfg = settings_to_config(AuthSettings(_env_file=None))
        assert cfg.permission_cache_ttl == 7 and cfg.permission_cache_negative_ttl == 2
        assert cfg.api_key_cache_ttl == 0 and cfg.api_key_cache_negative_ttl == 3
        stats = AuthGuard(config=cfg).cache_stats()
        assert stats["permission"]["ttl"] == 7 and stats["permission"]["negative_ttl"] == 2
        assert stats["api_key"]["ttl"] == 0

    def test_env_unset_means_derived(self, monkeypatch):
        for name in (
            "AB0T_AUTH_PERMISSION_CACHE_TTL",
            "AB0T_AUTH_PERMISSION_CACHE_NEGATIVE_TTL",
            "AB0T_AUTH_API_KEY_CACHE_TTL",
            "AB0T_AUTH_API_KEY_CACHE_NEGATIVE_TTL",
        ):
            monkeypatch.delenv(name, raising=False)
        cfg = settings_to_config(AuthSettings(_env_file=None))
        assert cfg.permission_cache_ttl is None and cfg.api_key_cache_ttl is None
        assert resolve_cache_ttls(cfg).permission == 15

    def test_settings_reject_negative_and_huge_values(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            AuthSettings(_env_file=None, permission_cache_ttl=-1)
        with pytest.raises(ValidationError):
            AuthSettings(_env_file=None, api_key_cache_ttl=301)


# =============================================================================
# 3. Permission decision cache: 15 s allowed / 5 s denied
# =============================================================================


class TestPermissionCacheTTLs:
    def test_allowed_served_for_15s_then_expires(self, clock):
        c = PermissionCache()
        c.set("u", "p", True, credential="fp", org_id="o")
        clock.advance(14.9)
        assert c.get("u", "p", credential="fp", org_id="o") is True
        clock.advance(0.1)  # exactly 15 s
        assert c.get("u", "p", credential="fp", org_id="o") is None

    def test_denied_served_for_5s_then_expires(self, clock):
        c = PermissionCache()
        c.set("u", "p", False, credential="fp", org_id="o")
        clock.advance(4.9)
        assert c.get("u", "p", credential="fp", org_id="o") is False
        clock.advance(0.1)  # exactly 5 s
        assert c.get("u", "p", credential="fp", org_id="o") is None

    def test_verify_permission_reasks_after_ttl(self, clock, monkeypatch):
        server = _FakePermServer(allowed=True)
        monkeypatch.setattr(perms_mod, "check_permission_remote", server)
        cache = PermissionCache()
        assert _verify(cache).allowed and _verify(cache).allowed
        assert server.calls == 1, "a repeat check within 15 s must be served from cache"
        clock.advance(15)
        assert _verify(cache).allowed
        assert server.calls == 2, "after 15 s the auth service must be asked again"

    def test_revoked_grant_stops_passing_within_15s(self, clock, monkeypatch):
        server = _FakePermServer(allowed=True)
        monkeypatch.setattr(perms_mod, "check_permission_remote", server)
        cache = PermissionCache()
        assert _verify(cache).allowed
        server.allowed = False  # grant revoked server-side
        clock.advance(10)
        assert _verify(cache).allowed, "inside the window the cached allow is still served"
        clock.advance(5)
        assert not _verify(cache).allowed, "the revocation must be visible after 15 s"

    def test_new_grant_visible_within_5s(self, clock, monkeypatch):
        server = _FakePermServer(allowed=False)
        monkeypatch.setattr(perms_mod, "check_permission_remote", server)
        cache = PermissionCache()
        assert not _verify(cache).allowed
        server.allowed = True  # grant added server-side
        clock.advance(5)
        assert _verify(cache).allowed, "a cached denial must not outlive the 5 s negative TTL"

    def test_ttl_zero_disables(self, monkeypatch):
        server = _FakePermServer(allowed=True)
        monkeypatch.setattr(perms_mod, "check_permission_remote", server)
        cache = PermissionCache(ttl=0)
        for _ in range(3):
            assert _verify(cache).allowed
        assert server.calls == 3 and cache.size == 0

    def test_negative_ttl_zero_caches_only_allows(self, monkeypatch):
        server = _FakePermServer(allowed=False)
        monkeypatch.setattr(perms_mod, "check_permission_remote", server)
        cache = PermissionCache(negative_ttl=0)
        _verify(cache)
        _verify(cache)
        assert server.calls == 2 and cache.size == 0
        server.allowed = True
        _verify(cache)
        _verify(cache)
        assert server.calls == 3

    def test_hit_miss_counters(self, monkeypatch):
        monkeypatch.setattr(perms_mod, "check_permission_remote", _FakePermServer(allowed=True))
        cache = PermissionCache()
        _verify(cache)
        _verify(cache)
        assert (cache.hits, cache.misses) == (1, 1)


class TestPermissionErrorsNeverCached:
    @pytest.mark.parametrize(
        "exc",
        [AuthServiceError("down"), AuthServiceError("Auth service returned HTTP 503")],
    )
    def test_service_error_not_cached_and_fails_closed(self, monkeypatch, exc):
        server = _FakePermServer(exc=exc)
        monkeypatch.setattr(perms_mod, "check_permission_remote", server)
        cache = PermissionCache()
        assert not _verify(cache).allowed, "default permission_fallback='deny' must refuse"
        assert not _verify(cache).allowed
        assert server.calls == 2 and cache.size == 0, "an error must never be cached"

    @pytest.mark.parametrize("status", [429, 500, 502, 503])
    def test_http_errors_not_cached(self, status):
        cache = PermissionCache()
        cfg = AuthConfig(auth_url=AUTH_URL)

        async def run():
            async with httpx.AsyncClient() as client:
                for _ in range(2):
                    try:
                        r = await perms_mod.verify_permission(
                            client, cfg, "Bearer t", _jwt_user(), "x.write", cache=cache
                        )
                        assert not r.allowed, f"HTTP {status} must not allow"
                    except AuthError:
                        pass  # 429 propagates as RateLimitError - also a refusal

        with respx.mock:
            route = respx.post(PERM_URL).mock(return_value=httpx.Response(status, json={}))
            asyncio.run(run())
        assert route.call_count == 2 and cache.size == 0

    def test_expired_allow_never_served_after_failed_refresh(self, clock, monkeypatch):
        server = _FakePermServer(allowed=True)
        monkeypatch.setattr(perms_mod, "check_permission_remote", server)
        cache = PermissionCache()
        assert _verify(cache).allowed
        clock.advance(15)
        server.exc = AuthServiceError("down")
        assert not _verify(cache).allowed, "a stale allow must not be served when the refresh fails"


class TestPermissionFresh:
    def test_fresh_skips_cache_and_stores_new_answer(self, monkeypatch):
        server = _FakePermServer(allowed=True)
        monkeypatch.setattr(perms_mod, "check_permission_remote", server)
        cache = PermissionCache()
        assert _verify(cache).allowed
        server.allowed = False
        assert not _verify(cache, fresh=True).allowed, "fresh=True must ask the auth service"
        assert server.calls == 2
        assert not _verify(cache).allowed, "the fresh answer replaces the cached one"
        assert server.calls == 2

    def test_fresh_on_any_and_all(self, monkeypatch):
        server = _FakePermServer(allowed=True)
        monkeypatch.setattr(perms_mod, "check_permission_remote", server)
        cache = PermissionCache()
        cfg = AuthConfig(auth_url=AUTH_URL)
        user = _jwt_user()

        async def run():
            await perms_mod.verify_all_permissions(None, cfg, "Bearer t", user, "a", "b", cache=cache)
            await perms_mod.verify_all_permissions(None, cfg, "Bearer t", user, "a", "b", cache=cache)
            assert server.calls == 2
            await perms_mod.verify_all_permissions(
                None, cfg, "Bearer t", user, "a", "b", cache=cache, fresh=True
            )
            assert server.calls == 4
            await perms_mod.verify_any_permission(
                None, cfg, "Bearer t", user, "a", cache=cache, fresh=True
            )
            assert server.calls == 5

        asyncio.run(run())


# =============================================================================
# 4. API-key validation cache: 60 s valid / 10 s rejected
# =============================================================================


class TestApiKeyCache:
    def test_valid_key_cached_60s(self, clock):
        guard = _guard()
        with respx.mock:
            route = respx.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=_valid_key_json()))
            results = _authenticate_key(guard, 3)
            assert all(r.success for r in results)
            assert route.call_count == 1, "a valid key must be validated once per 60 s"
            clock.advance(59.9)
            _authenticate_key(guard)
            assert route.call_count == 1
            clock.advance(0.1)
            _authenticate_key(guard)
            assert route.call_count == 2, "after 60 s the key must be re-validated"

    @pytest.mark.parametrize(
        "response",
        [
            httpx.Response(200, json={"valid": False, "error": "API key validation failed"}),
            httpx.Response(401, json={"detail": "Invalid API key"}),
            httpx.Response(403, json={"detail": "Forbidden"}),
        ],
    )
    def test_rejected_key_cached_10s(self, clock, response):
        guard = _guard()
        with respx.mock:
            route = respx.post(API_KEY_URL).mock(return_value=response)
            results = _authenticate_key(guard, 3)
            assert not any(r.success for r in results)
            assert all(r.error_code == "INVALID_API_KEY" for r in results)
            assert route.call_count == 1
            clock.advance(10)
            _authenticate_key(guard)
            assert route.call_count == 2, "a rejection must not be cached past 10 s"

    def test_revoked_key_stops_working_within_60s(self, clock):
        guard = _guard()
        with respx.mock:
            route = respx.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=_valid_key_json()))
            assert _authenticate_key(guard)[0].success
            route.mock(return_value=httpx.Response(200, json={"valid": False}))  # revoked
            clock.advance(30)
            assert _authenticate_key(guard)[0].success, "inside the window the cached answer is served"
            clock.advance(30)
            assert not _authenticate_key(guard)[0].success, "revocation must be visible after 60 s"

    @pytest.mark.parametrize("status", [429, 500, 502, 503])
    def test_http_errors_never_cached_and_fail_closed(self, status):
        guard = _guard()
        with respx.mock:
            route = respx.post(API_KEY_URL).mock(return_value=httpx.Response(status, json={}))
            results = _authenticate_key(guard, 3)
            assert not any(r.success for r in results), f"HTTP {status} must refuse (fail closed)"
            assert route.call_count == 3, f"HTTP {status} must never be cached"
        assert guard._api_key_cache.size == 0

    def test_network_error_never_cached(self):
        guard = _guard()
        with respx.mock:
            route = respx.post(API_KEY_URL).mock(side_effect=httpx.ConnectError("boom"))
            results = _authenticate_key(guard, 2)
            assert not any(r.success for r in results)
            assert route.call_count == 2 and guard._api_key_cache.size == 0

    def test_expired_entry_never_served_after_failed_refresh(self, clock):
        guard = _guard()
        with respx.mock:
            route = respx.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=_valid_key_json()))
            assert _authenticate_key(guard)[0].success
            clock.advance(60)
            route.mock(return_value=httpx.Response(503, json={}))
            assert not _authenticate_key(guard)[0].success, "stale valid entry served after a failed refresh"

    def test_malformed_valid_answer_not_cached(self):
        guard = _guard()
        with respx.mock:
            route = respx.post(API_KEY_URL).mock(
                return_value=httpx.Response(200, json={"valid": True, "user_id": None})
            )
            results = _authenticate_key(guard, 2)
            assert not any(r.success for r in results)
            assert route.call_count == 2

    def test_ttl_zero_disables(self):
        guard = _guard(api_key_cache_ttl=0)
        with respx.mock:
            route = respx.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=_valid_key_json()))
            _authenticate_key(guard, 3)
            assert route.call_count == 3

    def test_token_cache_ttl_zero_disables_api_key_cache_too(self):
        guard = _guard(token_cache_ttl=0)
        with respx.mock:
            route = respx.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=_valid_key_json()))
            _authenticate_key(guard, 2)
            assert route.call_count == 2, "token_cache_ttl=0 (strict) must keep API keys uncached"

    def test_negative_ttl_zero_caches_only_valid(self):
        guard = _guard(api_key_cache_negative_ttl=0)
        with respx.mock:
            route = respx.post(API_KEY_URL).mock(return_value=httpx.Response(200, json={"valid": False}))
            _authenticate_key(guard, 2)
            assert route.call_count == 2

    def test_fresh_bypasses_cache(self):
        guard = _guard()
        with respx.mock:
            route = respx.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=_valid_key_json()))
            _authenticate_key(guard)
            _authenticate_key(guard, fresh=True)
            assert route.call_count == 2, "fresh=True must re-validate with the auth service"
            route.mock(return_value=httpx.Response(200, json={"valid": False}))
            assert not _authenticate_key(guard, fresh=True)[0].success
            assert not _authenticate_key(guard)[0].success, "the fresh answer replaces the cached one"
            assert route.call_count == 3

    def test_invalidate_and_clear(self):
        guard = _guard()
        with respx.mock:
            route = respx.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=_valid_key_json()))
            _authenticate_key(guard)
            assert guard.invalidate_api_key(KEY) is True
            assert guard.invalidate_api_key(KEY) is False
            _authenticate_key(guard)
            guard.clear_caches()
            _authenticate_key(guard)
            assert route.call_count == 3

    def test_raw_key_never_stored(self):
        c = ApiKeyCache()
        c.set(KEY, ApiKeyValidationResponse(valid=True, user_id="svc_1"))
        assert all(KEY not in k for k in c._cache)
        assert c.get(KEY) is not None

    def test_bounded(self):
        c = ApiKeyCache(max_size=3)
        for i in range(10):
            c.set(f"k{i}", ApiKeyValidationResponse(valid=True, user_id="u"))
        assert c.size <= 3

    def test_stats(self):
        guard = _guard()
        with respx.mock:
            respx.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=_valid_key_json()))
            _authenticate_key(guard, 3)
        s = guard.cache_stats()["api_key"]
        assert (s["hits"], s["misses"], s["size"]) == (2, 1, 1)

    def test_legacy_service_side_wrappers_stand_down(self):
        """Services on <= 0.1.3 wrapped _authenticate_api_key to cache keys in _token_cache, and stand down once the
        upstream method's source mentions _token_cache. Keep that marker, or two cache layers stack up."""
        import inspect

        assert "_token_cache" in inspect.getsource(AuthGuard._authenticate_api_key)

    def test_create_api_key_cache_from_config(self):
        c = create_api_key_cache(AuthConfig(auth_url=AUTH_URL, api_key_cache_ttl=30))
        assert c.ttl == 30 and c.effective_negative_ttl == 10


class TestFlaskApiKeyCache:
    @pytest.fixture(autouse=True)
    def _reset_flask_user_context(self):
        """The Flask extension stores the user in a module-level ContextVar; do not leak it into other tests."""
        yield
        from ab0t_auth import flask as flask_mod

        flask_mod._current_user.set(None)

    def _app(self, **cfg):
        from flask import Flask

        from ab0t_auth.flask import Ab0tAuth, get_current_user

        app = Flask(__name__)
        auth = Ab0tAuth()
        auth.init_app(app, config=AuthConfig(auth_url=AUTH_URL, enable_jwt_auth=False, **cfg))

        @app.route("/me")
        def me():
            u = get_current_user()
            return {"user_id": u.user_id if u else None}

        return app, auth

    def test_flask_caches_valid_key(self):
        app, _ = self._app()
        mock = AsyncMock(return_value=ApiKeyValidationResponse(valid=True, user_id="svc_1"))
        with patch("ab0t_auth.flask.validate_api_key", mock):
            client = app.test_client()
            for _ in range(3):
                assert client.get("/me", headers={"X-API-Key": KEY}).json["user_id"] == "svc_1"
        assert mock.await_count == 1

    def test_flask_errors_not_cached(self):
        app, _ = self._app()
        mock = AsyncMock(side_effect=AuthServiceError("down"))
        with patch("ab0t_auth.flask.validate_api_key", mock):
            client = app.test_client()
            for _ in range(2):
                assert client.get("/me", headers={"X-API-Key": KEY}).json["user_id"] is None
        assert mock.await_count == 2

    def test_flask_ttl_zero_and_fresh(self):
        app, auth = self._app(api_key_cache_ttl=0)
        mock = AsyncMock(return_value=ApiKeyValidationResponse(valid=True, user_id="svc_1"))
        with patch("ab0t_auth.flask.validate_api_key", mock):
            client = app.test_client()
            client.get("/me", headers={"X-API-Key": KEY})
            client.get("/me", headers={"X-API-Key": KEY})
        assert mock.await_count == 2

        app, auth = self._app()
        mock = AsyncMock(return_value=ApiKeyValidationResponse(valid=True, user_id="svc_1"))
        with patch("ab0t_auth.flask.validate_api_key", mock):
            assert auth.authenticate(api_key=KEY).success
            assert auth.authenticate(api_key=KEY, fresh=True).success
            assert auth.invalidate_api_key(KEY) is True
        assert mock.await_count == 2


# =============================================================================
# 5. Token cache: capped at exp, failures never cached, fail closed, 0 disables, fresh
# =============================================================================


class TestTokenCache:
    def test_positive_capped_at_exp(self):
        now = time.time()
        c = TokenCache(ttl=60)
        user = AuthenticatedUser(user_id="u")
        c.set("tok", user, TokenClaims(sub="u", exp=int(now) + 5))
        entry = c.get("tok")
        assert entry is not None and entry.expires_at <= now + 5

    def test_not_served_after_exp(self, monkeypatch):
        now = time.time()
        c = TokenCache(ttl=60)
        c.set("tok", AuthenticatedUser(user_id="u"), TokenClaims(sub="u", exp=int(now) + 2))
        monkeypatch.setattr(cache_mod.time, "time", lambda: now + 3)
        assert c.get("tok") is None

    def test_already_expired_token_not_stored(self):
        c = TokenCache(ttl=60)
        c.set("tok", AuthenticatedUser(user_id="u"), TokenClaims(sub="u", exp=int(time.time()) - 1))
        assert c.size == 0

    def test_ttl_zero_disables(self):
        c = TokenCache(ttl=0)
        c.set("tok", AuthenticatedUser(user_id="u"), TokenClaims(sub="u", exp=int(time.time()) + 600))
        assert c.size == 0 and c.get("tok") is None

    def _jwt_guard(self, **cfg) -> AuthGuard:
        guard = AuthGuard(config=AuthConfig(auth_url=AUTH_URL, **cfg))
        guard._jwk_client = object()  # never used: validate_token_pipeline is patched
        guard._http_client = object()
        guard._initialized = True
        return guard

    def _pipeline_ok(self):
        user = AuthenticatedUser(user_id="u")
        claims = TokenClaims(sub="u", exp=int(time.time()) + 600)
        calls = {"n": 0}

        def fn(token, jwk, config):
            calls["n"] += 1
            return user, claims

        return fn, calls

    def test_failed_validation_never_cached(self):
        guard = self._jwt_guard()
        calls = {"n": 0}

        def bad(token, jwk, config):
            calls["n"] += 1
            raise TokenInvalidError("bad")

        with patch("ab0t_auth.guard.validate_token_pipeline", bad):
            for _ in range(2):
                assert not asyncio.run(guard.authenticate("Bearer x.y.z")).success
        assert calls["n"] == 2 and guard._token_cache.size == 0

    def test_fail_closed_after_expiry_when_revalidation_fails(self, monkeypatch):
        guard = self._jwt_guard()
        now = time.time()
        user = AuthenticatedUser(user_id="u")
        claims = TokenClaims(sub="u", exp=int(now) + 2)
        with patch("ab0t_auth.guard.validate_token_pipeline", lambda t, j, c: (user, claims)):
            assert asyncio.run(guard.authenticate("Bearer x.y.z")).success

        def jwks_down(token, jwk, config):
            raise JWKSFetchError("JWKS unavailable")

        monkeypatch.setattr(cache_mod.time, "time", lambda: now + 5)
        with patch("ab0t_auth.guard.validate_token_pipeline", jwks_down):
            assert not asyncio.run(
                guard.authenticate("Bearer x.y.z")
            ).success, "an expired cached token was served after re-validation failed"

    def test_guard_token_cache_ttl_zero(self):
        guard = self._jwt_guard(token_cache_ttl=0)
        fn, calls = self._pipeline_ok()
        with patch("ab0t_auth.guard.validate_token_pipeline", fn):
            for _ in range(3):
                assert asyncio.run(guard.authenticate("Bearer x.y.z")).success
        assert calls["n"] == 3

    def test_guard_fresh_bypasses_token_cache(self):
        guard = self._jwt_guard()
        fn, calls = self._pipeline_ok()
        with patch("ab0t_auth.guard.validate_token_pipeline", fn):
            asyncio.run(guard.authenticate("Bearer x.y.z"))
            asyncio.run(guard.authenticate("Bearer x.y.z"))
            assert calls["n"] == 1
            asyncio.run(guard.authenticate("Bearer x.y.z", fresh=True))
            assert calls["n"] == 2
            asyncio.run(guard.authenticate_or_raise("Bearer x.y.z", None, fresh=True))
            assert calls["n"] == 3


# =============================================================================
# 6. FastAPI dependencies: fresh=True per route; default call shape unchanged
# =============================================================================


def _server_guard(user: AuthenticatedUser, seen_kwargs: list) -> AuthGuard:
    guard = AuthGuard(
        config=AuthConfig(auth_url=AUTH_URL, org_id="org_1", permission_check_mode="server")
    )
    guard._initialized = True

    async def auth(authorization, api_key, **kwargs):
        seen_kwargs.append(kwargs)
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


class TestDependencyFresh:
    def test_default_route_uses_cache_and_two_arg_auth_call(self):
        seen: list = []
        guard = _server_guard(_jwt_user(), seen)
        with respx.mock:
            route = respx.post(PERM_URL).mock(return_value=httpx.Response(200, json={"allowed": True}))
            guard._http_client = httpx.AsyncClient()
            client = TestClient(_app(require_permission(guard, "billing.write")))
            for _ in range(3):
                assert client.get("/r", headers={"Authorization": "Bearer t"}).status_code == 200
        assert route.call_count == 1, "default routes keep the 15 s permission cache"
        assert seen == [{}, {}, {}], "default path must not pass `fresh` (keeps two-argument overrides working)"

    def test_fresh_route_asks_every_time(self):
        seen: list = []
        guard = _server_guard(_jwt_user(), seen)
        with respx.mock:
            route = respx.post(PERM_URL).mock(return_value=httpx.Response(200, json={"allowed": True}))
            guard._http_client = httpx.AsyncClient()
            client = TestClient(_app(require_permission(guard, "billing.write", fresh=True)))
            for _ in range(3):
                assert client.get("/r", headers={"Authorization": "Bearer t"}).status_code == 200
        assert route.call_count == 3, "fresh=True must ask /permissions/check on every request"
        assert seen == [{"fresh": True}] * 3

    def test_require_auth_fresh_flag_forwarded(self):
        seen: list = []
        guard = _server_guard(_jwt_user(), seen)
        client = TestClient(_app(require_auth(guard, fresh=True)))
        assert client.get("/r", headers={"Authorization": "Bearer t"}).status_code == 200
        assert seen == [{"fresh": True}]

    def test_two_arg_override_still_works_without_fresh(self):
        guard = AuthGuard(config=AuthConfig(auth_url=AUTH_URL))

        async def strict_two_args(authorization, api_key):
            return _jwt_user()

        guard.authenticate_or_raise = strict_two_args  # type: ignore[method-assign]
        client = TestClient(_app(require_auth(guard)))
        assert client.get("/r", headers={"Authorization": "Bearer t"}).status_code == 200


# =============================================================================
# 7. JWKS: unknown-kid refetch at most once per 60 s
# =============================================================================


class TestJwksKidCooldown:
    def test_default_cooldown_is_60s(self):
        from ab0t_auth.jwt import (
            JWKS_UNKNOWN_KID_REFRESH_COOLDOWN_SECONDS,
            CooldownPyJWKClient,
            create_jwk_client,
        )

        assert JWKS_UNKNOWN_KID_REFRESH_COOLDOWN_SECONDS == 60.0
        client = create_jwk_client(AuthConfig(auth_url=AUTH_URL))
        assert isinstance(client, CooldownPyJWKClient)
        assert client._ab0t_refresh_cooldown == 60.0

    def test_one_forced_refetch_per_minute(self, monkeypatch):
        from jwt import PyJWKClientError

        from ab0t_auth import jwt as jwt_mod
        from ab0t_auth.jwt import CooldownPyJWKClient

        t = {"now": 5000.0}
        monkeypatch.setattr(jwt_mod.time, "monotonic", lambda: t["now"])
        client = CooldownPyJWKClient(f"{AUTH_URL}/.well-known/jwks.json")
        refreshes = []
        monkeypatch.setattr(
            client, "get_signing_keys", lambda refresh=False: refreshes.append(refresh) or []
        )

        def unknown():
            with pytest.raises(PyJWKClientError):
                client.get_signing_key("unknown-kid")

        unknown()
        assert refreshes.count(True) == 1
        t["now"] += 30
        unknown()
        assert refreshes.count(True) == 1, "a second forced refetch inside 60 s (was allowed at 30 s)"
        t["now"] += 29.9
        unknown()
        assert refreshes.count(True) == 1
        t["now"] += 0.1  # 60 s after the first forced refetch
        unknown()
        assert refreshes.count(True) == 2, "key rotation: one refetch is allowed again after 60 s"

    def test_cooldown_tunable_via_module_default(self, monkeypatch):
        from ab0t_auth import jwt as jwt_mod

        monkeypatch.setattr(jwt_mod, "JWKS_UNKNOWN_KID_REFRESH_COOLDOWN_SECONDS", 30.0)
        client = jwt_mod.create_jwk_client(AuthConfig(auth_url=AUTH_URL))
        assert client._ab0t_refresh_cooldown == 30.0
        explicit = jwt_mod.CooldownPyJWKClient(f"{AUTH_URL}/.well-known/jwks.json", refresh_cooldown=5.0)
        assert explicit._ab0t_refresh_cooldown == 5.0
