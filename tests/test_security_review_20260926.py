"""Security review 2026-09-26 (0.1.2) — proofs for the security findings fixed in 0.1.2.

Each test is written against the 0.1.1 behaviour first (RED), then the fix makes it GREEN.
"""

import httpx
import pytest
import respx
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from ab0t_auth.core import AuthConfig, AuthenticatedUser, AuthMethod
from ab0t_auth.dependencies import (
    require_all_permissions,
    require_any_permission,
    require_permission,
)
from ab0t_auth.errors import AuthError
from ab0t_auth.guard import AuthGuard

AUTH_URL = "https://auth.test.ab0t.com"
OWNER = "user-rita"
NARROW_KEY = "ab0t_sk_narrow_reporting_key"
ATTACKER_JWT = "attacker.login.jwt-rejected-locally"


def _server_config() -> AuthConfig:
    return AuthConfig(
        auth_url=AUTH_URL,
        org_id="org-r",
        audience="billing-service",
        issuer=AUTH_URL,
        enable_api_key_auth=True,
        enable_jwt_auth=True,
        permission_check_mode="server",
    )


def _app(guard: AuthGuard, dep) -> FastAPI:
    app = FastAPI()

    @app.exception_handler(AuthError)
    async def _h(request: Request, exc: AuthError):
        return JSONResponse(
            status_code=exc.status_code, content={"detail": exc.message, "code": exc.code}
        )

    @app.post("/accounts")
    async def create(user: AuthenticatedUser = Depends(dep)):
        return {"user_id": user.user_id}

    return app


# =============================================================================
# F-1 (HIGH): server-mode permission check is asked with a credential that did NOT authenticate the request
# =============================================================================


@pytest.mark.parametrize(
    "factory", [require_permission, require_any_permission, require_all_permissions]
)
def test_permission_check_uses_the_credential_that_authenticated(factory):
    """Authorization carries a token the guard REJECTS (e.g. wrong audience / other service); X-API-Key carries a
    narrow key of the owner. The guard falls through to the key (user = owner, scope = billing.read). The permission
    check must be asked WITH THE KEY — not with the rejected bearer, which auth would answer for the named owner.
    """
    guard = AuthGuard(config=_server_config())
    seen: list[str] = []

    def perm_check(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        seen.append(auth)
        # Auth answers per CALLING credential: the attacker's own login token asking about the owner gets the
        # OWNER's answer (person path); the narrow key gets its own scope.
        allowed = auth == f"Bearer {ATTACKER_JWT}"
        return httpx.Response(200, json={"allowed": allowed})

    with respx.mock:
        respx.post(f"{AUTH_URL}/auth/validate-api-key").mock(
            return_value=httpx.Response(
                200,
                json={
                    "valid": True,
                    "user_id": OWNER,
                    "org_id": "org-r",
                    "permissions": ["billing.read"],
                },
            )
        )
        respx.post(f"{AUTH_URL}/permissions/check").mock(side_effect=perm_check)
        guard._http_client = httpx.AsyncClient()
        guard._initialized = (
            True  # no JWKS client → every bearer is rejected locally, like an audience mismatch
        )

        client = TestClient(_app(guard, factory(guard, "billing.write")))
        r = client.post(
            "/accounts",
            headers={"Authorization": f"Bearer {ATTACKER_JWT}", "X-API-Key": NARROW_KEY},
        )

    assert seen, "the permission check was never made"
    assert all(
        h == f"Bearer {NARROW_KEY}" for h in seen
    ), f"permission check asked with a credential that did not authenticate the request: {seen}"
    assert (
        r.status_code == 403
    ), f"narrow key escalated to its owner's authority via a rejected bearer: {r.status_code}"


def test_jwt_user_permission_check_still_uses_the_jwt(monkeypatch):
    """Control: a request authenticated by its JWT is still asked with that JWT (not with an extra X-API-Key)."""
    import asyncio

    from ab0t_auth import permissions as perms_mod
    from ab0t_auth.core import PermissionCheckResponse

    calls = []

    async def fake(client, config, token, request, *, api_key=None):
        calls.append((token, api_key))
        return PermissionCheckResponse(
            allowed=True, permission=request.permission, user_id=request.user_id
        )

    monkeypatch.setattr(perms_mod, "check_permission_remote", fake)
    user = AuthenticatedUser(user_id=OWNER, org_id="org-r", auth_method=AuthMethod.JWT)
    res = asyncio.run(
        perms_mod.verify_permission(
            None,
            _server_config(),
            "Bearer owner.jwt",
            user,
            "billing.write",
            api_key="some_other_key",
        )
    )
    assert res.allowed
    assert calls == [("Bearer owner.jwt", None)]


# =============================================================================
# SR-2 (MEDIUM): unknown-kid tokens force a synchronous JWKS refetch on every request (unauthenticated DoS)
# =============================================================================


def test_unknown_kid_does_not_refetch_jwks_every_request(monkeypatch):
    import uuid

    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt import PyJWKClientError
    from jwt.algorithms import RSAAlgorithm

    from ab0t_auth.jwt import create_jwk_client

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    import json

    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "real-kid", "use": "sig", "alg": "RS256"})
    fetches = {"n": 0}

    client = create_jwk_client(AuthConfig(auth_url=AUTH_URL))

    class _Resp:
        """Stands in for the HTTP response of the JWKS endpoint (patched at urllib, so PyJWT's own caching runs)."""

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *a):
            return json.dumps({"keys": [jwk]}).encode()

    def fake_urlopen(*a, **kw):
        fetches["n"] += 1
        return _Resp()

    import jwt.jwks_client as jwks_mod

    monkeypatch.setattr(jwks_mod.urllib.request, "urlopen", fake_urlopen)
    # Prime the cache with the real set (the normal steady state).
    client.get_signing_keys()
    primed = fetches["n"]

    for _ in range(25):
        forged = pyjwt.encode(
            {"sub": "x"}, "not-a-real-key", algorithm="HS256", headers={"kid": str(uuid.uuid4())}
        )
        with pytest.raises(PyJWKClientError):
            client.get_signing_key_from_jwt(forged)

    assert (
        fetches["n"] - primed <= 1
    ), f"{fetches['n'] - primed} JWKS fetches for 25 forged unknown-kid tokens"


def test_unknown_kid_refreshes_again_after_cooldown(monkeypatch):
    """Key rotation still works: once the cooldown has passed, an unknown kid triggers one more refresh."""
    from ab0t_auth.jwt import CooldownPyJWKClient

    client = CooldownPyJWKClient(
        "https://auth.test.ab0t.com/.well-known/jwks.json", refresh_cooldown=0.0
    )
    calls = []
    monkeypatch.setattr(
        client, "get_signing_keys", lambda refresh=False: calls.append(refresh) or []
    )
    from jwt import PyJWKClientError

    for _ in range(2):
        with pytest.raises(PyJWKClientError):
            client.get_signing_key("new-kid")
    assert (
        calls.count(True) == 2
    ), "with the cooldown elapsed each unknown kid must trigger a refresh"


# =============================================================================
# SR-3 (MEDIUM): an expired JWT is served from the token cache after its exp
# =============================================================================


def test_token_cache_never_outlives_token_exp(monkeypatch):
    import time as _time

    from ab0t_auth import cache as cache_mod
    from ab0t_auth.cache import TokenCache
    from ab0t_auth.core import TokenClaims

    now = _time.time()
    tc = TokenCache(max_size=10, ttl=60)
    user = AuthenticatedUser(user_id=OWNER, auth_method=AuthMethod.JWT)
    tc.set("tok", user, TokenClaims(sub=OWNER, exp=int(now) + 2))
    assert tc.get("tok") is not None, "fresh entry must be served"

    monkeypatch.setattr(
        cache_mod.time, "time", lambda: now + 30
    )  # 28 s after exp, well inside the 60 s TTL
    assert tc.get("tok") is None, "an expired token was served from the token cache"


# =============================================================================
# SR-5 (MEDIUM, config): audience verification silently off → loud warning at startup
# =============================================================================


def test_guard_warns_when_audience_not_verified():
    import asyncio
    from unittest.mock import MagicMock

    guard = AuthGuard(config=AuthConfig(auth_url=AUTH_URL))  # no audience
    guard._logger = MagicMock()
    asyncio.run(guard.initialize())
    msgs = " ".join(str(c.args[0]) for c in guard._logger.warning.call_args_list if c.args)
    assert "audience" in msgs.lower(), "no startup warning although JWT audience is not verified"
    asyncio.run(guard.shutdown())


def test_guard_no_audience_warning_when_configured():
    import asyncio
    from unittest.mock import MagicMock

    guard = AuthGuard(config=_server_config())  # audience set
    guard._logger = MagicMock()
    asyncio.run(guard.initialize())
    msgs = " ".join(str(c.args[0]) for c in guard._logger.warning.call_args_list if c.args)
    assert "audience" not in msgs.lower()
    asyncio.run(guard.shutdown())


# =============================================================================
# SR-6 (MEDIUM): require_auth_and_permission ignored permission_check_mode="server"
# =============================================================================


def test_require_auth_and_permission_honours_server_mode(monkeypatch):
    from ab0t_auth import permissions as perms_mod
    from ab0t_auth.core import PermissionCheckResponse
    from ab0t_auth.dependencies import require_auth_and_permission

    guard = AuthGuard(config=_server_config())
    stale = AuthenticatedUser(
        user_id=OWNER, org_id="org-r", permissions=("billing.write",), auth_method=AuthMethod.JWT
    )

    async def auth_or_raise(authorization, api_key):
        return stale

    async def revoked(client, config, token, request, *, api_key=None):
        return PermissionCheckResponse(
            allowed=False, permission=request.permission, user_id=request.user_id
        )

    monkeypatch.setattr(guard, "authenticate_or_raise", auth_or_raise)
    monkeypatch.setattr(perms_mod, "check_permission_remote", revoked)

    client = TestClient(_app(guard, require_auth_and_permission(guard, "billing.write")))
    r = client.post("/accounts", headers={"Authorization": "Bearer stale.claims.jwt"})
    assert (
        r.status_code == 403
    ), "server mode configured, auth says revoked, yet the token claim granted access"


# =============================================================================
# SR-7 (LOW): internal auth URL / raw exception text leaked in the 401 body
# =============================================================================


def test_auth_service_error_does_not_leak_internal_url():
    from ab0t_auth.dependencies import require_auth

    guard = AuthGuard(config=_server_config())
    with respx.mock:
        respx.post(f"{AUTH_URL}/auth/validate-api-key").mock(
            return_value=httpx.Response(500, json={})
        )
        guard._http_client = httpx.AsyncClient()
        guard._initialized = True
        client = TestClient(_app(guard, require_auth(guard)))
        r = client.post("/accounts", headers={"X-API-Key": "ab0t_sk_anything"})
    assert r.status_code == 401
    body = r.text
    assert (
        "auth.test.ab0t.com" not in body and "for url" not in body
    ), f"internal detail leaked: {body}"


# =============================================================================
# SR-8 (LOW): decision fields must be JSON true, not merely truthy
# =============================================================================


@pytest.mark.parametrize("value", ["false", "no", 1, ["x"]])
def test_permission_allowed_must_be_strict_true(value):
    import asyncio

    from ab0t_auth.client import check_permission
    from ab0t_auth.core import PermissionCheckRequest

    async def go():
        with respx.mock:
            respx.post(f"{AUTH_URL}/permissions/check").mock(
                return_value=httpx.Response(200, json={"allowed": value})
            )
            async with httpx.AsyncClient() as c:
                return await check_permission(
                    c,
                    _server_config(),
                    "Bearer t",
                    PermissionCheckRequest(user_id=OWNER, permission="p"),
                )

    assert asyncio.run(go()).allowed is False, f"allowed={value!r} was treated as a grant"
